use chrono::Utc;
use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use sqlx_core::types::Json as SqlxJson;
use uuid::Uuid;
use zann_core::{
    CachePolicy, Change, ChangeOp, ChangeType, Item, ItemHistory, SyncStatus, User, UserStatus,
    Vault, VaultEncryptionType, VaultKind, VaultMember, VaultMemberRole,
};
use zann_crypto::crypto::SecretKey;
use zann_crypto::secrets::{EncryptedPayload, FieldKind, FieldValue};
use zann_crypto::vault_crypto as core_crypto;
use zann_db::repo::{ChangeRepo, ItemHistoryRepo, ItemRepo, UserRepo, VaultMemberRepo, VaultRepo};
use zann_db::PgPool;

use crate::cli::tokens::SYSTEM_OWNER_EMAIL;
use crate::domains::items::service::{basename_from_path, ITEM_HISTORY_LIMIT};
use crate::settings;

#[derive(Debug, Clone, Args)]
pub struct ProvisionArgs {
    #[command(subcommand)]
    pub command: ProvisionCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ProvisionCommand {
    #[command(about = "Ensure the bootstrap system owner exists")]
    EnsureSystemUser,
    #[command(about = "Ensure a shared server-encrypted vault exists")]
    EnsureVault(EnsureVaultArgs),
    #[command(about = "Create or update a field in a shared item")]
    SetField(SetFieldArgs),
}

#[derive(Debug, Clone, Args)]
pub struct EnsureVaultArgs {
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub slug: String,
}

#[derive(Debug, Clone, Args)]
pub struct SetFieldArgs {
    #[arg(long, help = "Vault name or ID")]
    pub vault: String,
    #[arg(long, help = "Shared item path")]
    pub path: String,
    #[arg(long, help = "Field key")]
    pub key: String,
    #[arg(long, help = "Field value")]
    pub value: String,
    #[arg(long, value_enum, default_value = "text", help = "Field kind")]
    pub kind: ProvisionFieldKind,
    #[arg(
        long,
        default_value = "secret",
        help = "Item type for newly created items"
    )]
    pub type_id: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ProvisionFieldKind {
    Text,
    Password,
    Url,
    Otp,
    Note,
}

#[derive(Debug, Serialize)]
struct EnsureSystemUserOutput {
    status: &'static str,
    user_id: String,
    email: String,
}

#[derive(Debug, Serialize)]
struct EnsureVaultOutput {
    status: &'static str,
    vault_id: String,
    slug: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct SetFieldOutput {
    status: &'static str,
    vault_id: String,
    item_id: String,
    path: String,
    key: String,
}

pub(crate) async fn run(
    settings: &settings::Settings,
    db: &PgPool,
    args: &ProvisionArgs,
) -> Result<(), String> {
    match &args.command {
        ProvisionCommand::EnsureSystemUser => ensure_system_user_command(settings, db).await,
        ProvisionCommand::EnsureVault(command) => ensure_vault_command(settings, db, command).await,
        ProvisionCommand::SetField(command) => set_field_command(settings, db, command).await,
    }
}

async fn ensure_system_user_command(
    settings: &settings::Settings,
    db: &PgPool,
) -> Result<(), String> {
    let (user, created) = ensure_system_user(settings, db).await?;
    let output = EnsureSystemUserOutput {
        status: if created { "created" } else { "existing" },
        user_id: user.id.to_string(),
        email: user.email,
    };
    print_json(&output)
}

async fn ensure_vault_command(
    settings: &settings::Settings,
    db: &PgPool,
    args: &EnsureVaultArgs,
) -> Result<(), String> {
    let (vault, created) =
        ensure_shared_vault(settings, db, args.name.trim(), args.slug.trim()).await?;
    let output = EnsureVaultOutput {
        status: if created { "created" } else { "existing" },
        vault_id: vault.id.to_string(),
        slug: vault.slug,
        name: vault.name,
    };
    print_json(&output)
}

async fn set_field_command(
    settings: &settings::Settings,
    db: &PgPool,
    args: &SetFieldArgs,
) -> Result<(), String> {
    let owner = ensure_system_user(settings, db).await?.0;
    let vault = resolve_vault(db, args.vault.trim()).await?;
    if vault.kind != VaultKind::Shared || vault.encryption_type != VaultEncryptionType::Server {
        return Err("vault_not_shared_server_encrypted".to_string());
    }

    let path = normalize_path(&args.path);
    if path.is_empty() {
        return Err("invalid_path".to_string());
    }

    let key = args.key.trim();
    if key.is_empty() {
        return Err("invalid_key".to_string());
    }

    let type_id = args.type_id.trim();
    if type_id.is_empty() {
        return Err("invalid_type_id".to_string());
    }

    let field = FieldValue {
        kind: args.kind.into(),
        value: args.value.clone(),
        meta: None,
    };

    let item_repo = ItemRepo::new(db);
    let history_repo = ItemHistoryRepo::new(db);
    let change_repo = ChangeRepo::new(db);
    let mut existing = item_repo
        .get_by_vault_path(vault.id, &path)
        .await
        .map_err(db_error("item_lookup_failed"))?;

    let mut current_status = "created";
    let item = if let Some(mut item) = existing.take() {
        if item.deleted_at.is_some() || item.sync_status != SyncStatus::Active {
            return Err("path_in_use".to_string());
        }

        let mut payload = decrypt_payload(settings, &vault, item.id, &item.payload_enc)?;
        let before =
            serde_json::to_vec(&payload).map_err(|err| format!("payload_encode_failed: {err}"))?;
        payload.type_id = item.type_id.clone();
        payload.fields.insert(key.to_string(), field);
        let after =
            serde_json::to_vec(&payload).map_err(|err| format!("payload_encode_failed: {err}"))?;
        if before == after {
            current_status = "unchanged";
            item
        } else {
            let history = ItemHistory {
                id: Uuid::now_v7(),
                item_id: item.id,
                payload_enc: item.payload_enc.clone(),
                checksum: item.checksum.clone(),
                version: item.version,
                change_type: ChangeType::Update,
                fields_changed: None,
                changed_by_user_id: owner.id,
                changed_by_email: owner.email.clone(),
                changed_by_name: owner.full_name.clone(),
                changed_by_device_id: None,
                changed_by_device_name: None,
                created_at: Utc::now(),
            };
            if let Err(err) = history_repo.create(&history).await {
                tracing::error!(event = "provision_item_history_create_failed", error = %err, item_id = %item.id);
            }

            let payload_enc = encrypt_payload(settings, &vault, item.id, &payload)?;
            item.payload_enc = payload_enc;
            item.checksum = core_crypto::payload_checksum(&item.payload_enc);
            item.version += 1;
            item.device_id = Uuid::nil();
            item.updated_at = Utc::now();
            let affected = item_repo
                .update(&item)
                .await
                .map_err(db_error("item_update_failed"))?;
            if affected == 0 {
                return Err("version_conflict".to_string());
            }

            if let Err(err) = history_repo
                .prune_by_item(item.id, ITEM_HISTORY_LIMIT)
                .await
            {
                tracing::error!(event = "provision_item_history_prune_failed", error = %err, item_id = %item.id);
            }

            let change = Change {
                seq: 0,
                vault_id: vault.id,
                item_id: item.id,
                op: ChangeOp::Update,
                version: item.version,
                device_id: Uuid::nil(),
                created_at: item.updated_at,
            };
            if let Err(err) = change_repo.create(&change).await {
                tracing::error!(event = "provision_item_change_create_failed", error = %err, item_id = %item.id);
            }

            current_status = "updated";
            item
        }
    } else {
        let mut payload = EncryptedPayload::new(type_id);
        payload.fields.insert(key.to_string(), field);
        let item_id = Uuid::now_v7();
        let payload_enc = encrypt_payload(settings, &vault, item_id, &payload)?;
        let now = Utc::now();
        let item = Item {
            id: item_id,
            vault_id: vault.id,
            path: path.clone(),
            name: basename_from_path(&path),
            type_id: type_id.to_string(),
            tags: None,
            favorite: false,
            payload_enc,
            checksum: String::new(),
            version: 1,
            row_version: 1,
            device_id: Uuid::nil(),
            sync_status: SyncStatus::Active,
            deleted_at: None,
            deleted_by_user_id: None,
            deleted_by_device_id: None,
            created_at: now,
            updated_at: now,
        };
        let mut item = item;
        item.checksum = core_crypto::payload_checksum(&item.payload_enc);
        item_repo
            .create(&item)
            .await
            .map_err(db_error("item_create_failed"))?;

        let history = ItemHistory {
            id: Uuid::now_v7(),
            item_id,
            payload_enc: item.payload_enc.clone(),
            checksum: item.checksum.clone(),
            version: item.version,
            change_type: ChangeType::Create,
            fields_changed: None,
            changed_by_user_id: owner.id,
            changed_by_email: owner.email.clone(),
            changed_by_name: owner.full_name.clone(),
            changed_by_device_id: None,
            changed_by_device_name: None,
            created_at: now,
        };
        if let Err(err) = history_repo.create(&history).await {
            tracing::error!(event = "provision_item_history_create_failed", error = %err, item_id = %item.id);
        }

        let change = Change {
            seq: 0,
            vault_id: vault.id,
            item_id,
            op: ChangeOp::Create,
            version: item.version,
            device_id: Uuid::nil(),
            created_at: now,
        };
        if let Err(err) = change_repo.create(&change).await {
            tracing::error!(event = "provision_item_change_create_failed", error = %err, item_id = %item.id);
        }

        item
    };

    let output = SetFieldOutput {
        status: current_status,
        vault_id: vault.id.to_string(),
        item_id: item.id.to_string(),
        path: item.path,
        key: key.to_string(),
    };
    print_json(&output)
}

async fn ensure_system_user(
    settings: &settings::Settings,
    db: &PgPool,
) -> Result<(User, bool), String> {
    let repo = UserRepo::new(db);
    if let Some(user) = repo
        .get_by_email(SYSTEM_OWNER_EMAIL)
        .await
        .map_err(db_error("system_user_lookup_failed"))?
    {
        return Ok((user, false));
    }

    let now = Utc::now();
    let user = User {
        id: Uuid::now_v7(),
        email: SYSTEM_OWNER_EMAIL.to_string(),
        full_name: Some("System".to_string()),
        password_hash: None,
        kdf_salt: crate::domains::auth::core::passwords::random_kdf_salt(),
        kdf_algorithm: settings.config.auth.kdf.algorithm.to_string(),
        kdf_iterations: i64::from(settings.config.auth.kdf.iterations),
        kdf_memory_kb: i64::from(settings.config.auth.kdf.memory_kb),
        kdf_parallelism: i64::from(settings.config.auth.kdf.parallelism),
        recovery_key_hash: None,
        status: UserStatus::System,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        row_version: 1,
        created_at: now,
        updated_at: now,
        last_login_at: None,
    };
    repo.create(&user)
        .await
        .map_err(db_error("system_user_create_failed"))?;
    Ok((user, true))
}

async fn ensure_shared_vault(
    settings: &settings::Settings,
    db: &PgPool,
    name: &str,
    slug: &str,
) -> Result<(Vault, bool), String> {
    if name.is_empty() {
        return Err("invalid_vault_name".to_string());
    }
    if slug.is_empty() {
        return Err("invalid_vault_slug".to_string());
    }

    let (owner, _) = ensure_system_user(settings, db).await?;
    let repo = VaultRepo::new(db);
    if let Some(vault) = repo
        .get_by_slug(slug)
        .await
        .map_err(db_error("vault_lookup_failed"))?
    {
        ensure_vault_member(db, vault.id, owner.id).await?;
        return Ok((vault, false));
    }

    let smk = settings
        .server_master_key
        .as_ref()
        .ok_or_else(|| "server_master_key_missing".to_string())?;
    let vault_id = Uuid::now_v7();
    let vault_key = SecretKey::generate();
    let vault_key_enc = core_crypto::encrypt_vault_key(smk, vault_id, &vault_key)
        .map_err(|err| format!("vault_key_encrypt_failed: {err}"))?;
    let vault = Vault {
        id: vault_id,
        slug: slug.to_string(),
        name: name.to_string(),
        kind: VaultKind::Shared,
        encryption_type: VaultEncryptionType::Server,
        vault_key_enc,
        cache_policy: CachePolicy::Full,
        tags: Some(SqlxJson(Vec::<String>::new())),
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        row_version: 1,
        created_at: Utc::now(),
    };
    repo.create(&vault)
        .await
        .map_err(db_error("vault_create_failed"))?;
    ensure_vault_member(db, vault.id, owner.id).await?;
    Ok((vault, true))
}

async fn ensure_vault_member(db: &PgPool, vault_id: Uuid, user_id: Uuid) -> Result<(), String> {
    let repo = VaultMemberRepo::new(db);
    if repo
        .get(vault_id, user_id)
        .await
        .map_err(db_error("vault_member_lookup_failed"))?
        .is_some()
    {
        return Ok(());
    }
    let member = VaultMember {
        vault_id,
        user_id,
        role: VaultMemberRole::Admin,
        created_at: Utc::now(),
    };
    repo.create(&member)
        .await
        .map_err(db_error("vault_member_create_failed"))
}

async fn resolve_vault(db: &PgPool, selector: &str) -> Result<Vault, String> {
    let repo = VaultRepo::new(db);
    if let Ok(vault_id) = selector.parse::<Uuid>() {
        return repo
            .get_by_id(vault_id)
            .await
            .map_err(db_error("vault_lookup_failed"))?
            .ok_or_else(|| "vault_not_found".to_string());
    }
    repo.get_by_slug(selector)
        .await
        .map_err(db_error("vault_lookup_failed"))?
        .ok_or_else(|| "vault_not_found".to_string())
}

fn normalize_path(value: &str) -> String {
    value.trim().trim_matches('/').to_string()
}

fn decrypt_payload(
    settings: &settings::Settings,
    vault: &Vault,
    item_id: Uuid,
    payload_enc: &[u8],
) -> Result<EncryptedPayload, String> {
    let smk = settings
        .server_master_key
        .as_ref()
        .ok_or_else(|| "server_master_key_missing".to_string())?;
    let vault_key = core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc)
        .map_err(|err| format!("vault_key_decrypt_failed: {err}"))?;
    let payload_bytes =
        core_crypto::decrypt_payload_bytes(&vault_key, vault.id, item_id, payload_enc)
            .map_err(|err| format!("payload_decrypt_failed: {err}"))?;
    EncryptedPayload::from_bytes(&payload_bytes)
        .map_err(|err| format!("payload_decode_failed: {err}"))
}

fn encrypt_payload(
    settings: &settings::Settings,
    vault: &Vault,
    item_id: Uuid,
    payload: &EncryptedPayload,
) -> Result<Vec<u8>, String> {
    let smk = settings
        .server_master_key
        .as_ref()
        .ok_or_else(|| "server_master_key_missing".to_string())?;
    let vault_key = core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc)
        .map_err(|err| format!("vault_key_decrypt_failed: {err}"))?;
    let payload_bytes = payload
        .to_bytes()
        .map_err(|err| format!("payload_encode_failed: {err}"))?;
    core_crypto::encrypt_payload_bytes(&vault_key, vault.id, item_id, &payload_bytes)
        .map_err(|err| format!("payload_encrypt_failed: {err}"))
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let json = serde_json::to_string_pretty(value).map_err(|err| err.to_string())?;
    println!("{json}");
    Ok(())
}

fn db_error(label: &'static str) -> impl Fn(sqlx_core::Error) -> String {
    move |err| {
        tracing::error!(event = label, error = %err);
        label.to_string()
    }
}

impl From<ProvisionFieldKind> for FieldKind {
    fn from(value: ProvisionFieldKind) -> Self {
        match value {
            ProvisionFieldKind::Text => Self::Text,
            ProvisionFieldKind::Password => Self::Password,
            ProvisionFieldKind::Url => Self::Url,
            ProvisionFieldKind::Otp => Self::Otp,
            ProvisionFieldKind::Note => Self::Note,
        }
    }
}
