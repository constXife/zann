use chrono::Utc;
use clap::{Args, Subcommand, ValueEnum};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Serialize;
use sqlx_core::types::Json as SqlxJson;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zann_core::{
    CachePolicy, Change, ChangeOp, ChangeType, Device, Item, ItemHistory, ServiceAccount,
    SyncStatus, User, UserStatus, Vault, VaultEncryptionType, VaultKind, VaultMember,
    VaultMemberRole,
};
use zann_crypto::crypto::SecretKey;
use zann_crypto::secrets::{EncryptedPayload, FieldKind, FieldValue};
use zann_crypto::vault_crypto as core_crypto;
use zann_db::repo::{
    ChangeRepo, DeviceRepo, ItemHistoryRepo, ItemRepo, ServiceAccountRepo, UserRepo,
    VaultMemberRepo, VaultRepo,
};
use zann_db::PgPool;

use crate::cli::tokens::{SERVICE_ACCOUNT_PREFIX, SERVICE_ACCOUNT_PREFIX_LEN, SYSTEM_OWNER_EMAIL};
use crate::domains::auth::core::passwords;
use crate::domains::auth::helpers::build_device;
use crate::domains::items::service::{basename_from_path, ITEM_HISTORY_LIMIT};
use crate::settings;

const PROVISION_DEVICE_NAME: &str = "provision";
const PROVISION_DEVICE_FINGERPRINT: &str = "zann:provision:system";

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
    #[command(about = "Ensure a service account token exists for a scoped shared vault target")]
    EnsureToken(EnsureTokenArgs),
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

#[derive(Debug, Clone, Args)]
pub struct EnsureTokenArgs {
    #[arg(value_name = "name")]
    pub name: String,
    #[arg(
        value_name = "vault:prefixes",
        help = "Vault selector and prefixes, e.g. infra:/ or infra:rlyeh/yogg/grafana"
    )]
    pub target: String,
    #[arg(
        value_name = "ops",
        default_value = "read",
        help = "Comma-separated ops (read, write, read_history, read_previous)"
    )]
    pub ops: String,
    #[arg(long)]
    pub ttl: Option<String>,
    #[arg(long)]
    pub owner_email: Option<String>,
    #[arg(long)]
    pub owner_id: Option<String>,
    #[arg(long)]
    pub issued_by_email: Option<String>,
    #[arg(
        long,
        help = "Rotate the token plaintext and update the stored token hash"
    )]
    pub rotate: bool,
    #[arg(
        long,
        value_name = "path",
        help = "Write newly created or rotated plaintext token to a file instead of stdout"
    )]
    pub write_token_file: Option<PathBuf>,
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

#[derive(Debug, Serialize)]
struct EnsureTokenOutput {
    status: &'static str,
    token_written: bool,
    token_file: Option<String>,
    service_account: ProvisionedServiceAccountOutput,
}

#[derive(Debug, Serialize)]
struct ProvisionedServiceAccountOutput {
    id: String,
    owner_user_id: String,
    name: String,
    token_prefix: String,
    scopes: Vec<String>,
    issued_by: String,
    vault_id: String,
    vault_slug: String,
    prefix: Option<String>,
    prefixes: Option<Vec<String>>,
    ops: Vec<String>,
    expires_at: Option<String>,
    created_at: String,
    revoked_at: Option<String>,
}

#[derive(Debug, Clone)]
struct ProvisionTokenSpec {
    owner_id: Uuid,
    issued_by: String,
    vault: Vault,
    scopes: Vec<String>,
    description: String,
    expires_at: Option<chrono::DateTime<Utc>>,
    prefixes_display: Vec<String>,
    ops_display: Vec<String>,
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
        ProvisionCommand::EnsureToken(command) => ensure_token_command(settings, db, command).await,
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
    ensure_shared_server_vault(&vault)?;
    let provision_device = ensure_provision_device(db, &owner).await?;

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
                version: update_history_version(item.version),
                change_type: ChangeType::Update,
                fields_changed: None,
                changed_by_user_id: owner.id,
                changed_by_email: owner.email.clone(),
                changed_by_name: owner.full_name.clone(),
                changed_by_device_id: Some(provision_device.id),
                changed_by_device_name: Some(provision_device.name.clone()),
                created_at: Utc::now(),
            };
            if let Err(err) = history_repo.create(&history).await {
                tracing::error!(event = "provision_item_history_create_failed", error = %err, item_id = %item.id);
            }

            let payload_enc = encrypt_payload(settings, &vault, item.id, &payload)?;
            item.payload_enc = payload_enc;
            item.checksum = core_crypto::payload_checksum(&item.payload_enc);
            item.version += 1;
            item.device_id = provision_device.id;
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
                device_id: provision_device.id,
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
            device_id: provision_device.id,
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
            changed_by_device_id: Some(provision_device.id),
            changed_by_device_name: Some(provision_device.name.clone()),
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
            device_id: provision_device.id,
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

async fn ensure_token_command(
    settings: &settings::Settings,
    db: &PgPool,
    args: &EnsureTokenArgs,
) -> Result<(), String> {
    let name = args.name.trim();
    if name.is_empty() {
        return Err("invalid_name".to_string());
    }

    let spec = build_token_spec(settings, db, args).await?;
    let repo = ServiceAccountRepo::new(db);
    let token_file = args.write_token_file.as_deref();

    let (account, status, staged_secret) = if let Some(mut account) = repo
        .get_active_by_owner_and_name(spec.owner_id, name)
        .await
        .map_err(db_error("service_account_lookup_failed"))?
    {
        let mut status = "existing";
        let mut staged_secret = None;
        let description = Some(spec.description.clone());
        let metadata_changed = account.description != description
            || account.scopes.0 != spec.scopes
            || account.expires_at != spec.expires_at;

        if metadata_changed {
            account.description = description;
            account.scopes = sqlx_core::types::Json(spec.scopes.clone());
            account.expires_at = spec.expires_at;
            repo.update(&account)
                .await
                .map_err(db_error("service_account_update_failed"))?;
            status = "updated";
        }

        if args.rotate {
            if token_file.is_none() {
                return Err("token_sink_required".to_string());
            }
            let provisioned = generate_service_account_token(settings)?;
            staged_secret = Some(stage_secret_file(
                token_file.expect("token file path"),
                &provisioned.token,
            )?);
            account.token_hash = provisioned.token_hash;
            account.token_prefix = provisioned.token_prefix;
            account.description = Some(spec.description.clone());
            account.scopes = sqlx_core::types::Json(spec.scopes.clone());
            account.expires_at = spec.expires_at;
            account.revoked_at = None;
            if let Err(err) = repo.update(&account).await {
                if let Some(staged_secret) = staged_secret.take() {
                    let _ = staged_secret.discard();
                }
                return Err(db_error("service_account_rotate_failed")(err));
            }
            status = "rotated";
        }

        (account, status, staged_secret)
    } else {
        if token_file.is_none() {
            return Err("token_sink_required".to_string());
        }
        let provisioned = generate_service_account_token(settings)?;
        let staged_secret =
            stage_secret_file(token_file.expect("token file path"), &provisioned.token)?;
        let now = Utc::now();
        let account = ServiceAccount {
            id: Uuid::now_v7(),
            owner_user_id: spec.owner_id,
            name: name.to_string(),
            description: Some(spec.description.clone()),
            token_hash: provisioned.token_hash,
            token_prefix: provisioned.token_prefix,
            scopes: sqlx_core::types::Json(spec.scopes.clone()),
            allowed_ips: None,
            expires_at: spec.expires_at,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            use_count: 0,
            created_at: now,
            revoked_at: None,
        };
        if let Err(err) = repo.create(&account).await {
            let _ = staged_secret.discard();
            return Err(db_error("service_account_create_failed")(err));
        }
        (account, "created", Some(staged_secret))
    };

    let token_written = if let Some(staged_secret) = staged_secret {
        staged_secret.finalize()?;
        true
    } else {
        false
    };

    let output = EnsureTokenOutput {
        status,
        token_written,
        token_file: token_written
            .then(|| token_file.expect("token file path").display().to_string()),
        service_account: ProvisionedServiceAccountOutput {
            id: account.id.to_string(),
            owner_user_id: account.owner_user_id.to_string(),
            name: account.name,
            token_prefix: account.token_prefix,
            scopes: account.scopes.0,
            issued_by: spec.issued_by,
            vault_id: spec.vault.id.to_string(),
            vault_slug: spec.vault.slug,
            prefix: spec.prefixes_display.first().cloned(),
            prefixes: Some(spec.prefixes_display),
            ops: spec.ops_display,
            expires_at: account.expires_at.map(|dt| dt.to_rfc3339()),
            created_at: account.created_at.to_rfc3339(),
            revoked_at: account.revoked_at.map(|dt| dt.to_rfc3339()),
        },
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
        ensure_shared_server_vault(&vault)?;
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

async fn build_token_spec(
    settings: &settings::Settings,
    db: &PgPool,
    args: &EnsureTokenArgs,
) -> Result<ProvisionTokenSpec, String> {
    let target = args.target.trim();
    if target.is_empty() {
        return Err("invalid_target".to_string());
    }
    let (vault_selector, prefixes_raw) = target
        .split_once(':')
        .ok_or_else(|| "invalid_target".to_string())?;
    let vault_selector = vault_selector.trim();
    let prefixes_raw = prefixes_raw.trim();
    if vault_selector.is_empty() || prefixes_raw.is_empty() {
        return Err("invalid_target".to_string());
    }

    let (system_user, _) = ensure_system_user(settings, db).await?;
    let owner_id = resolve_owner_id(
        db,
        &system_user,
        args.owner_email.as_deref(),
        args.owner_id.as_deref(),
    )
    .await?;
    let issued_by = args
        .issued_by_email
        .as_deref()
        .unwrap_or(SYSTEM_OWNER_EMAIL)
        .trim()
        .to_string();
    if issued_by.is_empty() {
        return Err("invalid_issued_by_email".to_string());
    }

    let ops = parse_ops(&args.ops)?;
    let expires_at = args
        .ttl
        .as_deref()
        .map(parse_ttl)
        .transpose()?
        .map(|ttl| Utc::now() + ttl);
    let vault = resolve_vault(db, vault_selector).await?;
    ensure_shared_server_vault(&vault)?;

    let mut full_vault = false;
    let mut normalized_prefixes = Vec::new();
    for prefix in prefixes_raw.split(',') {
        let prefix = prefix.trim();
        if prefix.is_empty() {
            return Err("invalid_prefix".to_string());
        }
        if prefix == "/" {
            full_vault = true;
            continue;
        }
        normalized_prefixes.push(normalize_prefix(prefix)?);
    }
    if full_vault && !normalized_prefixes.is_empty() {
        return Err("prefix_root_conflict".to_string());
    }
    if !full_vault && normalized_prefixes.is_empty() {
        return Err("missing_prefix".to_string());
    }

    let scopes = if full_vault {
        ops.iter()
            .map(|op| format!("{}:{op}", vault.id))
            .collect::<Vec<_>>()
    } else {
        normalized_prefixes
            .iter()
            .flat_map(|prefix| {
                ops.iter()
                    .map(move |op| format!("{}/prefix:{}:{op}", vault.id, prefix.scope))
            })
            .collect::<Vec<_>>()
    };
    let prefixes_display = if full_vault {
        vec!["/".to_string()]
    } else {
        normalized_prefixes
            .iter()
            .map(|prefix| prefix.canonical.clone())
            .collect::<Vec<_>>()
    };
    let ops_display = ops
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    let description = serde_json::to_string(&serde_json::json!({
        "issued_by": issued_by,
        "vault_id": vault.id.to_string(),
        "vault_slug": vault.slug.clone(),
        "prefix": prefixes_display.first().cloned(),
        "prefixes": prefixes_display.clone(),
        "ops": ops_display.clone(),
    }))
    .map_err(|err| format!("description_encode_failed: {err}"))?;

    Ok(ProvisionTokenSpec {
        owner_id,
        issued_by,
        vault,
        scopes,
        description,
        expires_at,
        prefixes_display: if full_vault {
            vec!["/".to_string()]
        } else {
            normalized_prefixes
                .iter()
                .map(|prefix| prefix.canonical.clone())
                .collect::<Vec<_>>()
        },
        ops_display: ops.iter().map(|value| (*value).to_string()).collect(),
    })
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

async fn resolve_owner_id(
    db: &PgPool,
    system_user: &User,
    owner_email: Option<&str>,
    owner_id: Option<&str>,
) -> Result<Uuid, String> {
    if let Some(owner_id) = owner_id {
        return owner_id
            .parse::<Uuid>()
            .map_err(|_| "invalid_owner_id".to_string());
    }
    let owner_email = owner_email.unwrap_or(SYSTEM_OWNER_EMAIL).trim();
    if owner_email.is_empty() {
        return Err("invalid_owner_email".to_string());
    }
    if owner_email.eq_ignore_ascii_case(SYSTEM_OWNER_EMAIL) {
        return Ok(system_user.id);
    }
    let repo = UserRepo::new(db);
    let owner = repo
        .get_by_email(owner_email)
        .await
        .map_err(db_error("owner_lookup_failed"))?;
    owner
        .map(|user| user.id)
        .ok_or_else(|| "owner_not_found".to_string())
}

fn normalize_path(value: &str) -> String {
    value.trim().trim_matches('/').to_string()
}

fn normalize_prefix(prefix: &str) -> Result<NormalizedPrefix, String> {
    let trimmed = prefix.trim();
    if trimmed.is_empty() {
        return Err("invalid_prefix".to_string());
    }
    let canonical = trimmed.trim_matches('/').to_string();
    if canonical.is_empty() {
        return Err("invalid_prefix".to_string());
    }
    Ok(NormalizedPrefix {
        canonical: format!("/{canonical}"),
        scope: canonical.replace('/', "::"),
    })
}

fn parse_ops(value: &str) -> Result<Vec<&'static str>, String> {
    let mut ops = Vec::new();
    for token in value.split(',') {
        let normalized = token.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        let op = match normalized.as_str() {
            "read" => "read",
            "write" => "write",
            "read_history" => "read_history",
            "read_previous" => "read_previous",
            "history_read" => "read_history",
            _ => return Err(format!("invalid_ops:{token}")),
        };
        if !ops.contains(&op) {
            ops.push(op);
        }
    }
    if ops.is_empty() {
        return Err("invalid_ops".to_string());
    }
    Ok(ops)
}

fn parse_ttl(value: &str) -> Result<chrono::Duration, String> {
    let trimmed = value.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err("invalid_ttl".to_string());
    }
    let (amount, unit) = trimmed.split_at(trimmed.len().saturating_sub(1));
    let amount = amount
        .parse::<i64>()
        .map_err(|_| "invalid_ttl".to_string())?;
    match unit {
        "s" => Ok(chrono::Duration::seconds(amount)),
        "m" => Ok(chrono::Duration::minutes(amount)),
        "h" => Ok(chrono::Duration::hours(amount)),
        "d" => Ok(chrono::Duration::days(amount)),
        _ => Err("invalid_ttl".to_string()),
    }
}

fn generate_service_account_token(
    settings: &settings::Settings,
) -> Result<ProvisionedToken, String> {
    let token_suffix: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let token = format!("{SERVICE_ACCOUNT_PREFIX}{token_suffix}");
    let token_prefix = token
        .chars()
        .take(SERVICE_ACCOUNT_PREFIX_LEN)
        .collect::<String>();
    let params = passwords::KdfParams {
        algorithm: settings.config.auth.kdf.algorithm.clone(),
        iterations: settings.config.auth.kdf.iterations,
        memory_kb: settings.config.auth.kdf.memory_kb,
        parallelism: settings.config.auth.kdf.parallelism,
    };
    let token_hash = passwords::hash_service_token(&token, &settings.token_pepper, &params)
        .map_err(|err| format!("token_hash_failed: {err}"))?;
    Ok(ProvisionedToken {
        token,
        token_hash,
        token_prefix,
    })
}

#[cfg(test)]
fn write_secret_file(path: &Path, value: &str) -> Result<(), String> {
    stage_secret_file(path, value)?.finalize()
}

fn stage_secret_file(path: &Path, value: &str) -> Result<StagedSecretFile, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "invalid_token_file_path".to_string())?;
    fs::create_dir_all(parent).map_err(|err| format!("token_file_create_dir_failed: {err}"))?;
    let tmp_path = parent.join(format!(".{}.tmp", Uuid::now_v7()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)
        .map_err(|err| format!("token_file_open_failed: {err}"))?;
    file.write_all(value.as_bytes())
        .map_err(|err| format!("token_file_write_failed: {err}"))?;
    file.write_all(b"\n")
        .map_err(|err| format!("token_file_write_failed: {err}"))?;
    file.sync_all()
        .map_err(|err| format!("token_file_sync_failed: {err}"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("token_file_chmod_failed: {err}"))?;
    Ok(StagedSecretFile {
        final_path: path.to_path_buf(),
        tmp_path,
    })
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

fn update_history_version(current_version: i64) -> i64 {
    current_version
}

fn ensure_shared_server_vault(vault: &Vault) -> Result<(), String> {
    if vault.kind != VaultKind::Shared || vault.encryption_type != VaultEncryptionType::Server {
        return Err("vault_not_shared_server_encrypted".to_string());
    }
    Ok(())
}

async fn ensure_provision_device(db: &PgPool, user: &User) -> Result<Device, String> {
    let repo = DeviceRepo::new(db);
    let existing = repo
        .list_by_user(user.id, 1024, 0, "desc")
        .await
        .map_err(db_error("provision_device_lookup_failed"))?
        .into_iter()
        .find(|device| {
            device.revoked_at.is_none() && device.fingerprint == PROVISION_DEVICE_FINGERPRINT
        });
    if let Some(device) = existing {
        return Ok(device);
    }

    let now = Utc::now();
    let device = build_device(
        user.id,
        Some(PROVISION_DEVICE_NAME.to_string()),
        Some("server".to_string()),
        Some(PROVISION_DEVICE_FINGERPRINT.to_string()),
        Some("server".to_string()),
        None,
        None,
        PROVISION_DEVICE_NAME,
        "server",
        now,
    );
    repo.create(&device)
        .await
        .map_err(db_error("provision_device_create_failed"))?;
    Ok(device)
}

#[derive(Debug, Clone)]
struct NormalizedPrefix {
    canonical: String,
    scope: String,
}

#[derive(Debug, Clone)]
struct ProvisionedToken {
    token: String,
    token_hash: String,
    token_prefix: String,
}

#[derive(Debug)]
struct StagedSecretFile {
    final_path: PathBuf,
    tmp_path: PathBuf,
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

impl StagedSecretFile {
    fn finalize(self) -> Result<(), String> {
        let tmp_path = self.tmp_path.display().to_string();
        let final_path = self.final_path.display().to_string();
        fs::rename(&self.tmp_path, &self.final_path).map_err(|err| {
            format!(
                "token_file_rename_failed: {err}; staged_path={tmp_path}; final_path={final_path}"
            )
        })?;
        fs::set_permissions(&self.final_path, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("token_file_chmod_failed: {err}; final_path={final_path}"))?;
        Ok(())
    }

    fn discard(self) -> Result<(), String> {
        match fs::remove_file(&self.tmp_path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!("token_file_cleanup_failed: {err}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_shared_server_vault, normalize_prefix, parse_ops, parse_ttl, stage_secret_file,
        update_history_version, write_secret_file,
    };
    use chrono::Utc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;
    use zann_core::{CachePolicy, Vault, VaultEncryptionType, VaultKind};

    #[test]
    fn parse_ops_deduplicates_aliases() {
        let ops = parse_ops("read, history_read, read_history, read_previous").expect("ops");
        assert_eq!(ops, vec!["read", "read_history", "read_previous"]);
    }

    #[test]
    fn parse_ops_accepts_write() {
        let ops = parse_ops("read,write").expect("ops");
        assert_eq!(ops, vec!["read", "write"]);
    }

    #[test]
    fn parse_ops_rejects_unknown_values() {
        let err = parse_ops("read,rotate").expect_err("invalid ops");
        assert_eq!(err, "invalid_ops:rotate");
    }

    #[test]
    fn parse_ttl_supports_days() {
        let ttl = parse_ttl("30d").expect("ttl");
        assert_eq!(ttl, chrono::Duration::days(30));
    }

    #[test]
    fn normalize_prefix_canonicalizes_slashes() {
        let prefix = normalize_prefix("/rlyeh/yogg/grafana/").expect("prefix");
        assert_eq!(prefix.canonical, "/rlyeh/yogg/grafana");
        assert_eq!(prefix.scope, "rlyeh::yogg::grafana");
    }

    #[test]
    fn write_secret_file_persists_token_with_newline() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("zann-provision-token-{unique}.txt"));
        write_secret_file(&path, "zann_sa_example").expect("write secret file");
        let content = std::fs::read_to_string(&path).expect("read secret file");
        assert_eq!(content, "zann_sa_example\n");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn finalize_error_reports_staged_secret_path() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("zann-provision-finalize-{unique}"));
        std::fs::create_dir_all(&base).expect("create base dir");
        let final_path = base.join("token");
        std::fs::create_dir_all(&final_path).expect("create conflicting final dir");

        let staged = stage_secret_file(&final_path, "zann_sa_example").expect("stage secret");
        let err = staged.finalize().expect_err("finalize should fail");
        assert!(err.contains("staged_path="));
        assert!(err.contains(&final_path.display().to_string()));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn ensure_shared_server_vault_rejects_non_shared_vaults() {
        let vault = Vault {
            id: Uuid::now_v7(),
            slug: "personal".to_string(),
            name: "Personal".to_string(),
            kind: VaultKind::Personal,
            encryption_type: VaultEncryptionType::Client,
            vault_key_enc: Vec::new(),
            cache_policy: CachePolicy::Full,
            tags: None,
            deleted_at: None,
            deleted_by_user_id: None,
            deleted_by_device_id: None,
            row_version: 1,
            created_at: Utc::now(),
        };

        let err = ensure_shared_server_vault(&vault).expect_err("non-shared vault should fail");
        assert_eq!(err, "vault_not_shared_server_encrypted");
    }

    #[test]
    fn update_history_uses_previous_version() {
        assert_eq!(update_history_version(1), 1);
        assert_eq!(update_history_version(7), 7);
    }
}
