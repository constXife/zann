use super::{format::*, reader::Prepared, BackupError, ImportOptions, ImportReport};
use chrono::Utc;
use std::io::{BufRead, Read};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zann_core::{
    CachePolicy, Device, Item, SyncStatus, Vault, VaultEncryptionType, VaultKind, VaultMember,
    VaultMemberRole,
};
use zann_crypto::{vault_crypto as crypto, SecretKey};
use zann_db::{
    repo::{DeviceRepo, ItemRepo, ServerBackupRepo, VaultMemberRepo, VaultRepo},
    PgPool,
};
use zeroize::Zeroizing;

pub async fn import_file(
    db: &PgPool,
    smk: &SecretKey,
    options: ImportOptions,
) -> Result<ImportReport, BackupError> {
    if !options.confirmed {
        return Err(BackupError::Invalid("plaintext_confirmation_required"));
    }
    let prepared = tokio::task::spawn_blocking(move || {
        super::reader::prepare(super::files::open_private(&options.input)?)
    })
    .await??;
    restore(db, smk, &options.owner_email, prepared).await
}

async fn restore(
    db: &PgPool,
    smk: &SecretKey,
    owner_email: &str,
    prepared: Prepared,
) -> Result<ImportReport, BackupError> {
    let mut tx = db.begin().await?;
    // Recovery is an offline maintenance operation. Serialize with every item
    // writer so an empty-target proof remains valid through publication.
    sqlx_core::query::query("LOCK TABLE vaults, items IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    let owner = ServerBackupRepo::owner(&mut tx, owner_email)
        .await?
        .ok_or(BackupError::Invalid("active_import_owner_required"))?;
    let mut targets = Vec::with_capacity(prepared.vaults.len());
    // Check all destination scopes before creating any vault or device.
    for header in &prepared.vaults {
        let target = ServerBackupRepo::target_vault(&mut tx, &header.slug).await?;
        if let Some(vault) = &target {
            if vault.kind != VaultKind::Shared
                || vault.encryption_type != VaultEncryptionType::Server
                || vault.deleted_at.is_some()
            {
                return Err(BackupError::Invalid("vault_not_shared_server_encrypted"));
            }
            if ServerBackupRepo::item_count(&mut tx, vault.id, true).await? != 0 {
                return Err(BackupError::Invalid("import_target_not_empty"));
            }
        }
        targets.push(target);
    }
    let now = Utc::now();
    let device = Device {
        id: Uuid::now_v7(),
        user_id: owner,
        name: "Server backup import".into(),
        fingerprint: Uuid::now_v7().to_string(),
        os: None,
        os_version: None,
        app_version: None,
        last_seen_at: None,
        last_ip: None,
        revoked_at: None,
        created_at: now,
    };
    DeviceRepo::create_in(&mut tx, &device).await?;
    let mut keys = Vec::with_capacity(targets.len());
    for (header, target) in prepared.vaults.iter().zip(targets) {
        let (vault, key) = if let Some(vault) = target {
            let key = crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc)?;
            (vault, key)
        } else {
            let id = uuid(&header.id)?;
            let key = SecretKey::generate();
            let wrapped = crypto::encrypt_vault_key(smk, id, &key)?;
            let proof = crypto::decrypt_vault_key(smk, id, &wrapped)?;
            if !bool::from(proof.as_bytes().ct_eq(key.as_bytes())) {
                return Err(BackupError::Invalid("backup_verification_failed"));
            }
            let vault = Vault {
                id,
                slug: header.slug.clone(),
                name: header.name.clone(),
                kind: VaultKind::Shared,
                encryption_type: VaultEncryptionType::Server,
                vault_key_enc: wrapped,
                cache_policy: CachePolicy::Full,
                tags: Some(Vec::new()),
                deleted_at: None,
                deleted_by_user_id: None,
                deleted_by_device_id: None,
                row_version: 1,
                created_at: now,
            };
            VaultRepo::create_in(&mut tx, &vault).await?;
            VaultMemberRepo::create_in(
                &mut tx,
                &VaultMember {
                    vault_id: id,
                    user_id: owner,
                    role: VaultMemberRole::Admin,
                    created_at: now,
                },
            )
            .await?;
            (vault, key)
        };
        keys.push((vault.id, key));
    }
    let report = ImportReport {
        vaults: prepared.vaults.len(),
        items: prepared.items,
    };
    let mut input = std::io::BufReader::new(prepared.spool);
    loop {
        let mut bytes = Zeroizing::new(Vec::new());
        let count = input
            .by_ref()
            .take((MAX_RECORD_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes)?;
        if count == 0 {
            break;
        }
        if count > MAX_RECORD_BYTES {
            return Err(BackupError::Invalid("backup_record_limit_exceeded"));
        }
        let (index, item): (usize, SharedExportItem) = serde_json::from_slice(&bytes)?;
        let (vault_id, key) = keys
            .get(index)
            .ok_or(BackupError::Invalid("invalid_staged_vault"))?;
        let id = uuid(&item.id)?;
        let plaintext = Zeroizing::new(item.payload.to_bytes()?);
        let encrypted = crypto::encrypt_payload_bytes(key, *vault_id, id, &plaintext)?;
        let proof = Zeroizing::new(crypto::decrypt_payload_bytes(
            key, *vault_id, id, &encrypted,
        )?);
        if !bool::from(proof.as_slice().ct_eq(&plaintext)) {
            return Err(BackupError::Invalid("backup_verification_failed"));
        }
        let deleted = item.deleted_at.as_deref().map(timestamp).transpose()?;
        let updated = timestamp(&item.updated_at)?;
        ItemRepo::new(db)
            .create_in(
                &mut tx,
                &Item {
                    id,
                    vault_id: *vault_id,
                    path: item.path,
                    name: item.name,
                    type_id: item.type_id,
                    tags: item.tags,
                    favorite: item.favorite,
                    checksum: crypto::payload_checksum(&encrypted),
                    payload_enc: encrypted,
                    version: item.version,
                    row_version: 1,
                    device_id: device.id,
                    sync_status: if deleted.is_some() {
                        SyncStatus::Tombstone
                    } else {
                        SyncStatus::Active
                    },
                    deleted_at: deleted,
                    deleted_by_user_id: deleted.map(|_| owner),
                    deleted_by_device_id: deleted.map(|_| device.id),
                    created_at: updated,
                    updated_at: updated,
                },
            )
            .await?;
    }
    tx.commit().await?;
    Ok(report)
}
