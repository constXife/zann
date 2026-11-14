use super::{format::*, BackupError, ExportOptions};
use chrono::Utc;
use std::{
    collections::HashSet,
    io::{Seek, SeekFrom, Write},
};
use zann_core::{Vault, VaultEncryptionType, VaultKind};
use zann_crypto::{vault_crypto as crypto, SecretKey};
use zann_db::{repo::ServerBackupRepo, PgPool};

pub async fn export(
    db: &PgPool,
    smk: &SecretKey,
    options: &ExportOptions,
) -> Result<(), BackupError> {
    if !options.confirmed {
        return Err(BackupError::Invalid("plaintext_confirmation_required"));
    }
    if options.all_shared != options.vaults.is_empty() {
        return Err(BackupError::Invalid("export_scope_required"));
    }
    let mut output = super::files::output(options.output.as_deref())?;
    let mut tx = db.begin().await?;
    sqlx_core::query::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    write!(output,"{{\"version\":{EXPORT_VERSION},\"exported_at\":\"{}\",\"scope\":\"shared\",\"plaintext\":true,\"vaults\":[",Utc::now().to_rfc3339())?;
    let (mut vault_count, mut item_count) = (0, 0);
    if options.all_shared {
        let mut cursor = None;
        loop {
            let page = ServerBackupRepo::vault_page(&mut tx, cursor).await?;
            if page.is_empty() {
                break;
            }
            for vault in page {
                cursor = Some(vault.id);
                write_vault(
                    &mut output,
                    &mut tx,
                    smk,
                    &vault,
                    options.include_deleted,
                    &mut vault_count,
                    &mut item_count,
                )
                .await?;
            }
        }
    } else {
        let mut seen = HashSet::new();
        for selector in &options.vaults {
            let vault = ServerBackupRepo::vault(&mut tx, selector)
                .await?
                .ok_or(BackupError::Invalid("vault_not_found"))?;
            if seen.insert(vault.id) {
                write_vault(
                    &mut output,
                    &mut tx,
                    smk,
                    &vault,
                    options.include_deleted,
                    &mut vault_count,
                    &mut item_count,
                )
                .await?;
            }
        }
    }
    if vault_count == 0 {
        return Err(BackupError::Invalid("no_shared_vaults_found"));
    }
    output.write_all(b"]}\n")?;
    tx.commit().await?;
    output.flush()?;
    output.as_file().sync_all()?;
    if let Some(path) = &options.output {
        output
            .persist(path)
            .map_err(|error| BackupError::Io(error.error))?;
        std::fs::File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new(".")),
        )?
        .sync_all()?;
    } else {
        output.seek(SeekFrom::Start(0))?;
        std::io::copy(&mut output, &mut std::io::stdout().lock())?;
    }
    Ok(())
}

async fn write_vault<W: Write>(
    out: &mut W,
    tx: &mut sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>,
    smk: &SecretKey,
    vault: &Vault,
    deleted: bool,
    vault_count: &mut usize,
    total_items: &mut usize,
) -> Result<(), BackupError> {
    if vault.kind != VaultKind::Shared
        || vault.encryption_type != VaultEncryptionType::Server
        || vault.deleted_at.is_some()
    {
        return Err(BackupError::Invalid("vault_not_shared_server_encrypted"));
    }
    if *vault_count >= MAX_VAULTS {
        return Err(BackupError::Invalid("backup_vault_limit_exceeded"));
    }
    let count = usize::try_from(ServerBackupRepo::item_count(tx, vault.id, deleted).await?)
        .map_err(|_| BackupError::Invalid("invalid_item_count"))?;
    if count > MAX_ITEMS - *total_items {
        return Err(BackupError::Invalid("backup_item_limit_exceeded"));
    }
    let header = SharedExportVault {
        id: vault.id.to_string(),
        slug: vault.slug.clone(),
        name: vault.name.clone(),
        item_count: count,
    };
    validate_vault(&header)?;
    let header = serde_json::to_vec(&header)?;
    if *vault_count > 0 {
        out.write_all(b",")?
    }
    out.write_all(&header[..header.len() - 1])?;
    out.write_all(b",\"items\":[")?;
    let key = crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc)?;
    let mut cursor = None;
    let mut written = 0;
    loop {
        let page = ServerBackupRepo::item_page(tx, vault.id, deleted, cursor).await?;
        if page.is_empty() {
            break;
        }
        for item in page {
            cursor = Some(item.id);
            let payload = crypto::decrypt_payload(&key, vault.id, item.id, &item.payload_enc)?;
            let item = SharedExportItem {
                id: item.id.to_string(),
                path: item.path,
                name: item.name,
                type_id: item.type_id,
                tags: item.tags,
                favorite: item.favorite,
                payload,
                checksum: item.checksum,
                version: item.version,
                deleted_at: item.deleted_at.map(|v| v.to_rfc3339()),
                updated_at: item.updated_at.to_rfc3339(),
            };
            validate_item(&item)?;
            let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&item)?);
            if bytes.len() > MAX_RECORD_BYTES {
                return Err(BackupError::Invalid("backup_record_limit_exceeded"));
            }
            if written > 0 {
                out.write_all(b",")?
            }
            out.write_all(&bytes)?;
            written += 1;
        }
    }
    if written != count {
        return Err(BackupError::Invalid("export_snapshot_inconsistent"));
    }
    out.write_all(b"]}")?;
    *vault_count += 1;
    *total_items += written;
    Ok(())
}
