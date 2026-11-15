use super::*;

/// Canonical paged serializer. The caller owns the authorized/private writer.
pub(crate) async fn export_to_writer<W: Write>(
    ctx: &BackupCtx,
    writer: &mut W,
) -> Result<ExportReport, BackupError> {
    let storage_repo = LocalStorageRepo::new(&ctx.pool);
    let vault_repo = LocalVaultRepo::new(&ctx.pool);
    let item_repo = LocalItemRepo::new(&ctx.pool);
    if item_repo
        .has_unknown_metadata()
        .await
        .map_err(BackupError::source)?
    {
        return Err(BackupError::new(
            "backup_metadata_refresh_required",
            "legacy replica metadata must be refreshed from the server before export",
        ));
    }

    let storages = storage_repo.list().await.map_err(BackupError::source)?;

    let mut backup_storages = Vec::with_capacity(storages.len());
    let mut backup_vaults = Vec::new();
    let mut vault_queue = VecDeque::new();

    for storage in storages {
        let storage_id = storage.id;
        backup_storages.push(PlainBackupStorage {
            id: storage_id.to_string(),
            kind: storage.kind.as_i32(),
            name: storage.name.clone(),
            server_url: storage.server_url.clone(),
            server_name: storage.server_name.clone(),
            server_fingerprint: storage.server_fingerprint.clone(),
            account_subject: storage.account_subject.clone(),
            personal_vaults_enabled: storage.personal_vaults_enabled,
            auth_method: storage.auth_method.map(|method| method.as_i32()),
        });

        let vaults = vault_repo
            .list_by_storage(storage_id)
            .await
            .map_err(BackupError::source)?;
        if !vaults.is_empty() {
            ctx.key(storage_id)?;
        }
        for vault in vaults {
            backup_vaults.push(PlainBackupVault {
                id: vault.id.to_string(),
                storage_id: storage_id.to_string(),
                name: vault.name.clone(),
                kind: vault.kind.as_i32(),
                is_default: vault.is_default,
            });
            vault_queue.push_back((
                storage_id,
                vault.id,
                vault.kind,
                if vault.key_wrap_type == zann_db::local::KeyWrapType::RemoteServer {
                    zann_core::VaultEncryptionType::Server
                } else {
                    zann_core::VaultEncryptionType::Client
                },
            ));
        }
    }

    let exported_at = Utc::now().to_rfc3339();
    let mut streamer = ExportItemStreamer::new(ctx, item_repo, vault_queue);
    let items_count = write_backup_streaming(
        writer,
        BACKUP_VERSION,
        &exported_at,
        &backup_storages,
        &backup_vaults,
        &mut streamer,
    )
    .await
    .map_err(BackupError::from)?;

    Ok(ExportReport {
        storages_count: backup_storages.len(),
        vaults_count: backup_vaults.len(),
        items_count,
    })
}
