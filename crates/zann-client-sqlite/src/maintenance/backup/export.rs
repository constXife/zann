use super::*;

pub async fn plain_export(ctx: &BackupCtx, path: PathBuf) -> Result<ExportReport, BackupError> {
    let master_key = ctx.master_key.clone();
    let services = LocalServices::new(&ctx.pool, master_key.as_ref());
    let storage_repo = LocalStorageRepo::new(&ctx.pool);
    let vault_repo = LocalVaultRepo::new(&ctx.pool);
    let item_repo = LocalItemRepo::new(&ctx.pool);

    let storages = storage_repo.list().await.map_err(|err| err.to_string())?;

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
            .map_err(|err| err.to_string())?;
        for vault in vaults {
            backup_vaults.push(PlainBackupVault {
                id: vault.id.to_string(),
                storage_id: storage_id.to_string(),
                name: vault.name.clone(),
                kind: vault.kind.as_i32(),
                is_default: vault.is_default,
            });
            vault_queue.push_back((storage_id, vault.id));
        }
    }

    let output_path = path;
    ctx.log(&format!("export_start path={}", output_path.display()));
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let file = crate::maintenance::secure_file::create_private_file(&output_path)
        .map_err(|err| err.to_string())?;
    let mut writer = BufWriter::new(file);
    let exported_at = Utc::now().to_rfc3339();
    let mut streamer = ExportItemStreamer::new(services, item_repo, vault_queue);
    let items_count = match write_backup_streaming(
        &mut writer,
        BACKUP_VERSION,
        &exported_at,
        &backup_storages,
        &backup_vaults,
        &mut streamer,
    )
    .await
    {
        Ok(count) => count,
        Err(err) => {
            ctx.log(&format!(
                "export_failed path={} error={}",
                output_path.display(),
                err
            ));
            return Err(err.to_string().into());
        }
    };
    if let Err(err) = writer.flush() {
        ctx.log(&format!(
            "export_failed path={} error={}",
            output_path.display(),
            err
        ));
        return Err(err.to_string().into());
    }
    ctx.log(&format!(
        "export_ok path={} storages={} vaults={} items={}",
        output_path.display(),
        backup_storages.len(),
        backup_vaults.len(),
        items_count
    ));

    Ok(ExportReport {
        path: output_path.display().to_string(),
        storages_count: backup_storages.len(),
        vaults_count: backup_vaults.len(),
        items_count,
    })
}
