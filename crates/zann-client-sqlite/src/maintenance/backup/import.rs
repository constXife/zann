use super::*;

pub async fn plain_import(
    ctx: &BackupCtx,
    _path: PathBuf,
    target_storage_id: Option<String>,
) -> Result<ImportOutcome, BackupError> {
    let target = target_storage_id.ok_or_else(|| {
        BackupError::new(
            "import_target_required",
            "select a server storage to import into",
        )
    })?;
    let id = Uuid::parse_str(&target)
        .map_err(|_| BackupError::new("import_target_invalid", "invalid storage id"))?;
    let storage = LocalStorageRepo::new(&ctx.pool)
        .get(id)
        .await
        .map_err(|err| BackupError::new("storage_lookup_failed", err.to_string()))?
        .ok_or_else(|| BackupError::new("storage_not_found", "storage not found"))?;
    Ok(ImportOutcome::NeedsRemote(storage))
}
