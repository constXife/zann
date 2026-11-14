//! Restore into an explicitly selected server replica using the canonical auth and sync owners.
use super::*;
use zann_client::app::{BackupVaultSpec, SyncOutcomeStatus};
use zann_db::local::PendingChangeRepo;
mod validate;

pub async fn plain_import(
    ctx: &BackupCtx,
    path: PathBuf,
    session: &zann_client::app::BackupImportSession,
) -> Result<ImportReport, BackupError> {
    let storage_id = Uuid::parse_str(session.storage_id()).map_err(BackupError::source)?;
    let validate::ValidatedBackup {
        specs,
        source_storages,
        source_vaults,
    } = validate::validate(&path)?;
    ensure_complete(session.sync().await.map_err(BackupError::source)?)?;
    session
        .prepare_vaults(&specs)
        .await
        .map_err(BackupError::source)?;
    // Only sync reconciles the new catalog into the local replica.
    ensure_complete(session.sync().await.map_err(BackupError::source)?)?;
    let vaults = LocalVaultRepo::new(&ctx.pool)
        .list_by_storage(storage_id)
        .await
        .map_err(BackupError::source)?;
    let mut mapping = std::collections::HashMap::new();
    for (source, (kind, name)) in source_vaults {
        let spec = BackupVaultSpec {
            source_id: source.1,
            name,
            kind,
        };
        let import_slug = spec.import_slug();
        let matches = vaults
            .iter()
            .filter(|v| {
                v.kind == kind
                    && (kind == VaultKind::Personal || v.id == source.1 || v.slug == import_slug)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(BackupError::new(
                "backup_ambiguous_vault",
                "backup vault has no unique target",
            ));
        }
        mapping.insert(source, matches[0].id);
    }
    let services = LocalServices::new(&ctx.pool, ctx.master_key.as_ref());
    let report = std::sync::Mutex::new(ImportReport::default());
    stream_backup_items_async(&path, |item, _| {
        let mapping = &mapping;
        let services = &services;
        let report = &report;
        let source_storages = &source_storages;
        async move {
            if session.is_cancelled() || std::time::Instant::now() >= session.deadline() {
                return Err(BackupError::new(
                    "backup_cancelled",
                    "backup import cancelled or expired",
                ));
            }
            if item.deleted_at.is_some() {
                report.lock().expect("report lock poisoned").skipped_deleted += 1;
                return Ok(());
            }
            let source_storage = Uuid::parse_str(&item.storage_id).map_err(BackupError::source)?;
            if !source_storages.contains(&source_storage) {
                report
                    .lock()
                    .expect("report lock poisoned")
                    .skipped_missing_storage += 1;
                return Ok(());
            }
            let source_vault = Uuid::parse_str(&item.vault_id).map_err(BackupError::source)?;
            let Some(vault_id) = mapping.get(&(source_storage, source_vault)) else {
                report
                    .lock()
                    .expect("report lock poisoned")
                    .skipped_missing_vault += 1;
                return Ok(());
            };
            if LocalItemRepo::new(&ctx.pool)
                .get_active_by_vault_path(storage_id, *vault_id, &item.path)
                .await
                .map_err(BackupError::source)?
                .is_some()
            {
                report
                    .lock()
                    .expect("report lock poisoned")
                    .skipped_existing += 1;
                return Ok(());
            }
            services
                .put_item_with_metadata(
                    storage_id,
                    *vault_id,
                    item.path,
                    item.type_id,
                    item.payload,
                    zann_core::ItemMetadata {
                        tags: item.tags,
                        favorite: item.favorite,
                    },
                )
                .await
                .map_err(BackupError::source)?;
            report.lock().expect("report lock poisoned").imported_items += 1;
            Ok(())
        }
    })
    .await?;
    let mut pending = PendingChangeRepo::new(&ctx.pool)
        .count_by_storage(storage_id)
        .await
        .map_err(BackupError::source)?;
    while pending > 0 {
        ensure_complete(session.sync().await.map_err(BackupError::source)?)?;
        let remaining = PendingChangeRepo::new(&ctx.pool)
            .count_by_storage(storage_id)
            .await
            .map_err(BackupError::source)?;
        if remaining >= pending {
            return Err(BackupError::new(
                "backup_sync_incomplete",
                "sync made no progress on pending import changes",
            ));
        }
        pending = remaining;
    }
    Ok(report.into_inner().expect("report lock poisoned"))
}

fn ensure_complete(outcome: zann_client::app::SyncOutcome) -> Result<(), BackupError> {
    if outcome.status() != SyncOutcomeStatus::Complete {
        return Err(BackupError::new(
            "backup_sync_incomplete",
            "backup sync did not complete",
        ));
    }
    Ok(())
}
