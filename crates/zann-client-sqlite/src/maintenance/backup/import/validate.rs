use super::*;
use std::collections::{HashMap, HashSet};

pub(super) struct ValidatedBackup {
    pub specs: Vec<BackupVaultSpec>,
    pub source_storages: HashSet<Uuid>,
    pub source_vaults: HashMap<(Uuid, Uuid), (VaultKind, String)>,
}

pub(super) fn validate(
    input: &BackupInput,
    selected: Option<Uuid>,
) -> Result<ValidatedBackup, BackupError> {
    let meta = read_backup_metadata(input).map_err(BackupError::source)?;
    if meta.version != BACKUP_VERSION {
        return Err(BackupError::new(
            "backup_version_unsupported",
            "unsupported backup version",
        ));
    }
    if meta.vaults.len() > zann_client::app::BACKUP_MAX_VAULTS
        || meta.storages.len() > zann_client::app::BACKUP_MAX_VAULTS
    {
        return Err(BackupError::new(
            "backup_limit_exceeded",
            "too many backup storages or vaults",
        ));
    }
    let source_storages = meta
        .storages
        .iter()
        .map(|s| Uuid::parse_str(&s.id))
        .collect::<Result<HashSet<_>, _>>()
        .map_err(BackupError::source)?;
    if source_storages.len() != meta.storages.len() || source_storages.iter().any(Uuid::is_nil) {
        return Err(BackupError::new(
            "backup_invalid_catalog",
            "invalid backup storage catalog",
        ));
    }
    if selected.is_some_and(|id| !source_storages.contains(&id)) {
        return Err(BackupError::new(
            "backup_source_missing",
            "selected source storage is not in this backup",
        ));
    }
    let mut source_vaults = std::collections::HashMap::new();
    let mut specs = Vec::new();
    for vault in &meta.vaults {
        let source_storage = Uuid::parse_str(&vault.storage_id).map_err(BackupError::source)?;
        let source_id = Uuid::parse_str(&vault.id).map_err(BackupError::source)?;
        let kind = VaultKind::try_from(vault.kind).map_err(BackupError::source)?;
        if source_id.is_nil()
            || vault.name.trim().is_empty()
            || vault.name.trim() != vault.name
            || vault.name.len() > 200
            || !source_storages.contains(&source_storage)
            || source_vaults
                .insert((source_storage, source_id), (kind, vault.name.clone()))
                .is_some()
        {
            return Err(BackupError::new(
                "backup_invalid_catalog",
                "invalid backup vault catalog",
            ));
        }
        if selected.is_none_or(|id| source_storage == id) {
            specs.push(BackupVaultSpec {
                source_id,
                name: vault.name.clone(),
                kind,
            });
        }
    }
    stream_backup_items(input, |item, _| {
        let storage = Uuid::parse_str(&item.storage_id).map_err(|e| e.to_string())?;
        let vault = Uuid::parse_str(&item.vault_id).map_err(|e| e.to_string())?;
        if storage.is_nil() || vault.is_nil() {
            return Err("invalid backup item identity".into());
        }
        if let Some(id) = &item.id {
            if Uuid::parse_str(id).map_err(|e| e.to_string())?.is_nil() {
                return Err("invalid backup item identity".into());
            }
        }
        if item.version < 1
            || chrono::DateTime::parse_from_rfc3339(&item.updated_at).is_err()
            || item
                .deleted_at
                .as_ref()
                .is_some_and(|at| chrono::DateTime::parse_from_rfc3339(at).is_err())
            || item.path.rsplit('/').next() != Some(item.name.as_str())
        {
            return Err("invalid backup item location or revision".into());
        }
        let metadata = zann_core::ItemMetadata {
            tags: item.tags,
            favorite: item.favorite,
        };
        let canonical_path =
            LocalServices::validate_item_input(&item.path, &item.type_id, &item.payload, &metadata)
                .map_err(|e| e.to_string())?;
        if canonical_path != item.path {
            return Err("backup item path is not canonical".into());
        }
        Ok(())
    })
    .map_err(BackupError::source)?;
    if let Some(selected) = selected {
        source_vaults.retain(|(storage, _), _| *storage == selected);
    }
    Ok(ValidatedBackup {
        specs,
        source_storages: selected.map_or(source_storages, |id| HashSet::from([id])),
        source_vaults,
    })
}
