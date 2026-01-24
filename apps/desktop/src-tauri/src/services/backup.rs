use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::Utc;
use uuid::Uuid;
use zann_core::crypto::SecretKey;
use zann_core::vault_crypto as core_crypto;
use zann_core::{AuthMethod, StorageKind, VaultKind};
use zann_db::local::{
    KeyWrapType, LocalItemRepo, LocalStorage, LocalStorageRepo, LocalVault, LocalVaultRepo,
};
use zann_db::services::LocalServices;

use crate::state::{ensure_unlocked, AppState};
use crate::types::{
    ApiResponse, PlainBackup, PlainBackupExportResponse, PlainBackupImportResponse,
    PlainBackupItem, PlainBackupStorage, PlainBackupVault,
};

const BACKUP_VERSION: u32 = 1;

pub async fn plain_export(
    state: tauri::State<'_, AppState>,
    path: Option<String>,
) -> Result<ApiResponse<PlainBackupExportResponse>, String> {
    ensure_unlocked(&state).await?;
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    let storage_repo = LocalStorageRepo::new(&state.pool);
    let vault_repo = LocalVaultRepo::new(&state.pool);
    let item_repo = LocalItemRepo::new(&state.pool);

    let storages = storage_repo
        .list()
        .await
        .map_err(|err| err.to_string())?;

    let mut backup_storages = Vec::with_capacity(storages.len());
    let mut backup_vaults = Vec::new();
    let mut backup_items = Vec::new();

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

            let items = item_repo
                .list_by_vault(storage_id, vault.id, true)
                .await
                .map_err(|err| err.to_string())?;
            for item in items {
                let payload = services
                    .decrypt_payload(storage_id, item.vault_id, item.id, &item.payload_enc)
                    .await
                    .map_err(|err| err.message)?;
                backup_items.push(PlainBackupItem {
                    id: Some(item.id.to_string()),
                    storage_id: storage_id.to_string(),
                    vault_id: item.vault_id.to_string(),
                    path: item.path.clone(),
                    name: item.name.clone(),
                    type_id: item.type_id.clone(),
                    payload,
                    updated_at: item.updated_at.to_rfc3339(),
                    version: item.version,
                    deleted_at: item.deleted_at.map(|dt| dt.to_rfc3339()),
                });
            }
        }
    }

    let backup = PlainBackup {
        version: BACKUP_VERSION,
        exported_at: Utc::now().to_rfc3339(),
        storages: backup_storages,
        vaults: backup_vaults,
        items: backup_items,
    };

    let output_path = match path {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => default_backup_path(&state.root),
    };
    write_backup_file(&output_path, &backup).map_err(|err| err.to_string())?;

    Ok(ApiResponse::ok(PlainBackupExportResponse {
        path: output_path.display().to_string(),
        storages_count: backup.storages.len(),
        vaults_count: backup.vaults.len(),
        items_count: backup.items.len(),
    }))
}

pub async fn plain_import(
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<ApiResponse<PlainBackupImportResponse>, String> {
    ensure_unlocked(&state).await?;
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    let storage_repo = LocalStorageRepo::new(&state.pool);
    let vault_repo = LocalVaultRepo::new(&state.pool);
    let item_repo = LocalItemRepo::new(&state.pool);

    let backup = read_backup_file(Path::new(&path)).map_err(|err| err.to_string())?;
    if backup.version != BACKUP_VERSION {
        return Ok(ApiResponse::err(
            "backup_version_unsupported",
            "unsupported backup version",
        ));
    }

    let mut storages_by_id: HashMap<Uuid, StorageKind> = HashMap::new();
    for storage in backup.storages {
        let storage_id = Uuid::parse_str(&storage.id).map_err(|_| "invalid storage id")?;
        let kind = StorageKind::try_from(storage.kind).map_err(|_| "invalid storage kind")?;
        let existing = storage_repo
            .get(storage_id)
            .await
            .map_err(|err| err.to_string())?;
        if let Some(existing) = existing {
            storages_by_id.insert(storage_id, existing.kind);
            continue;
        }
        if kind == StorageKind::LocalOnly {
            let local_storage = LocalStorage {
                id: storage_id,
                kind,
                name: storage.name,
                server_url: storage.server_url,
                server_name: storage.server_name,
                server_fingerprint: storage.server_fingerprint,
                account_subject: storage.account_subject,
                personal_vaults_enabled: storage.personal_vaults_enabled,
                auth_method: storage
                    .auth_method
                    .map(AuthMethod::try_from)
                    .transpose()
                    .map_err(|_| "invalid auth method")?,
            };
            storage_repo
                .upsert(&local_storage)
                .await
                .map_err(|err| err.to_string())?;
            storages_by_id.insert(storage_id, kind);
        }
    }

    let mut existing_vaults: HashMap<(Uuid, Uuid), ()> = HashMap::new();
    for vault in &backup.vaults {
        let storage_id = Uuid::parse_str(&vault.storage_id).map_err(|_| "invalid storage id")?;
        let vault_id = Uuid::parse_str(&vault.id).map_err(|_| "invalid vault id")?;
        let existing = vault_repo
            .get_by_id(storage_id, vault_id)
            .await
            .map_err(|err| err.to_string())?;
        if existing.is_some() {
            existing_vaults.insert((storage_id, vault_id), ());
            continue;
        }

        let Some(kind) = storages_by_id.get(&storage_id) else {
            continue;
        };
        if *kind != StorageKind::LocalOnly {
            continue;
        }

        let vault_kind = VaultKind::try_from(vault.kind).map_err(|_| "invalid vault kind")?;
        let vault_key = SecretKey::generate();
        let vault_key_enc = core_crypto::encrypt_vault_key(master_key.as_ref(), vault_id, &vault_key)
            .map_err(|err| err.to_string())?;
        let local_vault = LocalVault {
            id: vault_id,
            storage_id,
            name: vault.name.clone(),
            kind: vault_kind,
            is_default: vault.is_default,
            vault_key_enc,
            key_wrap_type: KeyWrapType::Master,
            last_synced_at: None,
        };
        vault_repo
            .create(&local_vault)
            .await
            .map_err(|err| err.to_string())?;
        existing_vaults.insert((storage_id, vault_id), ());
    }

    let mut imported_items = 0usize;
    let mut skipped_existing = 0usize;
    let mut skipped_missing_storage = 0usize;
    let mut skipped_missing_vault = 0usize;
    let mut skipped_deleted = 0usize;

    for item in backup.items {
        if item.deleted_at.is_some() {
            skipped_deleted += 1;
            continue;
        }
        let storage_id = Uuid::parse_str(&item.storage_id).map_err(|_| "invalid storage id")?;
        let vault_id = Uuid::parse_str(&item.vault_id).map_err(|_| "invalid vault id")?;
        if !storages_by_id.contains_key(&storage_id) {
            skipped_missing_storage += 1;
            continue;
        }
        if !existing_vaults.contains_key(&(storage_id, vault_id)) {
            skipped_missing_vault += 1;
            continue;
        }
        let existing = item_repo
            .get_active_by_vault_path(storage_id, vault_id, &item.path)
            .await
            .map_err(|err| err.to_string())?;
        if existing.is_some() {
            skipped_existing += 1;
            continue;
        }
        match services
            .put_item(
                storage_id,
                vault_id,
                item.path.clone(),
                item.type_id.clone(),
                item.payload.clone(),
            )
            .await
        {
            Ok(_) => imported_items += 1,
            Err(err) if err.kind == "item_exists" => skipped_existing += 1,
            Err(err) => {
                return Ok(ApiResponse::err(&err.kind, &err.message));
            }
        }
    }

    Ok(ApiResponse::ok(PlainBackupImportResponse {
        imported_items,
        skipped_existing,
        skipped_missing_storage,
        skipped_missing_vault,
        skipped_deleted,
    }))
}

fn default_backup_path(root: &Path) -> PathBuf {
    let filename = format!("zann-plain-backup-{}.json", Utc::now().format("%Y%m%d-%H%M%S"));
    root.join("backups").join(filename)
}

fn write_backup_file(path: &Path, backup: &PlainBackup) -> Result<(), anyhow::Error> {
    let contents = serde_json::to_string_pretty(backup)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    Ok(())
}

fn read_backup_file(path: &Path) -> Result<PlainBackup, anyhow::Error> {
    let contents = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}
