use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use uuid::Uuid;
use zann_core::crypto::SecretKey;
use zann_core::vault_crypto as core_crypto;
use zann_core::{AuthMethod, CachePolicy, ItemsService, StorageKind, VaultKind};
use zann_db::local::{
    KeyWrapType, LocalItemRepo, LocalStorage, LocalStorageRepo, LocalVault, LocalVaultRepo,
};
use zann_db::services::LocalServices;

use crate::infra::auth::ensure_access_token_for_context;
use crate::infra::config::{load_config, save_config};
use crate::infra::http::{auth_headers, decode_json_response, ensure_success};
use crate::state::{ensure_unlocked, AppState};
use crate::types::{
    ApiResponse, PlainBackup, PlainBackupExportResponse, PlainBackupImportResponse,
    PlainBackupItem, PlainBackupStorage, PlainBackupVault, PersonalVaultStatusResponse,
    VaultDetailResponse, VaultListResponse,
};
use crate::util::context_name_from_url;

const BACKUP_VERSION: u32 = 1;

fn append_backup_log(message: &str) {
    let Some(home) = dirs::home_dir() else {
        return;
    };
    let logs_dir = home.join(".zann").join("logs");
    let _ = std::fs::create_dir_all(&logs_dir);
    let log_path = logs_dir.join("backup.log");
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    else {
        return;
    };
    let _ = writeln!(file, "{} {}", Utc::now().to_rfc3339(), message);
}

fn prompt_export_path(root: &Path) -> Option<PathBuf> {
    let suggested = default_backup_path(root);
    let filename = suggested
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("zann-plain-backup.json");
    let mut dialog = rfd::FileDialog::new().add_filter("Zann backup", &["json"]);
    if let Some(parent) = suggested.parent() {
        dialog = dialog.set_directory(parent);
    }
    dialog.set_file_name(filename).save_file()
}

fn prompt_import_path() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .add_filter("Zann backup", &["json"])
        .pick_file()
}

fn slugify(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in value.chars() {
        let next = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if next == '-' {
            if last_dash || out.is_empty() {
                continue;
            }
            last_dash = true;
            out.push('-');
        } else {
            last_dash = false;
            out.push(next);
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "imported-vault".to_string()
    } else {
        trimmed
    }
}

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
                    .decrypt_payload_for_item(
                        storage_id,
                        item.vault_id,
                        item.id,
                        &item.payload_enc,
                    )
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
        _ => match prompt_export_path(&state.root) {
            Some(path) => path,
            None => {
                append_backup_log("export_cancelled");
                return Ok(ApiResponse::err(
                    "backup_cancelled",
                    "backup export cancelled",
                ))
            }
        },
    };
    append_backup_log(&format!("export_start path={}", output_path.display()));
    if let Err(err) = write_backup_file(&output_path, &backup) {
        append_backup_log(&format!(
            "export_failed path={} error={}",
            output_path.display(),
            err
        ));
        return Err(err.to_string());
    }
    append_backup_log(&format!(
        "export_ok path={} storages={} vaults={} items={}",
        output_path.display(),
        backup.storages.len(),
        backup.vaults.len(),
        backup.items.len()
    ));

    Ok(ApiResponse::ok(PlainBackupExportResponse {
        path: output_path.display().to_string(),
        storages_count: backup.storages.len(),
        vaults_count: backup.vaults.len(),
        items_count: backup.items.len(),
    }))
}

pub async fn plain_import(
    state: tauri::State<'_, AppState>,
    path: Option<String>,
    target_storage_id: Option<String>,
) -> Result<ApiResponse<PlainBackupImportResponse>, String> {
    ensure_unlocked(&state).await?;
    append_backup_log(&format!(
        "import_mode_raw target_storage_id={}",
        target_storage_id.as_deref().unwrap_or("<none>")
    ));
    let target_storage_id = match target_storage_id.as_deref() {
        Some("local") | Some("") => None,
        other => other.map(str::to_string),
    };
    append_backup_log(&format!(
        "import_mode_select target_storage_id={}",
        target_storage_id.as_deref().unwrap_or("<none>")
    ));
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

    let mut target_storage_id = target_storage_id;
    if target_storage_id.is_none() {
        if let Ok(storages) = storage_repo.list().await {
            let remote = storages
                .into_iter()
                .filter(|storage| storage.kind == StorageKind::Remote)
                .collect::<Vec<_>>();
            if remote.len() == 1 {
                target_storage_id = Some(remote[0].id.to_string());
                append_backup_log(&format!(
                    "import_mode_fallback storage_id={}",
                    remote[0].id
                ));
            }
        }
    }

    if let Some(target_storage_id) = target_storage_id.as_deref() {
        let target_id =
            Uuid::parse_str(target_storage_id).map_err(|_| "invalid storage id".to_string())?;
        match storage_repo.get(target_id).await {
            Ok(Some(storage)) => {
                append_backup_log(&format!(
                    "import_mode_candidate storage_id={} kind={}",
                    storage.id,
                    storage.kind.as_i32()
                ));
                if storage.kind == StorageKind::Remote {
                    append_backup_log(&format!(
                        "import_mode_remote storage_id={}",
                        storage.id
                    ));
                    return plain_import_remote(state, path, storage).await;
                }
                append_backup_log("import_mode_fallback reason=storage_not_remote");
            }
            Ok(None) => {
                append_backup_log("import_mode_fallback reason=storage_not_found");
            }
            Err(err) => {
                append_backup_log(&format!(
                    "import_mode_fallback reason=storage_lookup_failed error={}",
                    err
                ));
            }
        }
    }

    let input_path = match path {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => match prompt_import_path() {
            Some(path) => path,
            None => {
                append_backup_log("import_cancelled");
                return Ok(ApiResponse::err(
                    "backup_cancelled",
                    "backup import cancelled",
                ))
            }
        },
    };
    append_backup_log(&format!("import_start path={}", input_path.display()));
    append_backup_log(&format!(
        "import_read_start path={}",
        input_path.display()
    ));
    let backup = match read_backup_file(&input_path) {
        Ok(backup) => backup,
        Err(err) => {
            append_backup_log(&format!(
                "import_failed path={} error={}",
                input_path.display(),
                err
            ));
            return Err(err.to_string());
        }
    };
    append_backup_log(&format!(
        "import_read_ok path={} storages={} vaults={} items={}",
        input_path.display(),
        backup.storages.len(),
        backup.vaults.len(),
        backup.items.len()
    ));
    if backup.version != BACKUP_VERSION {
        append_backup_log(&format!(
            "import_failed path={} error=unsupported_version version={}",
            input_path.display(),
            backup.version
        ));
        return Ok(ApiResponse::err(
            "backup_version_unsupported",
            "unsupported backup version",
        ));
    }

    let mut storage_map: HashMap<Uuid, Uuid> = HashMap::new();
    let local_storage_id = Uuid::nil();
    let log_error = |message: &str| {
        append_backup_log(&format!(
            "import_failed path={} error={}",
            input_path.display(),
            message
        ));
        message.to_string()
    };
    let mut created_storages = 0usize;
    let mut mapped_to_local = 0usize;
    for storage in backup.storages {
        let storage_id =
            Uuid::parse_str(&storage.id).map_err(|_| log_error("invalid storage id"))?;
        let kind = StorageKind::try_from(storage.kind)
            .map_err(|_| log_error("invalid storage kind"))?;
        let existing = storage_repo
            .get(storage_id)
            .await
            .map_err(|err| log_error(&err.to_string()))?;
        if let Some(existing) = existing {
            storage_map.insert(storage_id, existing.id);
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
                .map_err(|err| log_error(&err.to_string()))?;
            storage_map.insert(storage_id, storage_id);
            created_storages += 1;
        } else {
            storage_map.insert(storage_id, local_storage_id);
            mapped_to_local += 1;
            append_backup_log(&format!(
                "import_storage_mapped path={} storage_id={} mapped_to={}",
                input_path.display(),
                storage_id,
                local_storage_id
            ));
        }
    }
    append_backup_log(&format!(
        "import_storages_done path={} total={} created={} mapped_to_local={}",
        input_path.display(),
        storage_map.len(),
        created_storages,
        mapped_to_local
    ));

    let mut vault_map: HashMap<(Uuid, Uuid), (Uuid, Uuid)> = HashMap::new();
    let mut created_vaults = 0usize;
    let mut reused_vaults = 0usize;
    for vault in &backup.vaults {
        let backup_storage_id =
            Uuid::parse_str(&vault.storage_id).map_err(|_| log_error("invalid storage id"))?;
        let backup_vault_id =
            Uuid::parse_str(&vault.id).map_err(|_| log_error("invalid vault id"))?;
        let Some(&target_storage_id) = storage_map.get(&backup_storage_id) else {
            append_backup_log(&format!(
                "import_vault_skip path={} storage_id={} vault_id={} reason=missing_storage",
                input_path.display(),
                backup_storage_id,
                backup_vault_id
            ));
            continue;
        };
        if let Some(existing) = vault_repo
            .get_by_name(target_storage_id, &vault.name)
            .await
            .map_err(|err| log_error(&err.to_string()))?
        {
            vault_map.insert(
                (backup_storage_id, backup_vault_id),
                (target_storage_id, existing.id),
            );
            reused_vaults += 1;
            append_backup_log(&format!(
                "import_vault_reuse path={} storage_id={} vault_id={} existing_vault_id={} name={}",
                input_path.display(),
                backup_storage_id,
                backup_vault_id,
                existing.id,
                vault.name
            ));
            continue;
        }
        if let Some(existing) = vault_repo
            .get_by_id(target_storage_id, backup_vault_id)
            .await
            .map_err(|err| log_error(&err.to_string()))?
        {
            vault_map.insert(
                (backup_storage_id, backup_vault_id),
                (target_storage_id, existing.id),
            );
            reused_vaults += 1;
            append_backup_log(&format!(
                "import_vault_reuse path={} storage_id={} vault_id={} existing_vault_id={} reason=id_match",
                input_path.display(),
                backup_storage_id,
                backup_vault_id,
                existing.id
            ));
            continue;
        }

        let vault_kind =
            VaultKind::try_from(vault.kind).map_err(|_| log_error("invalid vault kind"))?;
        let vault_id_to_use = if target_storage_id == backup_storage_id {
            backup_vault_id
        } else {
            Uuid::now_v7()
        };
        let vault_key = SecretKey::generate();
        let vault_key_enc =
            core_crypto::encrypt_vault_key(master_key.as_ref(), vault_id_to_use, &vault_key)
                .map_err(|err| log_error(&err.to_string()))?;
        let base_name = vault.name.clone();
        let mut created = false;
        for attempt in 0..6 {
            let name = if attempt == 0 {
                base_name.clone()
            } else {
                format!("{base_name} (import {attempt})")
            };
            let local_vault = LocalVault {
                id: vault_id_to_use,
                storage_id: target_storage_id,
                name: name.clone(),
                kind: vault_kind,
                is_default: vault.is_default,
                vault_key_enc: vault_key_enc.clone(),
                key_wrap_type: KeyWrapType::Master,
                last_synced_at: None,
            };
            match vault_repo.create(&local_vault).await {
                Ok(()) => {
                    if attempt > 0 {
                        append_backup_log(&format!(
                            "import_vault_renamed path={} storage_id={} vault_id={} name_from={} name_to={}",
                            input_path.display(),
                            target_storage_id,
                            vault_id_to_use,
                            base_name,
                            name
                        ));
                    }
                    vault_map.insert(
                        (backup_storage_id, backup_vault_id),
                        (target_storage_id, vault_id_to_use),
                    );
                    created_vaults += 1;
                    created = true;
                    break;
                }
                Err(err) => {
                    let message = err.to_string();
                    if message.contains("UNIQUE constraint failed: local_vaults.storage_id, local_vaults.name") {
                        continue;
                    }
                    return Err(log_error(&message));
                }
            }
        }
        if !created {
            return Err(log_error("vault_name_conflict"));
        }
    }
    append_backup_log(&format!(
        "import_vaults_done path={} total={} created={} reused={}",
        input_path.display(),
        vault_map.len(),
        created_vaults,
        reused_vaults
    ));

    let mut imported_items = 0usize;
    let mut skipped_existing = 0usize;
    let mut skipped_missing_storage = 0usize;
    let mut skipped_missing_vault = 0usize;
    let mut skipped_deleted = 0usize;

    append_backup_log(&format!(
        "import_items_start path={} total={}",
        input_path.display(),
        backup.items.len()
    ));
    for (index, item) in backup.items.into_iter().enumerate() {
        append_backup_log(&format!(
            "import_item_start path={} index={} item_id={}",
            input_path.display(),
            index,
            item.id.as_deref().unwrap_or("new")
        ));
        if item.deleted_at.is_some() {
            skipped_deleted += 1;
            append_backup_log(&format!(
                "import_item_skip path={} index={} reason=deleted",
                input_path.display(),
                index
            ));
            continue;
        }
        let backup_storage_id =
            Uuid::parse_str(&item.storage_id).map_err(|_| log_error("invalid storage id"))?;
        let backup_vault_id =
            Uuid::parse_str(&item.vault_id).map_err(|_| log_error("invalid vault id"))?;
        if !storage_map.contains_key(&backup_storage_id) {
            skipped_missing_storage += 1;
            append_backup_log(&format!(
                "import_item_skip path={} index={} reason=missing_storage",
                input_path.display(),
                index
            ));
            continue;
        }
        let Some(&(target_storage_id, target_vault_id)) =
            vault_map.get(&(backup_storage_id, backup_vault_id))
        else {
            skipped_missing_vault += 1;
            append_backup_log(&format!(
                "import_item_skip path={} index={} reason=missing_vault",
                input_path.display(),
                index
            ));
            continue;
        };
        let existing = item_repo
            .get_active_by_vault_path(target_storage_id, target_vault_id, &item.path)
            .await
            .map_err(|err| log_error(&err.to_string()))?;
        if existing.is_some() {
            skipped_existing += 1;
            append_backup_log(&format!(
                "import_item_skip path={} index={} reason=existing_path",
                input_path.display(),
                index
            ));
            continue;
        }
        match services
            .put_item(
                target_storage_id,
                target_vault_id,
                item.path.clone(),
                item.type_id.clone(),
                item.payload.clone(),
            )
            .await
        {
            Ok(_) => {
                imported_items += 1;
                append_backup_log(&format!(
                    "import_item_ok path={} index={}",
                    input_path.display(),
                    index
                ));
            }
            Err(err) if err.kind == "item_exists" => {
                skipped_existing += 1;
                append_backup_log(&format!(
                    "import_item_skip path={} index={} reason=item_exists",
                    input_path.display(),
                    index
                ));
            }
            Err(err) => {
                append_backup_log(&format!(
                    "import_failed path={} error={}",
                    input_path.display(),
                    err.message
                ));
                return Ok(ApiResponse::err(&err.kind, &err.message));
            }
        }
    }

    append_backup_log(&format!(
        "import_ok path={} imported={} skipped_existing={} skipped_missing_storage={} skipped_missing_vault={} skipped_deleted={}",
        input_path.display(),
        imported_items,
        skipped_existing,
        skipped_missing_storage,
        skipped_missing_vault,
        skipped_deleted
    ));
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

#[derive(serde::Serialize)]
struct RemoteCreateVaultRequest {
    slug: String,
    name: String,
    kind: VaultKind,
    cache_policy: CachePolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    vault_key_enc: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
}

async fn plain_import_remote(
    state: tauri::State<'_, AppState>,
    path: Option<String>,
    storage: LocalStorage,
) -> Result<ApiResponse<PlainBackupImportResponse>, String> {
    let input_path = match path {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => match prompt_import_path() {
            Some(path) => path,
            None => {
                append_backup_log("import_remote_cancelled");
                return Ok(ApiResponse::err(
                    "backup_cancelled",
                    "backup import cancelled",
                ));
            }
        },
    };
    let addr = storage
        .server_url
        .clone()
        .ok_or_else(|| "server url missing".to_string())?;
    append_backup_log(&format!(
        "import_remote_start path={} server={}",
        input_path.display(),
        addr
    ));
    let log_remote_error = |message: &str| {
        append_backup_log(&format!(
            "import_remote_failed path={} error={}",
            input_path.display(),
            message
        ));
        message.to_string()
    };
    let backup = match read_backup_file(&input_path) {
        Ok(backup) => backup,
        Err(err) => {
            append_backup_log(&format!(
                "import_remote_failed path={} error={}",
                input_path.display(),
                err
            ));
            return Err(err.to_string());
        }
    };
    if backup.version != BACKUP_VERSION {
        append_backup_log(&format!(
            "import_remote_failed path={} error=unsupported_version version={}",
            input_path.display(),
            backup.version
        ));
        return Ok(ApiResponse::err(
            "backup_version_unsupported",
            "unsupported backup version",
        ));
    }

    let mut config = load_config(&state.root).map_err(|err| err.to_string())?;
    let context_name = context_name_from_url(&addr);
    let client = reqwest::Client::new();
    let access_token = ensure_access_token_for_context(
        &client,
        &addr,
        &context_name,
        &mut config,
        Some(storage.id),
    )
    .await
    .map_err(|err| log_remote_error(&format!("auth_failed: {err}")))?;
    let _ = save_config(&state.root, &config);
    let headers = auth_headers(&access_token)
        .map_err(|err| log_remote_error(&format!("auth_header_failed: {err}")))?;

    let vaults_url = format!("{}/v1/vaults", addr.trim_end_matches('/'));
    let vaults_resp = client
        .get(vaults_url)
        .headers(headers.clone())
        .send()
        .await
        .map_err(|err| log_remote_error(&format!("vault_list_request_failed: {err}")))?;
    let vaults_resp = ensure_success(vaults_resp)
        .await
        .map_err(|err| log_remote_error(&format!("vault_list_failed: {err}")))?;
    let vaults = decode_json_response::<VaultListResponse>(vaults_resp)
        .await
        .map_err(|err| log_remote_error(&format!("vault_list_decode_failed: {err}")))?;
    let mut existing_by_name: HashMap<String, String> = HashMap::new();
    for vault in &vaults.vaults {
        if vault.kind == VaultKind::Shared.as_i32() {
            existing_by_name.insert(vault.name.clone(), vault.id.clone());
        }
    }

    let personal_status_url = format!(
        "{}/v1/vaults/personal/status",
        addr.trim_end_matches('/')
    );
    let personal_resp = client
        .get(personal_status_url)
        .headers(headers.clone())
        .send()
        .await
        .map_err(|err| log_remote_error(&format!("personal_status_request_failed: {err}")))?;
    let personal_resp = ensure_success(personal_resp)
        .await
        .map_err(|err| log_remote_error(&format!("personal_status_failed: {err}")))?;
    let personal_status =
        decode_json_response::<PersonalVaultStatusResponse>(personal_resp)
            .await
            .map_err(|err| log_remote_error(&format!("personal_status_decode_failed: {err}")))?;
    let personal_vault_id = personal_status
        .personal_vault_id
        .clone()
        .ok_or_else(|| log_remote_error("personal vault missing"))?;

    let mut vault_map: HashMap<(Uuid, Uuid), String> = HashMap::new();
    let mut created_vaults = 0usize;
    let mut reused_vaults = 0usize;
    let mut mapped_personal = 0usize;

    for vault in &backup.vaults {
        let backup_storage_id =
            Uuid::parse_str(&vault.storage_id).map_err(|_| log_remote_error("invalid storage id"))?;
        let backup_vault_id =
            Uuid::parse_str(&vault.id).map_err(|_| log_remote_error("invalid vault id"))?;
        let kind =
            VaultKind::try_from(vault.kind).map_err(|_| log_remote_error("invalid vault kind"))?;
        if kind == VaultKind::Personal {
            vault_map.insert(
                (backup_storage_id, backup_vault_id),
                personal_vault_id.clone(),
            );
            reused_vaults += 1;
            mapped_personal += 1;
            continue;
        }
        let name = vault.name.clone();
        if let Some(existing_id) = existing_by_name.get(&name) {
            vault_map.insert((backup_storage_id, backup_vault_id), existing_id.clone());
            reused_vaults += 1;
            continue;
        }
        let slug_base = slugify(&name);
        let mut created_id = None;
        for attempt in 0..6 {
            let slug = if attempt == 0 {
                slug_base.clone()
            } else {
                format!("{slug_base}-import-{attempt}")
            };
            let payload = RemoteCreateVaultRequest {
                slug: slug.clone(),
                name: name.clone(),
                kind: VaultKind::Shared,
                cache_policy: CachePolicy::Full,
                vault_key_enc: None,
                tags: None,
            };
            let create_url = format!("{}/v1/vaults", addr.trim_end_matches('/'));
            let resp = client
                .post(create_url)
                .headers(headers.clone())
                .json(&payload)
                .send()
                .await
                .map_err(|err| log_remote_error(&format!("vault_create_request_failed: {err}")))?;
            if resp.status().is_success() {
                let created = decode_json_response::<VaultDetailResponse>(resp)
                    .await
                    .map_err(|err| log_remote_error(&format!("vault_create_decode_failed: {err}")))?;
                created_id = Some(created.id.clone());
                existing_by_name.insert(name.clone(), created.id.clone());
                if attempt > 0 {
                    append_backup_log(&format!(
                        "import_remote_vault_renamed path={} name_from={} slug_to={}",
                        input_path.display(),
                        name,
                        slug
                    ));
                }
                created_vaults += 1;
                break;
            }
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::BAD_REQUEST && body.contains("slug_taken") {
                continue;
            }
            return Err(log_remote_error(&format!(
                "vault_create_failed: {status} {body}"
            )));
        }
        let Some(created_id) = created_id else {
            return Err(log_remote_error("vault_create_failed: slug_conflict"));
        };
        vault_map.insert((backup_storage_id, backup_vault_id), created_id);
    }
    append_backup_log(&format!(
        "import_remote_vaults_done path={} created={} reused={} mapped_personal={}",
        input_path.display(),
        created_vaults,
        reused_vaults,
        mapped_personal
    ));

    let mut vault_details: HashMap<String, VaultDetailResponse> = HashMap::new();
    for vault_id in vault_map.values() {
        if vault_details.contains_key(vault_id) {
            continue;
        }
        let detail_url = format!("{}/v1/vaults/{}", addr.trim_end_matches('/'), vault_id);
        let resp = client
            .get(detail_url)
            .headers(headers.clone())
            .send()
            .await
            .map_err(|err| log_remote_error(&format!("vault_detail_request_failed: {err}")))?;
        let resp = ensure_success(resp)
            .await
            .map_err(|err| log_remote_error(&format!("vault_detail_failed: {err}")))?;
        let detail = decode_json_response::<VaultDetailResponse>(resp)
            .await
            .map_err(|err| log_remote_error(&format!("vault_detail_decode_failed: {err}")))?;
        vault_details.insert(vault_id.clone(), detail);
    }

    {
        let vault_repo = LocalVaultRepo::new(&state.pool);
        for detail in vault_details.values() {
            let vault_id =
                Uuid::parse_str(&detail.id).map_err(|_| log_remote_error("invalid vault id"))?;
            if vault_repo
                .get_by_id(storage.id, vault_id)
                .await
                .map_err(|err| log_remote_error(&err.to_string()))?
                .is_some()
            {
                continue;
            }
            let kind = VaultKind::try_from(detail.kind)
                .map_err(|_| log_remote_error("invalid vault kind"))?;
            let encryption_type = detail.encryption_type;
            let key_wrap_type =
                if encryption_type == zann_core::VaultEncryptionType::Server.as_i32() {
                    KeyWrapType::RemoteServer
                } else {
                    KeyWrapType::RemoteStrict
                };
            let local_vault = LocalVault {
                id: vault_id,
                storage_id: storage.id,
                name: detail.name.clone(),
                kind,
                is_default: false,
                vault_key_enc: detail.vault_key_enc.clone(),
                key_wrap_type,
                last_synced_at: None,
            };
            vault_repo
                .create(&local_vault)
                .await
                .map_err(|err| log_remote_error(&err.to_string()))?;
        }
    }

    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| log_remote_error("vault is locked"))?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    let item_repo = LocalItemRepo::new(&state.pool);

    let mut imported_items = 0usize;
    let mut skipped_existing = 0usize;
    let mut skipped_missing_storage = 0usize;
    let mut skipped_missing_vault = 0usize;
    let mut skipped_deleted = 0usize;

    for item in &backup.items {
        if item.deleted_at.is_some() {
            skipped_deleted += 1;
            continue;
        }
        let backup_storage_id =
            Uuid::parse_str(&item.storage_id).map_err(|_| log_remote_error("invalid storage id"))?;
        let backup_vault_id =
            Uuid::parse_str(&item.vault_id).map_err(|_| log_remote_error("invalid vault id"))?;
        let Some(target_vault_id) = vault_map
            .get(&(backup_storage_id, backup_vault_id))
            .cloned()
        else {
            skipped_missing_vault += 1;
            continue;
        };
        let target_vault_id =
            Uuid::parse_str(&target_vault_id).map_err(|_| log_remote_error("invalid vault id"))?;
        let existing = item_repo
            .get_active_by_vault_path(storage.id, target_vault_id, &item.path)
            .await
            .map_err(|err| log_remote_error(&err.to_string()))?;
        if existing.is_some() {
            skipped_existing += 1;
            continue;
        }
        match services
            .put_item(
                storage.id,
                target_vault_id,
                item.path.clone(),
                item.type_id.clone(),
                item.payload.clone(),
            )
            .await
        {
            Ok(_) => imported_items += 1,
            Err(err) if err.kind == "item_exists" => skipped_existing += 1,
            Err(err) => return Err(log_remote_error(&err.message)),
        }
    }

    drop(item_repo);
    drop(services);
    let sync = crate::services::sync::remote_sync(Some(storage.id.to_string()), state).await;
    if let Ok(response) = &sync {
        if !response.ok {
            append_backup_log(&format!(
                "import_remote_sync_failed path={} error={}",
                input_path.display(),
                response
                    .error
                    .as_ref()
                    .map(|err| err.message.as_str())
                    .unwrap_or("sync failed")
            ));
            return Ok(ApiResponse::err("sync_failed", "remote sync failed"));
        }
    } else if let Err(err) = sync {
        append_backup_log(&format!(
            "import_remote_sync_failed path={} error={}",
            input_path.display(),
            err
        ));
        return Ok(ApiResponse::err("sync_failed", &err));
    }

    append_backup_log(&format!(
        "import_remote_ok path={} imported={} skipped_existing={} skipped_missing_storage={} skipped_missing_vault={} skipped_deleted={}",
        input_path.display(),
        imported_items,
        skipped_existing,
        skipped_missing_storage,
        skipped_missing_vault,
        skipped_deleted
    ));
    Ok(ApiResponse::ok(PlainBackupImportResponse {
        imported_items,
        skipped_existing,
        skipped_missing_storage,
        skipped_missing_vault,
        skipped_deleted,
    }))
}
