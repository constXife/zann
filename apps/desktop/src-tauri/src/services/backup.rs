use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::future::Future;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use csv::ReaderBuilder;
use percent_encoding::percent_decode_str;
use serde::de::{self, DeserializeSeed, Deserializer as _, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use tokio::sync::mpsc;
use url::Url;
use uuid::Uuid;
use zann_core::crypto::SecretKey;
use zann_core::vault_crypto as core_crypto;
use zann_core::{
    AuthMethod, CachePolicy, EncryptedPayload, FieldKind, FieldValue, ItemsService, StorageKind,
    VaultKind, VaultsService,
};
use zann_db::local::{
    KeyWrapType, LocalItem, LocalItemRepo, LocalStorage, LocalStorageRepo, LocalVault,
    LocalVaultRepo,
};
use zann_db::services::LocalServices;

use crate::infra::auth::ensure_access_token_for_context;
use crate::infra::config::{load_config, save_config};
use crate::infra::http::{auth_headers, decode_json_response, ensure_success};
use crate::state::{ensure_unlocked, AppState};
use crate::types::{
    ApiResponse, ApplePasswordsImportResponse, PlainBackupExportResponse,
    PlainBackupImportResponse, PlainBackupItem, PlainBackupStorage, PlainBackupVault,
    PersonalVaultStatusResponse, VaultDetailResponse, VaultListResponse,
};
use crate::util::context_name_from_url;

const BACKUP_VERSION: u32 = 1;
const EXPORT_PAGE_LIMIT: i64 = 200;

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

fn prompt_apple_import_path() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .add_filter("Apple Passwords", &["csv"])
        .pick_file()
}

struct TotpMeta {
    secret: String,
    otp_type: Option<String>,
    issuer: Option<String>,
    label: Option<String>,
    algorithm: Option<String>,
    digits: Option<String>,
    period: Option<String>,
}

fn extract_totp_meta(value: &str) -> Option<TotpMeta> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let url = Url::parse(trimmed).ok()?;
    if url.scheme() != "otpauth" {
        return None;
    }
    let otp_type = url.host_str().map(|value| value.to_string());
    let mut secret = None;
    let mut issuer = None;
    let mut label = None;
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;
    let raw_path = url.path().trim_matches('/');
    if !raw_path.is_empty() {
        let decoded = percent_decode_str(raw_path).decode_utf8_lossy();
        if let Some((path_issuer, path_label)) = decoded.split_once(':') {
            let path_issuer = path_issuer.trim();
            let path_label = path_label.trim();
            if !path_issuer.is_empty() && issuer.is_none() {
                issuer = Some(path_issuer.to_string());
            }
            if !path_label.is_empty() {
                label = Some(path_label.to_string());
            }
        } else {
            let path_label = decoded.trim();
            if !path_label.is_empty() {
                label = Some(path_label.to_string());
            }
        }
    }
    for (key, val) in url.query_pairs() {
        if key.eq_ignore_ascii_case("secret") {
            let value = val.trim();
            if !value.is_empty() {
                secret = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("issuer") {
            let value = val.trim();
            if !value.is_empty() {
                issuer = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("algorithm") {
            let value = val.trim();
            if !value.is_empty() {
                algorithm = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("digits") {
            let value = val.trim();
            if !value.is_empty() {
                digits = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("period") {
            let value = val.trim();
            if !value.is_empty() {
                period = Some(value.to_string());
            }
        }
    }
    let secret = secret?;
    Some(TotpMeta {
        secret,
        otp_type,
        issuer,
        label,
        algorithm,
        digits,
        period,
    })
}

#[derive(serde::Deserialize)]
struct ApplePasswordsRow {
    #[serde(rename = "Title")]
    title: String,
    #[serde(rename = "URL")]
    url: Option<String>,
    #[serde(rename = "Username")]
    username: Option<String>,
    #[serde(rename = "Password")]
    password: Option<String>,
    #[serde(rename = "Notes")]
    notes: Option<String>,
    #[serde(rename = "OTPAuth")]
    otp_auth: Option<String>,
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
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let file = File::create(&output_path).map_err(|err| err.to_string())?;
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
            append_backup_log(&format!(
                "export_failed path={} error={}",
                output_path.display(),
                err
            ));
            return Err(err.to_string());
        }
    };
    if let Err(err) = writer.flush() {
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
        backup_storages.len(),
        backup_vaults.len(),
        items_count
    ));

    Ok(ApiResponse::ok(PlainBackupExportResponse {
        path: output_path.display().to_string(),
        storages_count: backup_storages.len(),
        vaults_count: backup_vaults.len(),
        items_count,
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
    let backup_meta = match read_backup_metadata(&input_path) {
        Ok(meta) => meta,
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
        "import_read_ok path={} storages={} vaults={} items=streaming",
        input_path.display(),
        backup_meta.storages.len(),
        backup_meta.vaults.len()
    ));
    if backup_meta.version != BACKUP_VERSION {
        append_backup_log(&format!(
            "import_failed path={} error=unsupported_version version={}",
            input_path.display(),
            backup_meta.version
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
    for storage in backup_meta.storages {
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
    for vault in &backup_meta.vaults {
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

    append_backup_log(&format!(
        "import_items_start path={} total=streaming",
        input_path.display()
    ));
    #[derive(Default)]
    struct ImportCounters {
        imported_items: usize,
        skipped_existing: usize,
        skipped_missing_storage: usize,
        skipped_missing_vault: usize,
        skipped_deleted: usize,
    }

    let counters = Arc::new(Mutex::new(ImportCounters::default()));
    let api_error = Arc::new(Mutex::new(None));
    let path_display = input_path.display().to_string();
    let storage_map_ref = &storage_map;
    let vault_map_ref = &vault_map;
    let services_ref = &services;
    let item_repo_ref = &item_repo;

    let stream_result = stream_backup_items_async(&input_path, |item, index| {
        let counters = Arc::clone(&counters);
        let api_error = Arc::clone(&api_error);
        let path_display = path_display.clone();
        async move {
            append_backup_log(&format!(
                "import_item_start path={} index={} item_id={}",
                path_display,
                index,
                item.id.as_deref().unwrap_or("new")
            ));
            if item.deleted_at.is_some() {
                let mut guard = counters.lock().map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_deleted += 1;
                append_backup_log(&format!(
                    "import_item_skip path={} index={} reason=deleted",
                    path_display,
                    index
                ));
                return Ok(());
            }
            let backup_storage_id = Uuid::parse_str(&item.storage_id)
                .map_err(|_| "invalid storage id".to_string())?;
            let backup_vault_id =
                Uuid::parse_str(&item.vault_id).map_err(|_| "invalid vault id".to_string())?;
            if !storage_map_ref.contains_key(&backup_storage_id) {
                let mut guard = counters.lock().map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_missing_storage += 1;
                append_backup_log(&format!(
                    "import_item_skip path={} index={} reason=missing_storage",
                    path_display,
                    index
                ));
                return Ok(());
            }
            let Some(&(target_storage_id, target_vault_id)) =
                vault_map_ref.get(&(backup_storage_id, backup_vault_id))
            else {
                let mut guard = counters.lock().map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_missing_vault += 1;
                append_backup_log(&format!(
                    "import_item_skip path={} index={} reason=missing_vault",
                    path_display,
                    index
                ));
                return Ok(());
            };
            let existing = item_repo_ref
                .get_active_by_vault_path(target_storage_id, target_vault_id, &item.path)
                .await
                .map_err(|err| err.to_string())?;
            if existing.is_some() {
                let mut guard = counters.lock().map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_existing += 1;
                append_backup_log(&format!(
                    "import_item_skip path={} index={} reason=existing_path",
                    path_display,
                    index
                ));
                return Ok(());
            }
            match services_ref
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
                    let mut guard =
                        counters.lock().map_err(|_| "counter_lock_failed".to_string())?;
                    guard.imported_items += 1;
                    append_backup_log(&format!(
                        "import_item_ok path={} index={}",
                        path_display,
                        index
                    ));
                }
                Err(err) if err.kind == "item_exists" => {
                    let mut guard =
                        counters.lock().map_err(|_| "counter_lock_failed".to_string())?;
                    guard.skipped_existing += 1;
                    append_backup_log(&format!(
                        "import_item_skip path={} index={} reason=item_exists",
                        path_display,
                        index
                    ));
                }
                Err(err) => {
                    append_backup_log(&format!(
                        "import_failed path={} error={}",
                        path_display,
                        err.message
                    ));
                    if let Ok(mut guard) = api_error.lock() {
                        *guard = Some((err.kind, err.message));
                    }
                    return Err("import_failed".to_string());
                }
            }
            Ok(())
        }
    })
    .await;
    if let Ok(guard) = api_error.lock() {
        if let Some((kind, message)) = guard.as_ref() {
            return Ok(ApiResponse::err(kind, message));
        }
    }
    if let Err(err) = stream_result {
        append_backup_log(&format!(
            "import_failed path={} error={}",
            input_path.display(),
            err
        ));
        return Err(err);
    }

    let counters = counters.lock().map_err(|_| "counter_lock_failed".to_string())?;
    let imported_items = counters.imported_items;
    let skipped_existing = counters.skipped_existing;
    let skipped_missing_storage = counters.skipped_missing_storage;
    let skipped_missing_vault = counters.skipped_missing_vault;
    let skipped_deleted = counters.skipped_deleted;

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

fn insert_payload_field(
    payload: &mut EncryptedPayload,
    key: &str,
    kind: FieldKind,
    value: Option<&str>,
) {
    let Some(value) = value else {
        return;
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    payload.fields.insert(
        key.to_string(),
        FieldValue {
            kind,
            value: trimmed.to_string(),
            meta: None,
        },
    );
}

pub async fn apple_import(
    state: tauri::State<'_, AppState>,
    path: Option<String>,
    target_storage_id: Option<String>,
) -> Result<ApiResponse<ApplePasswordsImportResponse>, String> {
    ensure_unlocked(&state).await?;
    append_backup_log(&format!(
        "apple_import_mode_raw target_storage_id={}",
        target_storage_id.as_deref().unwrap_or("<none>")
    ));
    let target_storage_id = match target_storage_id.as_deref() {
        Some("local") | Some("") => None,
        other => other.map(str::to_string),
    };
    append_backup_log(&format!(
        "apple_import_mode_select target_storage_id={}",
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
                    "apple_import_mode_fallback storage_id={}",
                    remote[0].id
                ));
            }
        }
    }

    let (storage_id, personal_vault_id) = if let Some(target_storage_id) =
        target_storage_id.as_deref()
    {
        let target_id =
            Uuid::parse_str(target_storage_id).map_err(|_| "invalid storage id".to_string())?;
        let storage = storage_repo
            .get(target_id)
            .await
            .map_err(|err| err.to_string())?
            .ok_or_else(|| "storage not found".to_string())?;
        if storage.kind != StorageKind::Remote {
            let local_personal = services
                .ensure_default_local_personal()
                .await
                .map_err(|err| err.message)?;
            (Uuid::nil(), local_personal.id)
        } else {
            if !storage.personal_vaults_enabled {
                return Ok(ApiResponse::err(
                    "personal_vaults_disabled",
                    "personal vaults disabled for server",
                ));
            }
            let existing_personal = vault_repo
                .list_by_storage(storage.id)
                .await
                .map_err(|err| err.to_string())?
                .into_iter()
                .find(|vault| vault.kind == VaultKind::Personal);
            let personal_id = if let Some(existing) = existing_personal {
                existing.id
            } else {
                let addr = storage
                    .server_url
                    .clone()
                    .ok_or_else(|| "server url missing".to_string())?;
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
                .map_err(|err| format!("auth_failed: {err}"))?;
                let _ = save_config(&state.root, &config);
                let headers = auth_headers(&access_token)
                    .map_err(|err| format!("auth_header_failed: {err}"))?;

                let personal_status_url = format!(
                    "{}/v1/vaults/personal/status",
                    addr.trim_end_matches('/')
                );
                let personal_resp = client
                    .get(personal_status_url)
                    .headers(headers.clone())
                    .send()
                    .await
                    .map_err(|err| format!("personal_status_request_failed: {err}"))?;
                let personal_resp = ensure_success(personal_resp)
                    .await
                    .map_err(|err| format!("personal_status_failed: {err}"))?;
                let personal_status =
                    decode_json_response::<PersonalVaultStatusResponse>(personal_resp)
                        .await
                        .map_err(|err| format!("personal_status_decode_failed: {err}"))?;
                let personal_vault_id = personal_status
                    .personal_vault_id
                    .clone()
                    .ok_or_else(|| "personal vault missing".to_string())?;

                let detail_url =
                    format!("{}/v1/vaults/{}", addr.trim_end_matches('/'), personal_vault_id);
                let detail_resp = client
                    .get(detail_url)
                    .headers(headers.clone())
                    .send()
                    .await
                    .map_err(|err| format!("vault_detail_request_failed: {err}"))?;
                let detail_resp = ensure_success(detail_resp)
                    .await
                    .map_err(|err| format!("vault_detail_failed: {err}"))?;
                let detail = decode_json_response::<VaultDetailResponse>(detail_resp)
                    .await
                    .map_err(|err| format!("vault_detail_decode_failed: {err}"))?;

                let vault_id =
                    Uuid::parse_str(&detail.id).map_err(|_| "invalid vault id".to_string())?;
                if vault_repo
                    .get_by_id(storage.id, vault_id)
                    .await
                    .map_err(|err| err.to_string())?
                    .is_none()
                {
                    let kind = VaultKind::try_from(detail.kind)
                        .map_err(|_| "invalid vault kind".to_string())?;
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
                        .map_err(|err| err.to_string())?;
                }
                vault_id
            };
            (storage.id, personal_id)
        }
    } else {
        let local_personal = services
            .ensure_default_local_personal()
            .await
            .map_err(|err| err.message)?;
        (Uuid::nil(), local_personal.id)
    };

    let input_path = match path {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => match prompt_apple_import_path() {
            Some(path) => path,
            None => {
                append_backup_log("apple_import_cancelled");
                return Ok(ApiResponse::err(
                    "backup_cancelled",
                    "backup import cancelled",
                ));
            }
        },
    };
    append_backup_log(&format!(
        "apple_import_start path={}",
        input_path.display()
    ));

    let mut reader = ReaderBuilder::new()
        .trim(csv::Trim::All)
        .from_path(&input_path)
        .map_err(|err| err.to_string())?;

    let mut imported_items = 0usize;
    let mut skipped_existing = 0usize;
    let mut skipped_invalid = 0usize;

    for (index, result) in reader.deserialize::<ApplePasswordsRow>().enumerate() {
        let row = match result {
            Ok(row) => row,
            Err(err) => {
                append_backup_log(&format!(
                    "apple_import_failed path={} error={}",
                    input_path.display(),
                    err
                ));
                return Err(err.to_string());
            }
        };
        let row_number = index + 2;
        let title = row.title.trim();
        if title.is_empty() {
            skipped_invalid += 1;
            append_backup_log(&format!(
                "apple_import_skip path={} row={} reason=missing_title",
                input_path.display(),
                row_number
            ));
            continue;
        }

        let existing = item_repo
            .get_active_by_vault_path(storage_id, personal_vault_id, title)
            .await
            .map_err(|err| err.to_string())?;
        if existing.is_some() {
            skipped_existing += 1;
            append_backup_log(&format!(
                "apple_import_skip path={} row={} title={} reason=existing_path",
                input_path.display(),
                row_number,
                title
            ));
            continue;
        }

        let mut payload = EncryptedPayload::new("login");
        insert_payload_field(
            &mut payload,
            "username",
            FieldKind::Text,
            row.username.as_deref(),
        );
        insert_payload_field(
            &mut payload,
            "password",
            FieldKind::Password,
            row.password.as_deref(),
        );
        insert_payload_field(&mut payload, "url", FieldKind::Url, row.url.as_deref());
        insert_payload_field(&mut payload, "notes", FieldKind::Note, row.notes.as_deref());
        if let Some(otp_auth) = row.otp_auth.as_deref() {
            if let Some(meta) = extract_totp_meta(otp_auth) {
                insert_payload_field(
                    &mut payload,
                    "totp_secret",
                    FieldKind::Otp,
                    Some(meta.secret.as_str()),
                );
                let mut extra = payload.extra.take().unwrap_or_default();
                if let Some(value) = meta.otp_type {
                    extra.insert("otp_type".to_string(), value);
                }
                if let Some(value) = meta.issuer {
                    extra.insert("otp_issuer".to_string(), value);
                }
                if let Some(value) = meta.algorithm {
                    extra.insert("otp_algorithm".to_string(), value);
                }
                if let Some(value) = meta.label {
                    extra.insert("otp_label".to_string(), value);
                }
                if let Some(value) = meta.digits {
                    extra.insert("otp_digits".to_string(), value);
                }
                if let Some(value) = meta.period {
                    extra.insert("otp_period".to_string(), value);
                }
                if !extra.is_empty() {
                    payload.extra = Some(extra);
                }
            }
        }

        match services
            .put_item(
                storage_id,
                personal_vault_id,
                title.to_string(),
                "login".to_string(),
                payload,
            )
            .await
        {
            Ok(_) => imported_items += 1,
            Err(err) if err.kind == "item_exists" => skipped_existing += 1,
            Err(err)
                if matches!(
                    err.kind.as_str(),
                    "path_required"
                        | "path_invalid"
                        | "path_segment_invalid"
                        | "name_too_long"
                        | "path_segments_limit"
                        | "payload_too_large"
                ) =>
            {
                skipped_invalid += 1;
                append_backup_log(&format!(
                    "apple_import_skip path={} row={} title={} reason={}",
                    input_path.display(),
                    row_number,
                    title,
                    err.kind
                ));
            }
            Err(err) => return Err(err.message),
        }
    }

    append_backup_log(&format!(
        "apple_import_ok path={} imported={} skipped_existing={} skipped_invalid={}",
        input_path.display(),
        imported_items,
        skipped_existing,
        skipped_invalid
    ));

    Ok(ApiResponse::ok(ApplePasswordsImportResponse {
        imported_items,
        skipped_existing,
        skipped_invalid,
    }))
}

fn default_backup_path(root: &Path) -> PathBuf {
    let filename = format!("zann-plain-backup-{}.json", Utc::now().format("%Y%m%d-%H%M%S"));
    root.join("backups").join(filename)
}

struct ExportItemStreamer<'a> {
    services: LocalServices<'a>,
    item_repo: LocalItemRepo<'a>,
    vaults: VecDeque<(Uuid, Uuid)>,
    current_vault: Option<(Uuid, Uuid)>,
    cursor: Option<(chrono::DateTime<Utc>, Uuid)>,
    buffer: VecDeque<LocalItem>,
}

trait BackupItemSource: Send {
    fn next_item<'a>(
        &'a mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<PlainBackupItem>, anyhow::Error>> + Send + 'a>,
    >;
}

impl<'a> BackupItemSource for ExportItemStreamer<'a> {
    fn next_item<'b>(
        &'b mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<PlainBackupItem>, anyhow::Error>> + Send + 'b>,
    > {
        Box::pin(ExportItemStreamer::next_item(self))
    }
}

impl<'a> ExportItemStreamer<'a> {
    fn new(
        services: LocalServices<'a>,
        item_repo: LocalItemRepo<'a>,
        vaults: VecDeque<(Uuid, Uuid)>,
    ) -> Self {
        Self {
            services,
            item_repo,
            vaults,
            current_vault: None,
            cursor: None,
            buffer: VecDeque::new(),
        }
    }

    async fn next_item(&mut self) -> Result<Option<PlainBackupItem>, anyhow::Error> {
        loop {
            if let Some(item) = self.buffer.pop_front() {
                let payload = self
                    .services
                    .decrypt_payload_for_item(
                        item.storage_id,
                        item.vault_id,
                        item.id,
                        &item.payload_enc,
                    )
                    .await
                    .map_err(|err| anyhow::anyhow!(err.message))?;
                let backup_item = PlainBackupItem {
                    id: Some(item.id.to_string()),
                    storage_id: item.storage_id.to_string(),
                    vault_id: item.vault_id.to_string(),
                    path: item.path.clone(),
                    name: item.name.clone(),
                    type_id: item.type_id.clone(),
                    payload,
                    updated_at: item.updated_at.to_rfc3339(),
                    version: item.version,
                    deleted_at: item.deleted_at.map(|dt| dt.to_rfc3339()),
                };
                return Ok(Some(backup_item));
            }

            if self.current_vault.is_none() {
                self.current_vault = self.vaults.pop_front();
                self.cursor = None;
            }

            let Some((storage_id, vault_id)) = self.current_vault else {
                return Ok(None);
            };

            let items = self
                .item_repo
                .list_by_vault_paged(
                    storage_id,
                    vault_id,
                    true,
                    EXPORT_PAGE_LIMIT,
                    self.cursor,
                )
                .await?;
            if items.is_empty() {
                self.current_vault = None;
                self.cursor = None;
                continue;
            }
            if let Some(last) = items.last() {
                self.cursor = Some((last.updated_at, last.id));
            }
            self.buffer = VecDeque::from(items);
        }
    }
}

async fn write_backup_streaming<W>(
    writer: &mut W,
    version: u32,
    exported_at: &str,
    storages: &[PlainBackupStorage],
    vaults: &[PlainBackupVault],
    source: &mut dyn BackupItemSource,
) -> Result<usize, anyhow::Error>
where
    W: std::io::Write,
{
    write!(writer, "{{\"version\":")?;
    serde_json::to_writer(&mut *writer, &version)?;
    write!(writer, ",\"exported_at\":")?;
    serde_json::to_writer(&mut *writer, &exported_at)?;
    write!(writer, ",\"storages\":[")?;
    for (idx, storage) in storages.iter().enumerate() {
        if idx > 0 {
            write!(writer, ",")?;
        }
        serde_json::to_writer(&mut *writer, storage)?;
    }
    write!(writer, "],\"vaults\":[")?;
    for (idx, vault) in vaults.iter().enumerate() {
        if idx > 0 {
            write!(writer, ",")?;
        }
        serde_json::to_writer(&mut *writer, vault)?;
    }
    write!(writer, "],\"items\":[")?;
    let mut items_count = 0usize;
    let mut item_index = 0usize;
    loop {
        let item = source.next_item().await?;
        let Some(item) = item else {
            break;
        };
        if item_index > 0 {
            write!(writer, ",")?;
        }
        serde_json::to_writer(&mut *writer, &item)?;
        item_index += 1;
        items_count += 1;
    }
    write!(writer, "]}}")?;
    Ok(items_count)
}

struct PlainBackupMeta {
    version: u32,
    _exported_at: String,
    storages: Vec<PlainBackupStorage>,
    vaults: Vec<PlainBackupVault>,
}

impl<'de> Deserialize<'de> for PlainBackupMeta {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct MetaVisitor;

        impl<'de> Visitor<'de> for MetaVisitor {
            type Value = PlainBackupMeta;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("plain backup metadata")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut version: Option<u32> = None;
                let mut exported_at: Option<String> = None;
                let mut storages: Option<Vec<PlainBackupStorage>> = None;
                let mut vaults: Option<Vec<PlainBackupVault>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" => {
                            version = Some(map.next_value()?);
                        }
                        "exported_at" => {
                            exported_at = Some(map.next_value()?);
                        }
                        "storages" => {
                            storages = Some(map.next_value()?);
                        }
                        "vaults" => {
                            vaults = Some(map.next_value()?);
                        }
                        "items" => {
                            let _: IgnoredAny = map.next_value()?;
                        }
                        _ => {
                            let _: IgnoredAny = map.next_value()?;
                        }
                    }
                }

                Ok(PlainBackupMeta {
                    version: version.ok_or_else(|| de::Error::missing_field("version"))?,
                    _exported_at: exported_at
                        .ok_or_else(|| de::Error::missing_field("exported_at"))?,
                    storages: storages.ok_or_else(|| de::Error::missing_field("storages"))?,
                    vaults: vaults.ok_or_else(|| de::Error::missing_field("vaults"))?,
                })
            }
        }

        deserializer.deserialize_map(MetaVisitor)
    }
}

struct ItemsSeed<'a, F> {
    handler: &'a mut F,
    index: &'a mut usize,
}

impl<'de, 'a, F> DeserializeSeed<'de> for ItemsSeed<'a, F>
where
    F: FnMut(PlainBackupItem, usize) -> Result<(), String>,
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ItemsVisitor<'a, F> {
            handler: &'a mut F,
            index: &'a mut usize,
        }

        impl<'de, 'a, F> Visitor<'de> for ItemsVisitor<'a, F>
        where
            F: FnMut(PlainBackupItem, usize) -> Result<(), String>,
        {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("plain backup items list")
            }

            fn visit_seq<M>(self, mut seq: M) -> Result<Self::Value, M::Error>
            where
                M: SeqAccess<'de>,
            {
                while let Some(item) = seq.next_element::<PlainBackupItem>()? {
                    let index = *self.index;
                    *self.index += 1;
                    (self.handler)(item, index).map_err(de::Error::custom)?;
                }
                Ok(())
            }
        }

        deserializer.deserialize_seq(ItemsVisitor {
            handler: self.handler,
            index: self.index,
        })
    }
}

fn read_backup_metadata(path: &Path) -> Result<PlainBackupMeta, anyhow::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let meta = PlainBackupMeta::deserialize(&mut deserializer)?;
    Ok(meta)
}

fn stream_backup_items<F>(path: &Path, mut handler: F) -> Result<(), anyhow::Error>
where
    F: FnMut(PlainBackupItem, usize) -> Result<(), String>,
{
    struct StreamVisitor<'a, F> {
        handler: &'a mut F,
        index: usize,
    }

    impl<'de, 'a, F> Visitor<'de> for StreamVisitor<'a, F>
    where
        F: FnMut(PlainBackupItem, usize) -> Result<(), String>,
    {
        type Value = ();

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("plain backup stream")
        }

        fn visit_map<M>(mut self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            while let Some(key) = map.next_key::<String>()? {
                match key.as_str() {
                    "items" => {
                        let mut index = self.index;
                        map.next_value_seed(ItemsSeed {
                            handler: self.handler,
                            index: &mut index,
                        })?;
                        self.index = index;
                    }
                    _ => {
                        let _: IgnoredAny = map.next_value()?;
                    }
                }
            }
            Ok(())
        }
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    deserializer.deserialize_map(StreamVisitor {
        handler: &mut handler,
        index: 0,
    })?;
    Ok(())
}

async fn stream_backup_items_async<F, Fut>(
    path: &Path,
    mut handler: F,
) -> Result<(), String>
where
    F: FnMut(PlainBackupItem, usize) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let (tx, mut rx) = mpsc::channel(32);
    let path = path.to_path_buf();
    let handle = tokio::task::spawn_blocking(move || {
        let parse_result = stream_backup_items(&path, |item, index| {
            tx.blocking_send(Ok((item, index)))
                .map_err(|_| "channel_closed".to_string())
        });
        if let Err(err) = parse_result {
            let _ = tx.blocking_send(Err(err.to_string()));
        }
    });

    while let Some(message) = rx.recv().await {
        match message {
            Ok((item, index)) => {
                if let Err(err) = handler(item, index).await {
                    handle.abort();
                    return Err(err);
                }
            }
            Err(err) => return Err(err),
        }
    }

    handle.await.map_err(|err| err.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::BufWriter;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::collections::VecDeque;
    use crate::types::PlainBackup;

    struct VecItemSource {
        items: VecDeque<PlainBackupItem>,
    }

    impl BackupItemSource for VecItemSource {
        fn next_item<'a>(
            &'a mut self,
        ) -> Pin<
            Box<dyn Future<Output = Result<Option<PlainBackupItem>, anyhow::Error>> + Send + 'a>,
        > {
            Box::pin(async move { Ok(self.items.pop_front()) })
        }
    }

    fn sample_payload() -> EncryptedPayload {
        let mut payload = EncryptedPayload::new("login");
        payload.fields.insert(
            "username".to_string(),
            FieldValue {
                kind: FieldKind::Text,
                value: "user@example.com".to_string(),
                meta: None,
            },
        );
        payload
    }

    fn temp_path(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("zann-{label}-{}.json", Uuid::now_v7()));
        path
    }

    #[test]
    fn reads_metadata_and_streams_items() {
        let path = temp_path("backup-meta");
        let backup = PlainBackup {
            version: BACKUP_VERSION,
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            storages: vec![PlainBackupStorage {
                id: Uuid::nil().to_string(),
                kind: StorageKind::LocalOnly.as_i32(),
                name: "Local".to_string(),
                server_url: None,
                server_name: None,
                server_fingerprint: None,
                account_subject: None,
                personal_vaults_enabled: false,
                auth_method: None,
            }],
            vaults: vec![PlainBackupVault {
                id: Uuid::now_v7().to_string(),
                storage_id: Uuid::nil().to_string(),
                name: "Default".to_string(),
                kind: VaultKind::Personal.as_i32(),
                is_default: true,
            }],
            items: vec![
                PlainBackupItem {
                    id: Some(Uuid::now_v7().to_string()),
                    storage_id: Uuid::nil().to_string(),
                    vault_id: Uuid::now_v7().to_string(),
                    path: "example".to_string(),
                    name: "Example".to_string(),
                    type_id: "login".to_string(),
                    payload: sample_payload(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                    version: 1,
                    deleted_at: None,
                },
                PlainBackupItem {
                    id: Some(Uuid::now_v7().to_string()),
                    storage_id: Uuid::nil().to_string(),
                    vault_id: Uuid::now_v7().to_string(),
                    path: "example2".to_string(),
                    name: "Example 2".to_string(),
                    type_id: "login".to_string(),
                    payload: sample_payload(),
                    updated_at: "2024-01-02T00:00:00Z".to_string(),
                    version: 1,
                    deleted_at: None,
                },
            ],
        };

        let file = File::create(&path).expect("create temp backup");
        serde_json::to_writer(file, &backup).expect("write backup");

        let meta = read_backup_metadata(&path).expect("read metadata");
        assert_eq!(meta.version, BACKUP_VERSION);
        assert_eq!(meta.storages.len(), 1);
        assert_eq!(meta.vaults.len(), 1);

        let mut streamed = Vec::new();
        stream_backup_items(&path, |item, _index| {
            streamed.push(item);
            Ok(())
        })
        .expect("stream items");
        assert_eq!(streamed.len(), 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn streams_items_async() {
        let path = temp_path("backup-stream-async");
        let backup = PlainBackup {
            version: BACKUP_VERSION,
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            storages: vec![],
            vaults: vec![],
            items: vec![
                PlainBackupItem {
                    id: Some(Uuid::now_v7().to_string()),
                    storage_id: Uuid::nil().to_string(),
                    vault_id: Uuid::now_v7().to_string(),
                    path: "one".to_string(),
                    name: "One".to_string(),
                    type_id: "login".to_string(),
                    payload: sample_payload(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                    version: 1,
                    deleted_at: None,
                },
                PlainBackupItem {
                    id: Some(Uuid::now_v7().to_string()),
                    storage_id: Uuid::nil().to_string(),
                    vault_id: Uuid::now_v7().to_string(),
                    path: "two".to_string(),
                    name: "Two".to_string(),
                    type_id: "login".to_string(),
                    payload: sample_payload(),
                    updated_at: "2024-01-02T00:00:00Z".to_string(),
                    version: 1,
                    deleted_at: None,
                },
            ],
        };

        let file = File::create(&path).expect("create temp backup");
        serde_json::to_writer(file, &backup).expect("write backup");

        let items = Arc::new(Mutex::new(Vec::new()));
        let items_clone = Arc::clone(&items);
        tauri::async_runtime::block_on(async {
            stream_backup_items_async(&path, |item, _index| {
                let items_clone = Arc::clone(&items_clone);
                async move {
                    let mut guard = items_clone.lock().expect("lock items");
                    guard.push(item);
                    Ok(())
                }
            })
            .await
            .expect("stream async");
        });

        let guard = items.lock().expect("lock items");
        assert_eq!(guard.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn writes_backup_streaming() {
        let path = temp_path("backup-write");
        let storages = vec![PlainBackupStorage {
            id: Uuid::nil().to_string(),
            kind: StorageKind::LocalOnly.as_i32(),
            name: "Local".to_string(),
            server_url: None,
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: false,
            auth_method: None,
        }];
        let vaults = vec![PlainBackupVault {
            id: Uuid::now_v7().to_string(),
            storage_id: Uuid::nil().to_string(),
            name: "Default".to_string(),
            kind: VaultKind::Personal.as_i32(),
            is_default: true,
        }];
        let items = VecDeque::from(vec![
            PlainBackupItem {
                id: Some(Uuid::now_v7().to_string()),
                storage_id: Uuid::nil().to_string(),
                vault_id: Uuid::now_v7().to_string(),
                path: "alpha".to_string(),
                name: "Alpha".to_string(),
                type_id: "login".to_string(),
                payload: sample_payload(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
                version: 1,
                deleted_at: None,
            },
            PlainBackupItem {
                id: Some(Uuid::now_v7().to_string()),
                storage_id: Uuid::nil().to_string(),
                vault_id: Uuid::now_v7().to_string(),
                path: "beta".to_string(),
                name: "Beta".to_string(),
                type_id: "login".to_string(),
                payload: sample_payload(),
                updated_at: "2024-01-02T00:00:00Z".to_string(),
                version: 1,
                deleted_at: None,
            },
        ]);
        let mut source = VecItemSource { items };

        let file = File::create(&path).expect("create temp backup");
        let mut writer = BufWriter::new(file);
        let items_count = tauri::async_runtime::block_on(async {
            write_backup_streaming(
                &mut writer,
                BACKUP_VERSION,
                "2024-01-01T00:00:00Z",
                &storages,
                &vaults,
                &mut source,
            )
            .await
            .expect("write backup")
        });
        writer.flush().expect("flush");
        assert_eq!(items_count, 2);

        let meta = read_backup_metadata(&path).expect("read metadata");
        assert_eq!(meta.version, BACKUP_VERSION);
        assert_eq!(meta.storages.len(), 1);
        assert_eq!(meta.vaults.len(), 1);

        let mut streamed = Vec::new();
        stream_backup_items(&path, |item, _index| {
            streamed.push(item);
            Ok(())
        })
        .expect("stream items");
        assert_eq!(streamed.len(), 2);
        let _ = std::fs::remove_file(&path);
    }
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
    let backup_meta = match read_backup_metadata(&input_path) {
        Ok(meta) => meta,
        Err(err) => {
            append_backup_log(&format!(
                "import_remote_failed path={} error={}",
                input_path.display(),
                err
            ));
            return Err(err.to_string());
        }
    };
    if backup_meta.version != BACKUP_VERSION {
        append_backup_log(&format!(
            "import_remote_failed path={} error=unsupported_version version={}",
            input_path.display(),
            backup_meta.version
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

    for vault in &backup_meta.vaults {
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

    #[derive(Default)]
    struct ImportCounters {
        imported_items: usize,
        skipped_existing: usize,
        skipped_missing_vault: usize,
        skipped_deleted: usize,
    }

    let counters = Arc::new(Mutex::new(ImportCounters::default()));
    let path_display = input_path.display().to_string();
    let vault_map_ref = &vault_map;
    let services_ref = &services;
    let item_repo_ref = &item_repo;

    let stream_result = stream_backup_items_async(&input_path, |item, _index| {
        let counters = Arc::clone(&counters);
        let path_display = path_display.clone();
        async move {
            if item.deleted_at.is_some() {
                let mut guard = counters.lock().map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_deleted += 1;
                return Ok(());
            }
            let backup_storage_id =
                Uuid::parse_str(&item.storage_id).map_err(|_| "invalid storage id".to_string())?;
            let backup_vault_id =
                Uuid::parse_str(&item.vault_id).map_err(|_| "invalid vault id".to_string())?;
            let Some(target_vault_id) = vault_map_ref
                .get(&(backup_storage_id, backup_vault_id))
                .cloned()
            else {
                let mut guard = counters.lock().map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_missing_vault += 1;
                return Ok(());
            };
            let target_vault_id =
                Uuid::parse_str(&target_vault_id).map_err(|_| "invalid vault id".to_string())?;
            let existing = item_repo_ref
                .get_active_by_vault_path(storage.id, target_vault_id, &item.path)
                .await
                .map_err(|err| log_remote_error(&err.to_string()))?;
            if existing.is_some() {
                let mut guard = counters.lock().map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_existing += 1;
                return Ok(());
            }
            match services_ref
                .put_item(
                    storage.id,
                    target_vault_id,
                    item.path.clone(),
                    item.type_id.clone(),
                    item.payload.clone(),
                )
                .await
            {
                Ok(_) => {
                    let mut guard =
                        counters.lock().map_err(|_| "counter_lock_failed".to_string())?;
                    guard.imported_items += 1;
                }
                Err(err) if err.kind == "item_exists" => {
                    let mut guard =
                        counters.lock().map_err(|_| "counter_lock_failed".to_string())?;
                    guard.skipped_existing += 1;
                }
                Err(err) => {
                    append_backup_log(&format!(
                        "import_remote_failed path={} error={}",
                        path_display,
                        err.message
                    ));
                    return Err(log_remote_error(&err.message));
                }
            }
            Ok(())
        }
    })
    .await;
    if let Err(err) = stream_result {
        append_backup_log(&format!(
            "import_remote_failed path={} error={}",
            input_path.display(),
            err
        ));
        return Err(err);
    }

    let (imported_items, skipped_existing, skipped_missing_vault, skipped_deleted) = {
        let counters = counters.lock().map_err(|_| "counter_lock_failed".to_string())?;
        (
            counters.imported_items,
            counters.skipped_existing,
            counters.skipped_missing_vault,
            counters.skipped_deleted,
        )
    };
    let skipped_missing_storage = 0usize;

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
