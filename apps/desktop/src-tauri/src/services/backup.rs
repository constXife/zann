//! Desktop backup commands.
//!
//! The portable half of this module now lives in `zann-app`, so that COSMIC and
//! any future client can export and import too. What is left here is what is
//! genuinely desktop-bound: the file dialogs, and the two flows that still need
//! the HTTP and token machinery (`apple_import`, `plain_import_remote`). Those
//! move in the auth phase — see docs/adr/0003-shared-core-layering.md.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use csv::ReaderBuilder;
use uuid::Uuid;
use zann_app::backup::{
    extract_totp_meta, insert_payload_field, read_backup_metadata, slugify,
    stream_backup_items_async, ApplePasswordsRow, BackupCtx, ImportOutcome, BACKUP_VERSION,
};
use zann_core::{
    CachePolicy, EncryptedPayload, FieldKind, ItemsService, StorageKind, VaultKind, VaultsService,
};
use zann_db::local::{
    KeyWrapType, LocalItemRepo, LocalStorage, LocalStorageRepo, LocalVault, LocalVaultRepo,
};
use zann_db::services::LocalServices;

use crate::infra::auth::ensure_access_token_for_context;
use crate::infra::config::{load_config, save_config};
use crate::infra::http::{auth_headers, decode_json_response, ensure_success};
use crate::state::{ensure_unlocked, AppState};
use crate::types::{
    ApiResponse, ApplePasswordsImportResponse, PersonalVaultStatusResponse,
    PlainBackupExportResponse, PlainBackupImportResponse, VaultDetailResponse, VaultListResponse,
};
use crate::util::context_name_from_url;
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

/// Build the context `zann-app` needs from the Tauri state.
async fn backup_ctx(state: &tauri::State<'_, AppState>) -> Result<BackupCtx, String> {
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    Ok(BackupCtx::new(
        state.pool.clone(),
        master_key,
        state.root.clone(),
    ))
}

/// Keep the original error split intact. Failures that carried a machine
/// readable `kind` came back as a resolved `ApiResponse::err`; everything else
/// rejected with a bare string. `BackupError::from(String)` tags the latter as
/// `backup_failed`, so that is the marker.
fn from_backup_error<T>(err: zann_app::BackupError) -> Result<ApiResponse<T>, String>
where
    T: serde::Serialize,
{
    if err.kind == "backup_failed" {
        Err(err.message)
    } else {
        Ok(ApiResponse::err(&err.kind, &err.message))
    }
}

pub async fn plain_export(
    state: tauri::State<'_, AppState>,
    path: Option<String>,
) -> Result<ApiResponse<PlainBackupExportResponse>, String> {
    ensure_unlocked(&state).await?;
    let ctx = backup_ctx(&state).await?;

    let output_path = match path {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => match prompt_export_path(&state.root) {
            Some(path) => path,
            None => {
                append_backup_log("export_cancelled");
                return Ok(ApiResponse::err(
                    "backup_cancelled",
                    "backup export cancelled",
                ));
            }
        },
    };

    match zann_app::backup::plain_export(&ctx, output_path).await {
        Ok(report) => Ok(ApiResponse::ok(PlainBackupExportResponse {
            path: report.path,
            storages_count: report.storages_count,
            vaults_count: report.vaults_count,
            items_count: report.items_count,
        })),
        Err(err) => from_backup_error(err),
    }
}

pub async fn plain_import(
    state: tauri::State<'_, AppState>,
    path: Option<String>,
    target_storage_id: Option<String>,
) -> Result<ApiResponse<PlainBackupImportResponse>, String> {
    ensure_unlocked(&state).await?;
    let ctx = backup_ctx(&state).await?;

    let input_path = match path.clone() {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => match prompt_import_path() {
            Some(path) => path,
            None => {
                append_backup_log("import_cancelled");
                return Ok(ApiResponse::err(
                    "backup_cancelled",
                    "backup import cancelled",
                ));
            }
        },
    };

    match zann_app::backup::plain_import(&ctx, input_path, target_storage_id).await {
        Ok(ImportOutcome::Done(report)) => Ok(ApiResponse::ok(PlainBackupImportResponse {
            imported_items: report.imported_items,
            skipped_existing: report.skipped_existing,
            skipped_missing_storage: report.skipped_missing_storage,
            skipped_missing_vault: report.skipped_missing_vault,
            skipped_deleted: report.skipped_deleted,
        })),
        // Importing into a remote storage still needs tokens and HTTP, which
        // have not moved into `zann-app` yet.
        Ok(ImportOutcome::NeedsRemote(storage)) => plain_import_remote(state, path, storage).await,
        Err(err) => from_backup_error(err),
    }
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

    let (storage_id, personal_vault_id) =
        if let Some(target_storage_id) = target_storage_id.as_deref() {
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

                    let personal_status_url =
                        format!("{}/v1/vaults/personal/status", addr.trim_end_matches('/'));
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

                    let detail_url = format!(
                        "{}/v1/vaults/{}",
                        addr.trim_end_matches('/'),
                        personal_vault_id
                    );
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
                            slug: detail.slug.clone(),
                            name: detail.name.clone(),
                            kind,
                            is_default: false,
                            vault_key_enc: detail.vault_key_enc.clone(),
                            key_wrap_type,
                            cache_key_fp: None,
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
    append_backup_log(&format!("apple_import_start path={}", input_path.display()));

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
    let filename = format!(
        "zann-plain-backup-{}.json",
        Utc::now().format("%Y%m%d-%H%M%S")
    );
    root.join("backups").join(filename)
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

    let personal_status_url = format!("{}/v1/vaults/personal/status", addr.trim_end_matches('/'));
    let personal_resp = client
        .get(personal_status_url)
        .headers(headers.clone())
        .send()
        .await
        .map_err(|err| log_remote_error(&format!("personal_status_request_failed: {err}")))?;
    let personal_resp = ensure_success(personal_resp)
        .await
        .map_err(|err| log_remote_error(&format!("personal_status_failed: {err}")))?;
    let personal_status = decode_json_response::<PersonalVaultStatusResponse>(personal_resp)
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
        let backup_storage_id = Uuid::parse_str(&vault.storage_id)
            .map_err(|_| log_remote_error("invalid storage id"))?;
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
                    .map_err(|err| {
                        log_remote_error(&format!("vault_create_decode_failed: {err}"))
                    })?;
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
                slug: detail.slug.clone(),
                name: detail.name.clone(),
                kind,
                is_default: false,
                vault_key_enc: detail.vault_key_enc.clone(),
                key_wrap_type,
                cache_key_fp: None,
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
                let mut guard = counters
                    .lock()
                    .map_err(|_| "counter_lock_failed".to_string())?;
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
                let mut guard = counters
                    .lock()
                    .map_err(|_| "counter_lock_failed".to_string())?;
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
                let mut guard = counters
                    .lock()
                    .map_err(|_| "counter_lock_failed".to_string())?;
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
                    let mut guard = counters
                        .lock()
                        .map_err(|_| "counter_lock_failed".to_string())?;
                    guard.imported_items += 1;
                }
                Err(err) if err.kind == "item_exists" => {
                    let mut guard = counters
                        .lock()
                        .map_err(|_| "counter_lock_failed".to_string())?;
                    guard.skipped_existing += 1;
                }
                Err(err) => {
                    append_backup_log(&format!(
                        "import_remote_failed path={} error={}",
                        path_display, err.message
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
        let counters = counters
            .lock()
            .map_err(|_| "counter_lock_failed".to_string())?;
        (
            counters.imported_items,
            counters.skipped_existing,
            counters.skipped_missing_vault,
            counters.skipped_deleted,
        )
    };
    let skipped_missing_storage = 0usize;

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
