//! Desktop backup commands.
//!
//! Plain backups use the canonical client/SQLite implementation.
//! Apple CSV remote import remains legacy migration debt.

use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use uuid::Uuid;
use zann_client_sqlite::maintenance::backup::BackupCtx;
use zann_core::VaultKind;
use zann_db::local::{KeyWrapType, LocalStorageRepo, LocalVault, LocalVaultRepo};

use crate::infra::auth::ensure_access_token_for_context;
use crate::infra::config::{load_config, save_config};
use crate::infra::http::{auth_headers, decode_json_response, ensure_success};
use crate::state::{ensure_unlocked, AppState};
use crate::types::{
    ApiResponse, ApplePasswordsImportResponse, PersonalVaultStatusResponse,
    PlainBackupExportResponse, PlainBackupImportResponse, VaultDetailResponse,
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
fn from_backup_error<T>(
    err: zann_client_sqlite::maintenance::BackupError,
) -> Result<ApiResponse<T>, String>
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

    match zann_client_sqlite::maintenance::backup::plain_export(&ctx, output_path).await {
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

    match crate::infra::sync_client::import_backup(&state.root, &ctx, input_path, target_storage_id)
        .await
    {
        Ok(report) => Ok(ApiResponse::ok(PlainBackupImportResponse {
            imported_items: report.imported_items,
            skipped_existing: report.skipped_existing,
            skipped_missing_storage: report.skipped_missing_storage,
            skipped_missing_vault: report.skipped_missing_vault,
            skipped_deleted: report.skipped_deleted,
        })),
        Err(err) => from_backup_error(err),
    }
}

pub async fn apple_import(
    state: tauri::State<'_, AppState>,
    path: Option<String>,
    target_storage_id: Option<String>,
) -> Result<ApiResponse<ApplePasswordsImportResponse>, String> {
    ensure_unlocked(&state).await?;
    let ctx = backup_ctx(&state).await?;
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

    let storage_repo = LocalStorageRepo::new(&state.pool);
    let vault_repo = LocalVaultRepo::new(&state.pool);
    let (_storage_id, _personal_vault_id) =
        if let Some(target_storage_id) = target_storage_id.as_deref() {
            let target_id =
                Uuid::parse_str(target_storage_id).map_err(|_| "invalid storage id".to_string())?;
            let storage = storage_repo
                .get(target_id)
                .await
                .map_err(|err| err.to_string())?
                .ok_or_else(|| "storage not found".to_string())?;

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
        } else {
            return Ok(ApiResponse::err(
                "import_target_required",
                "select a server storage to import into",
            ));
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
    match zann_client_sqlite::maintenance::backup::apple_passwords_import(
        &ctx,
        input_path,
        target_storage_id,
    )
    .await
    {
        Ok(report) => Ok(ApiResponse::ok(ApplePasswordsImportResponse {
            imported_items: report.imported_items,
            renamed_items: report.renamed_items,
            skipped_existing: 0,
            skipped_invalid: report.skipped_invalid,
        })),
        Err(err) => from_backup_error(err),
    }
}
fn default_backup_path(root: &Path) -> PathBuf {
    let filename = format!(
        "zann-plain-backup-{}.json",
        Utc::now().format("%Y%m%d-%H%M%S")
    );
    root.join("backups").join(filename)
}
