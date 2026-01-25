use tauri::State;

use crate::services::backup as backup_service;
use crate::state::AppState;
use crate::types::{ApiResponse, PlainBackupExportResponse, PlainBackupImportResponse};

#[derive(serde::Deserialize)]
pub struct BackupImportRequest {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default, rename = "target_storage_id")]
    pub target_storage_id: Option<String>,
}

#[tauri::command]
pub async fn backup_plain_export(
    state: State<'_, AppState>,
    path: Option<String>,
) -> Result<ApiResponse<PlainBackupExportResponse>, String> {
    backup_service::plain_export(state, path).await
}

#[tauri::command]
pub async fn backup_plain_import(
    state: State<'_, AppState>,
    payload: BackupImportRequest,
) -> Result<ApiResponse<PlainBackupImportResponse>, String> {
    backup_service::plain_import(state, payload.path, payload.target_storage_id).await
}
