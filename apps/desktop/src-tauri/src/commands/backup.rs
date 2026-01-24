use tauri::State;

use crate::services::backup as backup_service;
use crate::state::AppState;
use crate::types::{ApiResponse, PlainBackupExportResponse, PlainBackupImportResponse};

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
    path: String,
) -> Result<ApiResponse<PlainBackupImportResponse>, String> {
    backup_service::plain_import(state, path).await
}
