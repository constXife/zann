use tauri::State;

use crate::services::sync as sync_service;
use crate::state::AppState;
use crate::types::ApiResponse;

#[tauri::command]
pub async fn remote_sync(
    storage_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<ApiResponse<serde_json::Value>, String> {
    sync_service::remote_sync(storage_id, state).await
}

#[tauri::command]
pub async fn remote_reset(
    storage_id: String,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    sync_service::remote_reset(storage_id, state).await
}
