use tauri::State;

use crate::services::types as types_service;
use crate::state::AppState;
use crate::types::ApiResponse;
use zann_core::SecurityProfile;

#[tauri::command]
pub async fn types_list(
    state: State<'_, AppState>,
) -> Result<ApiResponse<Vec<String>>, String> {
    types_service::types_list(state).await
}

#[tauri::command]
pub async fn types_show(
    state: State<'_, AppState>,
    type_id: String,
) -> Result<ApiResponse<SecurityProfile>, String> {
    types_service::types_show(state, type_id).await
}

#[tauri::command]
pub async fn publish_list() -> Result<ApiResponse<Vec<String>>, String> {
    types_service::publish_list().await
}

#[tauri::command]
pub async fn publish_trigger() -> Result<ApiResponse<()>, String> {
    types_service::publish_trigger().await
}
