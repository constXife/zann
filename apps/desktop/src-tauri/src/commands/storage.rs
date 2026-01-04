use tauri::State;

use crate::services::storage as storage_service;
use crate::state::AppState;
use crate::types::{ApiResponse, AppVersionResponse, StorageInfoResponse, StorageSummary};

#[tauri::command]
pub async fn storages_list(
    state: State<'_, AppState>,
) -> Result<ApiResponse<Vec<StorageSummary>>, String> {
    storage_service::storages_list(state).await
}

#[tauri::command]
pub async fn storage_info(
    state: State<'_, AppState>,
    storage_id: String,
) -> Result<ApiResponse<StorageInfoResponse>, String> {
    storage_service::storage_info(state, storage_id).await
}

#[tauri::command]
pub async fn storage_delete(
    state: State<'_, AppState>,
    storage_id: String,
    move_to_trash: bool,
) -> Result<ApiResponse<()>, String> {
    storage_service::storage_delete(state, storage_id, move_to_trash).await
}

#[tauri::command]
pub async fn storage_disconnect(
    state: State<'_, AppState>,
    storage_id: String,
) -> Result<ApiResponse<()>, String> {
    storage_service::storage_disconnect(state, storage_id).await
}

#[tauri::command]
pub async fn storage_reveal(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    storage_id: String,
) -> Result<ApiResponse<()>, String> {
    storage_service::storage_reveal(state, app, storage_id).await
}

#[tauri::command]
pub async fn storage_sign_out(
    state: State<'_, AppState>,
    storage_id: String,
    erase_cache: bool,
) -> Result<ApiResponse<()>, String> {
    storage_service::storage_sign_out(state, storage_id, erase_cache).await
}

#[tauri::command]
pub async fn local_clear_data(
    state: State<'_, AppState>,
    also_clear_remote_cache: bool,
    also_remove_connections: bool,
) -> Result<ApiResponse<()>, String> {
    storage_service::local_clear_data(state, also_clear_remote_cache, also_remove_connections).await
}

#[tauri::command]
pub async fn local_factory_reset(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<ApiResponse<()>, String> {
    storage_service::local_factory_reset(state, app).await
}

#[tauri::command]
pub async fn app_version() -> Result<ApiResponse<AppVersionResponse>, String> {
    storage_service::app_version().await
}

#[tauri::command]
pub async fn open_data_folder(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<ApiResponse<()>, String> {
    storage_service::open_data_folder(state, app).await
}

#[tauri::command]
pub async fn open_logs(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<ApiResponse<()>, String> {
    storage_service::open_logs(state, app).await
}
