use tauri::State;

use crate::services::session as session_service;
use crate::state::AppState;
use crate::types::{
    ApiResponse, AppStatusResponse, AutolockConfig, BootstrapResponse, DesktopSettings,
    KeystoreStatusResponse, StatusResponse,
};

#[tauri::command]
pub async fn bootstrap(state: State<'_, AppState>) -> Result<BootstrapResponse, String> {
    session_service::bootstrap(state).await
}

#[tauri::command]
pub async fn status(state: State<'_, AppState>) -> Result<StatusResponse, String> {
    session_service::status(state).await
}

#[tauri::command]
pub async fn app_status(
    state: State<'_, AppState>,
) -> Result<ApiResponse<AppStatusResponse>, String> {
    session_service::app_status(state).await
}

#[tauri::command]
pub async fn session_status(
    state: State<'_, AppState>,
) -> Result<ApiResponse<StatusResponse>, String> {
    session_service::session_status(state).await
}

#[tauri::command]
pub async fn session_unlock_with_password(
    app: tauri::AppHandle,
    password: String,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    session_service::session_unlock_with_password(app, password, state).await
}

#[tauri::command]
pub async fn initialize_master_password(
    app: tauri::AppHandle,
    password: String,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    session_service::initialize_master_password(app, password, state).await
}

#[tauri::command]
pub async fn initialize_local_identity(
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    session_service::initialize_local_identity(state).await
}

#[tauri::command]
pub async fn session_lock(state: State<'_, AppState>) -> Result<ApiResponse<()>, String> {
    session_service::session_lock(state).await
}

#[tauri::command]
pub async fn keystore_status(
    app: tauri::AppHandle,
) -> Result<ApiResponse<KeystoreStatusResponse>, String> {
    session_service::keystore_status(app).await
}

#[tauri::command]
#[allow(non_snake_case)]
pub async fn keystore_enable(
    app: tauri::AppHandle,
    requireBiometrics: bool,
) -> Result<ApiResponse<()>, String> {
    session_service::keystore_enable(app, requireBiometrics).await
}

#[tauri::command]
pub async fn keystore_disable(app: tauri::AppHandle) -> Result<ApiResponse<()>, String> {
    session_service::keystore_disable(app).await
}

#[tauri::command]
pub async fn session_unlock_with_biometrics(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    session_service::session_unlock_with_biometrics(app, state).await
}

#[tauri::command]
pub async fn session_rebind_biometrics(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    session_service::session_rebind_biometrics(app, state).await
}

#[tauri::command]
pub fn system_locale() -> Result<ApiResponse<String>, String> {
    session_service::system_locale()
}

#[tauri::command]
pub async fn session_autolock_config() -> Result<ApiResponse<AutolockConfig>, String> {
    session_service::session_autolock_config().await
}

#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> Result<DesktopSettings, String> {
    session_service::get_settings(state).await
}

#[tauri::command]
pub async fn update_settings(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    settings: DesktopSettings,
) -> Result<DesktopSettings, String> {
    session_service::update_settings(app, state, settings).await
}

#[tauri::command]
pub async fn unlock(
    app: tauri::AppHandle,
    password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    session_service::unlock(app, password, state).await
}
