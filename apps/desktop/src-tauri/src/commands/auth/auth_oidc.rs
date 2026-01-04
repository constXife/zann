use tauri::{AppHandle, State};

use crate::services::auth_oidc;
use crate::state::AppState;
use crate::types::{ApiResponse, OidcLoginStartResponse};

#[tauri::command]
pub async fn remote_begin_login(
    server_url: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<ApiResponse<OidcLoginStartResponse>, String> {
    auth_oidc::begin_login(server_url, &state, &app).await
}

#[tauri::command]
pub async fn remote_trust_fingerprint(
    login_id: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<ApiResponse<()>, String> {
    auth_oidc::trust_fingerprint(login_id, &state, &app).await
}
