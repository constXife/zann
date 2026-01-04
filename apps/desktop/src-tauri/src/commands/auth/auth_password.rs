use tauri::State;

use crate::services::auth_password::{self, PasswordAuthResponse};
use crate::state::AppState;
use crate::types::ApiResponse;

#[tauri::command]
pub async fn password_login(
    server_url: String,
    email: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<ApiResponse<PasswordAuthResponse>, String> {
    auth_password::password_login(server_url, email, password, &state).await
}

#[tauri::command]
pub async fn password_register(
    server_url: String,
    email: String,
    password: String,
    full_name: Option<String>,
    state: State<'_, AppState>,
) -> Result<ApiResponse<PasswordAuthResponse>, String> {
    auth_password::password_register(server_url, email, password, full_name, &state).await
}
