mod auth_oidc;
mod auth_password;

pub use auth_oidc::{remote_begin_login, remote_trust_fingerprint};
pub use auth_password::{password_login, password_register};

use crate::infra::remote::fetch_system_info;
use crate::types::{ApiResponse, SystemInfoResponse};

#[tauri::command]
pub async fn get_server_info(
    server_url: String,
) -> Result<ApiResponse<SystemInfoResponse>, String> {
    if server_url.trim().is_empty() {
        return Ok(ApiResponse::err("invalid_server_url", "server_url is required"));
    }
    let client = reqwest::Client::new();
    let info = fetch_system_info(&client, &server_url).await.map_err(|e| e)?;
    Ok(ApiResponse::ok(info))
}
