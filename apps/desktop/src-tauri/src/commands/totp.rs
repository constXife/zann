use tauri::State;

use crate::services::totp as totp_service;
use crate::state::AppState;
use crate::types::{ApiResponse, TotpCodeResponse};

#[tauri::command]
pub async fn totp_generate(
    _state: State<'_, AppState>,
    secret: String,
    algorithm: Option<String>,
    digits: Option<u32>,
    period: Option<u32>,
) -> Result<ApiResponse<TotpCodeResponse>, String> {
    let response = totp_service::generate_totp(totp_service::TotpParams {
        secret,
        algorithm,
        digits,
        period,
    })?;
    Ok(ApiResponse::ok(response))
}
