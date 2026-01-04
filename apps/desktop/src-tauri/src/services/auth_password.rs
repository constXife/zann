use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

use crate::constants::TOKEN_SESSION;
use crate::infra::remote::{fetch_prelogin, fetch_system_info};
use crate::services::auth::{
    apply_login_context, context_name_for_server_id, empty_oidc_config, empty_oidc_discovery,
    fingerprint_change_for_context, insert_pending_login,
};
use crate::state::{AppState, PendingLogin, PendingLoginResult};
use crate::types::ApiResponse;
use crate::util::context_name_from_url;

#[derive(Serialize)]
pub struct PasswordAuthResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    login_id: Option<String>,
}

fn password_success(email: String, storage_id: Option<String>) -> PasswordAuthResponse {
    PasswordAuthResponse {
        status: "success".to_string(),
        storage_id,
        email: Some(email),
        old_fingerprint: None,
        new_fingerprint: None,
        login_id: None,
    }
}

fn password_fingerprint_changed(
    email: String,
    old_fingerprint: String,
    new_fingerprint: String,
    login_id: String,
) -> PasswordAuthResponse {
    PasswordAuthResponse {
        status: "fingerprint_changed".to_string(),
        storage_id: None,
        email: Some(email),
        old_fingerprint: Some(old_fingerprint),
        new_fingerprint: Some(new_fingerprint),
        login_id: Some(login_id),
    }
}

#[derive(Serialize)]
struct InternalLoginRequest {
    email: String,
    password: String,
    device_name: Option<String>,
    device_platform: Option<String>,
    device_fingerprint: Option<String>,
    device_os: Option<String>,
    device_os_version: Option<String>,
    device_app_version: Option<String>,
}

#[derive(Serialize)]
struct InternalRegisterRequest {
    email: String,
    password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_name: Option<String>,
    device_name: Option<String>,
    device_platform: Option<String>,
    device_fingerprint: Option<String>,
    device_os: Option<String>,
    device_os_version: Option<String>,
    device_app_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invite_token: Option<String>,
}

#[derive(Deserialize)]
struct InternalLoginResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

async fn parse_server_error(response: reqwest::Response) -> (String, String) {
    #[derive(serde::Deserialize)]
    struct ErrorResponse {
        error: String,
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if let Ok(parsed) = serde_json::from_str::<ErrorResponse>(&body) {
        return (parsed.error.clone(), parsed.error);
    }
    (format!("http_{}", status.as_u16()), body)
}

pub(crate) async fn password_login(
    server_url: String,
    email: String,
    password: String,
    state: &State<'_, AppState>,
) -> Result<ApiResponse<PasswordAuthResponse>, String> {
    println!(
        "[auth] password_login_request server_url={} email={}",
        server_url, email
    );
    if server_url.trim().is_empty() {
        return Ok(ApiResponse::err("invalid_server_url", "server_url is required"));
    }
    if email.trim().is_empty() || password.trim().is_empty() {
        return Ok(ApiResponse::err("invalid_credentials", "email and password are required"));
    }

    let client = reqwest::Client::new();
    let payload = InternalLoginRequest {
        email: email.clone(),
        password,
        device_name: Some("desktop".to_string()),
        device_platform: Some("desktop".to_string()),
        device_fingerprint: None,
        device_os: None,
        device_os_version: None,
        device_app_version: None,
    };
    let url = format!("{}/v1/auth/login", server_url.trim_end_matches('/'));
    let response = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        let (kind, message) = parse_server_error(response).await;
        return Ok(ApiResponse::err(&kind, &message));
    }
    let auth: InternalLoginResponse = response.json().await.map_err(|err| err.to_string())?;

    let info = fetch_system_info(&client, &server_url).await.map_err(|e| e)?;
    let prelogin = fetch_prelogin(&client, &server_url, &email).await.map_err(|e| e)?;
    let result = PendingLoginResult {
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
        expires_in: auth.expires_in,
        email: email.clone(),
        prelogin,
        info: info.clone(),
        token_name: TOKEN_SESSION.to_string(),
    };

    let context_name = context_name_from_url(&server_url);
    let fingerprint_context = info
        .server_id
        .as_deref()
        .and_then(|server_id| context_name_for_server_id(state, server_id))
        .unwrap_or_else(|| context_name.clone());
    if let Some(existing) =
        fingerprint_change_for_context(state, &fingerprint_context, &info.server_fingerprint)
    {
        let login_id = Uuid::now_v7().to_string();
        let pending = PendingLogin {
            server_url: server_url.clone(),
            discovery: empty_oidc_discovery(),
            oidc_config: empty_oidc_config(),
            oauth_state: String::new(),
            code_verifier: String::new(),
            redirect_uri: String::new(),
            fingerprint_new: Some(info.server_fingerprint.clone()),
            fingerprint_trusted: false,
            pending_result: Some(result),
        };
        insert_pending_login(state, login_id.clone(), pending)?;
        return Ok(ApiResponse::ok(password_fingerprint_changed(
            email,
            existing,
            info.server_fingerprint,
            login_id,
        )));
    }

    let storage_id = apply_login_context(state, &server_url, &result).await?;
    Ok(ApiResponse::ok(password_success(email, storage_id)))
}

pub(crate) async fn password_register(
    server_url: String,
    email: String,
    password: String,
    full_name: Option<String>,
    state: &State<'_, AppState>,
) -> Result<ApiResponse<PasswordAuthResponse>, String> {
    println!(
        "[auth] password_register_request server_url={} email={}",
        server_url, email
    );
    if server_url.trim().is_empty() {
        return Ok(ApiResponse::err("invalid_server_url", "server_url is required"));
    }
    if email.trim().is_empty() || password.trim().is_empty() {
        return Ok(ApiResponse::err("invalid_credentials", "email and password are required"));
    }

    let client = reqwest::Client::new();
    let payload = InternalRegisterRequest {
        email: email.clone(),
        password,
        full_name: full_name.and_then(|value| {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }),
        device_name: Some("desktop".to_string()),
        device_platform: Some("desktop".to_string()),
        device_fingerprint: None,
        device_os: None,
        device_os_version: None,
        device_app_version: None,
        invite_token: None,
    };
    let url = format!("{}/v1/auth/register", server_url.trim_end_matches('/'));
    let response = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        let (kind, message) = parse_server_error(response).await;
        return Ok(ApiResponse::err(&kind, &message));
    }
    let auth: InternalLoginResponse = response.json().await.map_err(|err| err.to_string())?;

    let info = fetch_system_info(&client, &server_url).await.map_err(|e| e)?;
    let prelogin = fetch_prelogin(&client, &server_url, &email).await.map_err(|e| e)?;
    let result = PendingLoginResult {
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
        expires_in: auth.expires_in,
        email: email.clone(),
        prelogin,
        info: info.clone(),
        token_name: TOKEN_SESSION.to_string(),
    };

    let context_name = context_name_from_url(&server_url);
    let fingerprint_context = info
        .server_id
        .as_deref()
        .and_then(|server_id| context_name_for_server_id(state, server_id))
        .unwrap_or_else(|| context_name.clone());
    if let Some(existing) =
        fingerprint_change_for_context(state, &fingerprint_context, &info.server_fingerprint)
    {
        let login_id = Uuid::now_v7().to_string();
        let pending = PendingLogin {
            server_url: server_url.clone(),
            discovery: empty_oidc_discovery(),
            oidc_config: empty_oidc_config(),
            oauth_state: String::new(),
            code_verifier: String::new(),
            redirect_uri: String::new(),
            fingerprint_new: Some(info.server_fingerprint.clone()),
            fingerprint_trusted: false,
            pending_result: Some(result),
        };
        insert_pending_login(state, login_id.clone(), pending)?;
        return Ok(ApiResponse::ok(password_fingerprint_changed(
            email,
            existing,
            info.server_fingerprint,
            login_id,
        )));
    }

    let storage_id = apply_login_context(state, &server_url, &result).await?;
    Ok(ApiResponse::ok(password_success(email, storage_id)))
}
