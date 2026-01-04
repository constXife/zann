use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_app_version: Option<String>,
}

#[derive(Serialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[derive(Serialize)]
pub struct ServiceAccountAuthRequest {
    pub token: String,
}

#[derive(Deserialize)]
pub struct ServiceAccountAuthResponse {
    pub access_token: String,
    pub expires_in: u64,
}

#[derive(Deserialize)]
pub struct OidcConfigResponse {
    pub issuer: String,
    pub client_id: String,
    pub audience: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Deserialize)]
pub struct OidcDiscovery {
    pub device_authorization_endpoint: String,
    pub token_endpoint: String,
}

#[derive(Deserialize)]
pub struct DeviceAuthResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: i64,
    pub interval: Option<i64>,
}

#[derive(Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
}

#[derive(Deserialize)]
pub struct TokenErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}
