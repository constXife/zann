use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct KdfParams {
    pub algorithm: String,
    pub iterations: u32,
    pub memory_kb: u32,
    pub parallelism: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub device_platform: Option<String>,
    #[serde(default)]
    pub device_fingerprint: Option<String>,
    #[serde(default)]
    pub device_os: Option<String>,
    #[serde(default)]
    pub device_os_version: Option<String>,
    #[serde(default)]
    pub device_app_version: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub full_name: Option<String>,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub device_platform: Option<String>,
    #[serde(default)]
    pub device_fingerprint: Option<String>,
    #[serde(default)]
    pub device_os: Option<String>,
    #[serde(default)]
    pub device_os_version: Option<String>,
    #[serde(default)]
    pub device_app_version: Option<String>,
    #[serde(default)]
    pub invite_token: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct PreloginResponse {
    pub kdf_salt: String,
    pub kdf_params: KdfParams,
    pub salt_fingerprint: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OidcLoginRequest {
    pub token: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct OidcConfigResponse {
    pub issuer: String,
    pub client_id: String,
    pub audience: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct InviteInfoResponse {
    pub valid: bool,
    pub uses_left: Option<i64>,
    pub expires_at: Option<String>,
}
