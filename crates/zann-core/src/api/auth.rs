use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    pub algorithm: String,
    pub iterations: u32,
    pub memory_kb: u32,
    pub parallelism: u32,
}

impl KdfParams {
    #[must_use]
    pub fn to_crypto_params(&self) -> zann_crypto::passwords::KdfParams {
        zann_crypto::passwords::KdfParams {
            algorithm: self.algorithm.clone(),
            iterations: self.iterations,
            memory_kb: self.memory_kb,
            parallelism: self.parallelism,
        }
    }

    pub fn validate_policy(&self) -> Result<(), &'static str> {
        zann_crypto::passwords::validate_kdf_policy(&self.to_crypto_params())
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
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

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
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

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct OidcLoginRequest {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct OidcConfigResponse {
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub audience: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct InviteInfoResponse {
    pub valid: bool,
    pub uses_left: Option<i64>,
    pub expires_at: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ServiceAccountLoginRequest {
    pub token: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ServiceAccountLoginResponse {
    pub service_account_id: String,
    pub owner_user_id: String,
    pub access_token: String,
    pub expires_in: u64,
    pub vault_keys: Vec<ServiceAccountVaultKey>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ServiceAccountVaultKey {
    pub vault_id: String,
    pub vault_key: String,
}

/// The stable error envelope returned by v1 HTTP endpoints.
///
/// Unknown JSON fields are intentionally accepted so older clients can decode
/// an error after the server adds optional diagnostic metadata.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiErrorResponse {
    pub error: String,
}

impl ApiErrorResponse {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn password_auth_wire_contract_is_stable() {
        let login = LoginRequest {
            email: "person@example.test".to_string(),
            password: "login-secret".to_string(),
            device_name: Some("workstation".to_string()),
            device_platform: Some("desktop".to_string()),
            device_fingerprint: None,
            device_os: None,
            device_os_version: None,
            device_app_version: Some("1.2.3".to_string()),
        };
        assert_eq!(
            serde_json::to_value(&login).expect("serialize login request"),
            json!({
                "email": "person@example.test",
                "password": "login-secret",
                "device_name": "workstation",
                "device_platform": "desktop",
                "device_fingerprint": null,
                "device_os": null,
                "device_os_version": null,
                "device_app_version": "1.2.3"
            })
        );

        let register = RegisterRequest {
            email: "person@example.test".to_string(),
            password: "register-secret".to_string(),
            full_name: None,
            device_name: Some("workstation".to_string()),
            device_platform: Some("desktop".to_string()),
            device_fingerprint: None,
            device_os: None,
            device_os_version: None,
            device_app_version: None,
            invite_token: None,
        };
        assert_eq!(
            serde_json::to_value(&register).expect("serialize register request"),
            json!({
                "email": "person@example.test",
                "password": "register-secret",
                "device_name": "workstation",
                "device_platform": "desktop",
                "device_fingerprint": null,
                "device_os": null,
                "device_os_version": null,
                "device_app_version": null
            })
        );

        let response: LoginResponse = serde_json::from_value(json!({
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 3600,
            "future_metadata": {"ignored": true}
        }))
        .expect("decode forward-compatible login response");
        assert_eq!(response.access_token, "access");
        assert_eq!(response.refresh_token, "refresh");
        assert_eq!(response.expires_in, 3600);
    }

    #[test]
    fn refresh_wire_contract_requires_the_rotated_secret() {
        let request = RefreshRequest {
            refresh_token: "old-refresh".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&request).expect("serialize refresh request"),
            json!({"refresh_token": "old-refresh"})
        );

        let missing = serde_json::from_value::<LoginResponse>(json!({
            "access_token": "new-access",
            "expires_in": 3600
        }));
        assert!(missing.is_err(), "missing refresh_token must not decode");
    }

    #[test]
    fn oidc_and_service_account_wire_contracts_are_canonical() {
        let oidc_request = OidcLoginRequest {
            token: "oidc-token".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&oidc_request).expect("serialize OIDC request"),
            json!({"token": "oidc-token"})
        );

        let oidc_config: OidcConfigResponse = serde_json::from_value(json!({
            "issuer": "https://issuer.example.test",
            "client_id": "zann",
            "scopes": ["openid", "offline_access"]
        }))
        .expect("decode OIDC config without an audience");
        assert_eq!(oidc_config.client_id, "zann");
        assert_eq!(oidc_config.audience, None);

        let service_request = ServiceAccountLoginRequest {
            token: "zann_sa_secret".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&service_request).expect("serialize service request"),
            json!({"token": "zann_sa_secret"})
        );

        let response_json = json!({
            "service_account_id": "service-id",
            "owner_user_id": "owner-id",
            "access_token": "access",
            "expires_in": 900,
            "vault_keys": [{"vault_id": "vault-id", "vault_key": "encoded-key"}]
        });
        let response: ServiceAccountLoginResponse =
            serde_json::from_value(response_json.clone()).expect("decode full service response");
        assert_eq!(
            serde_json::to_value(&response).expect("serialize full service response"),
            response_json
        );
        assert_eq!(response.service_account_id, "service-id");
        assert_eq!(response.vault_keys.len(), 1);
        assert_eq!(response.vault_keys[0].vault_id, "vault-id");
    }

    #[test]
    fn api_error_response_accepts_future_fields() {
        let response: ApiErrorResponse = serde_json::from_value(json!({
            "error": "invalid_token",
            "request_id": "future-field",
            "details": {"retryable": false}
        }))
        .expect("decode forward-compatible API error");
        assert_eq!(response.error, "invalid_token");
    }
}
