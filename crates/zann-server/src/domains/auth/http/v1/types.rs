use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, JsonSchema)]
pub(crate) struct ErrorResponse {
    pub(crate) error: &'static str,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct PreloginQuery {
    pub(crate) email: String,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct ServiceAccountLoginRequest {
    pub(crate) token: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ServiceAccountLoginResponse {
    pub(crate) service_account_id: String,
    pub(crate) owner_user_id: String,
    pub(crate) access_token: String,
    pub(crate) expires_in: u64,
    pub(crate) vault_keys: Vec<ServiceAccountVaultKey>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ServiceAccountVaultKey {
    pub(crate) vault_id: String,
    pub(crate) vault_key: String,
}
