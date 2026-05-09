use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use zann_db::SqlitePool;

use crate::types::{OidcConfigResponse, OidcDiscovery, SystemInfoResponse};
use zann_core::api::auth::PreloginResponse;

#[derive(Clone)]
pub struct ClientState {
    pub pool: SqlitePool,
    pub root: PathBuf,
    pub pending_logins: Arc<Mutex<HashMap<String, PendingLogin>>>,
}

impl ClientState {
    pub fn new(pool: SqlitePool, root: PathBuf) -> Self {
        Self {
            pool,
            root,
            pending_logins: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[derive(Clone)]
pub struct PendingLogin {
    pub server_url: String,
    pub discovery: OidcDiscovery,
    pub oidc_config: OidcConfigResponse,
    pub oauth_state: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub fingerprint_new: Option<String>,
    pub fingerprint_trusted: bool,
    pub pending_result: Option<PendingLoginResult>,
}

#[derive(Clone)]
pub struct PendingLoginResult {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub email: String,
    pub prelogin: PreloginResponse,
    pub info: SystemInfoResponse,
    pub token_name: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct TokenEntry {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub access_expires_at: Option<String>,
    #[serde(default)]
    pub service_account_token: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CliContext {
    pub addr: String,
    #[serde(default)]
    pub needs_salt_update: bool,
    #[serde(default)]
    pub server_id: Option<String>,
    #[serde(default)]
    pub server_fingerprint: Option<String>,
    #[serde(default)]
    pub expected_master_key_fp: Option<String>,
    #[serde(default)]
    pub tokens: HashMap<String, TokenEntry>,
    #[serde(default)]
    pub current_token: Option<String>,
    #[serde(default)]
    pub storage_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CliConfig {
    #[serde(default)]
    pub current_context: Option<String>,
    #[serde(default)]
    pub contexts: HashMap<String, CliContext>,
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IdentityConfig {
    pub kdf_salt: String,
    pub kdf_params: zann_core::api::auth::KdfParams,
    #[serde(default)]
    pub salt_fingerprint: Option<String>,
    #[serde(default)]
    pub first_seen_at: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}
