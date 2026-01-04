use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zann_core::api::auth::KdfParams;

#[derive(Serialize, Deserialize, Default)]
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
    pub email: String,
    pub kdf_salt: String,
    pub kdf_params: KdfParams,
    pub salt_fingerprint: String,
    #[serde(default)]
    pub first_seen_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CliContext {
    pub addr: String,
    #[serde(default)]
    pub needs_salt_update: bool,
    #[serde(default)]
    pub server_fingerprint: Option<String>,
    #[serde(default)]
    pub tokens: HashMap<String, TokenEntry>,
    #[serde(default)]
    pub current_token: Option<String>,
    #[serde(default)]
    pub vault: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TokenEntry {
    pub access_expires_at: Option<String>,
}

#[derive(Deserialize)]
pub struct SystemInfoResponse {
    pub server_fingerprint: String,
}

pub struct CommandContext<'a> {
    pub client: &'a reqwest::Client,
    pub addr: &'a str,
    pub access_token: String,
    pub context_name: Option<String>,
    pub token_name: Option<String>,
    pub config: &'a mut CliConfig,
}
