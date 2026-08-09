use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zann_core::api::auth::KdfParams;
use zann_core::AuthMethod;

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
/// Mirrors what the other writers of `config.json` actually emit.
///
/// `zann-ffi` creates an identity before any account exists, so it writes
/// `email` and `salt_fingerprint` as null. Requiring strings here made every
/// CLI command fail to parse a config written by the desktop or COSMIC client
/// with `invalid type: null, expected a string`. Until ADR 0003's Ф6 gives the
/// file one owner, every reader has to be this tolerant.
pub struct IdentityConfig {
    #[serde(default)]
    pub email: Option<String>,
    pub kdf_salt: String,
    pub kdf_params: KdfParams,
    #[serde(default)]
    pub salt_fingerprint: Option<String>,
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

#[derive(Serialize, Deserialize)]
pub struct SystemInfoResponse {
    pub server_fingerprint: String,
    #[serde(default)]
    pub server_id: Option<String>,
    #[serde(default)]
    pub identity: Option<SystemIdentity>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub personal_vaults_enabled: Option<bool>,
    #[serde(default)]
    pub auth_methods: Vec<AuthMethod>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SystemIdentity {
    pub public_key: String,
    pub timestamp: i64,
    pub signature: String,
}

pub struct CommandContext<'a> {
    pub client: &'a reqwest::Client,
    pub addr: &'a str,
    pub allow_insecure: bool,
    pub access_token: String,
    pub context_name: Option<String>,
    pub token_name: Option<String>,
    pub config: &'a mut CliConfig,
}
