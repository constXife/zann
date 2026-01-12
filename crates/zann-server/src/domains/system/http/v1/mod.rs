use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::Signer;
use schemars::JsonSchema;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zann_core::{AuthMethod, SecurityProfile};

use crate::app::AppState;
use crate::config::AuthMode;
use crate::runtime;

#[derive(Serialize, JsonSchema)]
pub(crate) struct SystemInfoResponse {
    pub(crate) version: &'static str,
    pub(crate) build_commit: Option<&'static str>,
    pub(crate) server_id: String,
    pub(crate) identity: SystemIdentity,
    pub(crate) server_name: Option<String>,
    pub(crate) server_fingerprint: String,
    pub(crate) auth_methods: Vec<AuthMethod>,
    pub(crate) personal_vaults_enabled: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SystemIdentity {
    pub(crate) public_key: String,
    pub(crate) timestamp: i64,
    pub(crate) signature: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/system/info", get(info))
        .route("/v1/system/security-profiles", get(security_profiles))
}

async fn info(State(state): State<AppState>) -> impl IntoResponse {
    let version = env!("CARGO_PKG_VERSION");
    let build_commit = option_env!("GIT_COMMIT");
    let fingerprint = runtime::server_fingerprint(&state);
    let verifying_key = state.identity_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();
    let public_key = base64::engine::general_purpose::STANDARD.encode(public_key_bytes);
    let hash = Sha256::digest(public_key_bytes);
    let server_id = BASE32_NOPAD.encode(&hash).to_ascii_lowercase();
    let timestamp = chrono::Utc::now().timestamp();
    let message = format!("zann-id:v1:{server_id}:{timestamp}");
    let signature = state.identity_key.sign(message.as_bytes());
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    let mut auth_methods = Vec::new();
    if state.config.auth.internal.enabled && !matches!(state.config.auth.mode, AuthMode::Oidc) {
        auth_methods.push(AuthMethod::Password);
        auth_methods.push(AuthMethod::ServiceAccount);
    }
    if state.config.auth.oidc.enabled && !matches!(state.config.auth.mode, AuthMode::Internal) {
        auth_methods.push(AuthMethod::Oidc);
        if !auth_methods.contains(&AuthMethod::ServiceAccount) {
            auth_methods.push(AuthMethod::ServiceAccount);
        }
    }

    (
        StatusCode::OK,
        Json(SystemInfoResponse {
            version,
            build_commit,
            server_id,
            identity: SystemIdentity {
                public_key,
                timestamp,
                signature: signature_b64,
            },
            server_name: state.config.server.name.clone(),
            server_fingerprint: fingerprint,
            auth_methods,
            personal_vaults_enabled: state.config.server.personal_vaults_enabled,
        }),
    )
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SecurityProfilesResponse {
    pub(crate) profiles: HashMap<String, SecurityProfile>,
}

async fn security_profiles(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(SecurityProfilesResponse {
            profiles: state.security_profiles.profiles().clone(),
        }),
    )
}
