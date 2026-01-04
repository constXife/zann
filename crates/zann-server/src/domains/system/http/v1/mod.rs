use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use schemars::JsonSchema;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zann_core::SecurityProfile;

use crate::app::AppState;
use crate::config::AuthMode;

#[derive(Serialize, JsonSchema)]
pub(crate) struct SystemInfoResponse {
    pub(crate) version: &'static str,
    pub(crate) build_commit: Option<&'static str>,
    pub(crate) server_name: Option<String>,
    pub(crate) server_fingerprint: String,
    pub(crate) auth_methods: Vec<&'static str>,
    pub(crate) personal_vaults_enabled: bool,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/system/info", get(info))
        .route("/v1/system/security-profiles", get(security_profiles))
}

async fn info(State(state): State<AppState>) -> impl IntoResponse {
    let version = env!("CARGO_PKG_VERSION");
    let build_commit = option_env!("GIT_COMMIT");
    let fingerprint = if let Some(value) = state.config.server.fingerprint.clone() {
        value
    } else {
        let mut hasher = Sha256::new();
        hasher.update(state.token_pepper.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    };

    let mut auth_methods = Vec::new();
    if state.config.auth.internal.enabled && !matches!(state.config.auth.mode, AuthMode::Oidc) {
        auth_methods.push("password");
        auth_methods.push("service_account");
    }
    if state.config.auth.oidc.enabled && !matches!(state.config.auth.mode, AuthMode::Internal) {
        auth_methods.push("oidc");
        if !auth_methods.contains(&"service_account") {
            auth_methods.push("service_account");
        }
    }

    (
        StatusCode::OK,
        Json(SystemInfoResponse {
            version,
            build_commit,
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
