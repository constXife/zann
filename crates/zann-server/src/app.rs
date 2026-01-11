use axum::{extract::DefaultBodyLimit, Extension, Router};
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::Semaphore;

use crate::config::ServerConfig;
use crate::domains::access_control::policy_store::PolicyStore;
use crate::domains::auth::core::oidc::OidcJwksCache;
use crate::domains::secrets::policies::PasswordPolicy;
use crate::infra::usage::UsageTracker;
use crate::settings::DbTxIsolation;
use ed25519_dalek::SigningKey;
use std::sync::Arc;
use zann_core::crypto::SecretKey;
use zann_core::SecurityProfileRegistry;
use zann_db::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub db_tx_isolation: DbTxIsolation,
    pub started_at: Instant,
    pub password_pepper: String,
    pub token_pepper: String,
    pub server_master_key: Option<Arc<SecretKey>>,
    pub identity_key: Arc<SigningKey>,
    pub access_token_ttl_seconds: i64,
    pub refresh_token_ttl_seconds: i64,
    pub argon2_semaphore: Arc<Semaphore>,
    pub oidc_jwks_cache: OidcJwksCache,
    pub config: ServerConfig,
    pub policy_store: PolicyStore,
    pub usage_tracker: std::sync::Arc<UsageTracker>,
    pub security_profiles: SecurityProfileRegistry,
    pub secret_policies: HashMap<String, PasswordPolicy>,
    pub secret_default_policy: String,
}

pub fn build_router(state: AppState) -> Router {
    let extension_state = state.clone();
    let max_body_bytes = state.config.server.max_body_bytes;
    crate::http::router()
        .with_state(state)
        .layer(Extension(extension_state))
        .layer(DefaultBodyLimit::max(max_body_bytes))
}
