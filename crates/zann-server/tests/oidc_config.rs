use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

mod support;

use tokio::sync::Semaphore;
use zann_db::PgPool;
use zann_server::app::{build_router, AppState};
use zann_server::config::{AuthMode, ServerConfig};
use zann_server::domains::access_control::policies::{PolicyRule, PolicySet};
use zann_server::domains::access_control::policy_store::PolicyStore;
use zann_server::infra::security_profiles::load_security_profiles;
use zann_server::infra::usage::UsageTracker;
use zann_server::oidc::OidcJwksCache;

struct TestApp {
    app: axum::Router,
    _pool: PgPool,
}

impl TestApp {
    async fn new(config: ServerConfig) -> Self {
        let pool = support::setup_db().await;

        let policy_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/policies.default.yaml");
        let rules: Vec<PolicyRule> =
            serde_yaml::from_str(&std::fs::read_to_string(policy_path).expect("policy file"))
                .expect("parse policies");

        let usage_tracker = std::sync::Arc::new(UsageTracker::new(pool.clone(), 100));
        let (secret_policies, secret_default_policy) = support::default_secret_policies();
        let state = AppState {
            db: pool.clone(),
            started_at: std::time::Instant::now(),
            password_pepper: "pepper".to_string(),
            token_pepper: "pepper".to_string(),
            server_master_key: None,

            identity_key: support::test_identity_key(),
            access_token_ttl_seconds: 3600,
            refresh_token_ttl_seconds: 3600,
            argon2_semaphore: std::sync::Arc::new(Semaphore::new(4)),
            oidc_jwks_cache: OidcJwksCache::new(),
            config,
            policy_store: PolicyStore::new(PolicySet::from_rules(rules)),
            usage_tracker,
            security_profiles: load_security_profiles(),
            secret_policies,
            secret_default_policy,
        };
        let app = build_router(state);

        Self { app, _pool: pool }
    }

    async fn get_json(&self, path: &str) -> serde_json::Value {
        let request = Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }
}

fn base_config() -> ServerConfig {
    let mut config = ServerConfig::default();
    config.auth.mode = AuthMode::Oidc;
    config.auth.oidc.enabled = true;
    config.auth.oidc.issuer = "https://auth.example.com".to_string();
    config.auth.oidc.client_id = "client-123".to_string();
    config
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn oidc_config_returns_values() {
    let mut config = base_config();
    config.auth.oidc.audience = Some("aud-1".to_string());
    let app = TestApp::new(config).await;

    let body = app.get_json("/v1/auth/oidc/config").await;
    assert_eq!(body["issuer"], "https://auth.example.com");
    assert_eq!(body["client_id"], "client-123");
    assert_eq!(body["audience"], "aud-1");
    assert!(body["scopes"].is_array());
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn oidc_config_omits_empty_audience() {
    let mut config = base_config();
    config.auth.oidc.audience = Some("   ".to_string());
    let app = TestApp::new(config).await;

    let body = app.get_json("/v1/auth/oidc/config").await;
    let audience = body.get("audience");
    assert!(audience.is_none() || audience == Some(&serde_json::Value::Null));
}
