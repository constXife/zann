use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

mod support;

use tokio::sync::Semaphore;
use zann_db::PgPool;
use zann_server::app::AppState;
use zann_server::config::{MetricsConfig, MetricsProfile, ServerConfig};
use zann_server::domains::access_control::policies::{PolicyRule, PolicySet};
use zann_server::domains::access_control::policy_store::PolicyStore;
use zann_server::infra::metrics;
use zann_server::infra::security_profiles::load_security_profiles;
use zann_server::infra::usage::UsageTracker;
use zann_server::oidc::OidcJwksCache;

struct TestApp {
    _guard: support::TestGuard,
    app: axum::Router,
    _pool: PgPool,
}

impl TestApp {
    async fn new(metrics_config: MetricsConfig) -> Self {
        let guard = support::test_guard().await;
        let pool = support::setup_shared_db().await;
        support::reset_db(&pool).await;
        let rules: Vec<PolicyRule> = support::load_policy_rules();

        metrics::set_profile(metrics_config.effective_profile());
        let mut config = ServerConfig::default();
        support::tune_test_kdf(&mut config);
        let usage_tracker = std::sync::Arc::new(UsageTracker::new(pool.clone(), 100));
        let (secret_policies, secret_default_policy) = support::default_secret_policies();
        let state = AppState {
            db: pool.clone(),
            db_tx_isolation: zann_server::settings::DbTxIsolation::ReadCommitted,
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
        let app = zann_server::bootstrap::build_app(&metrics_config, state);

        Self { _guard: guard, app, _pool: pool }
    }

    async fn get(&self, path: &str) -> axum::response::Response {
        let request = Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("request");
        self.app.clone().oneshot(request).await.expect("response")
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn metrics_endpoint_exports_http_metrics() {
    let metrics_config = MetricsConfig {
        enabled: true,
        endpoint: "/metrics".to_string(),
        profile: Some(MetricsProfile::Prod),
    };
    let app = TestApp::new(metrics_config).await;

    let health_response = app.get("/health").await;
    assert_eq!(health_response.status(), StatusCode::OK);

    let metrics_response = app.get("/metrics").await;
    assert_eq!(metrics_response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(metrics_response.into_body(), usize::MAX)
        .await
        .expect("metrics body");
    let body = String::from_utf8_lossy(&bytes);
    assert!(body.contains("zann_http_requests_total"));
    assert!(body.contains("zann_http_request_duration_seconds"));
}
