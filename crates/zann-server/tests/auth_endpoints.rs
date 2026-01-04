use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod support;

use tokio::sync::Semaphore;
use zann_core::crypto::SecretKey;
use zann_core::ServiceAccount;
use zann_db::repo::{ServiceAccountRepo, UserRepo};
use zann_db::PgPool;
use zann_server::app::{build_router, AppState};
use zann_server::config::{AuthMode, InternalRegistration, ServerConfig};
use zann_server::domains::access_control::policies::{PolicyRule, PolicySet};
use zann_server::domains::access_control::policy_store::PolicyStore;
use zann_server::infra::security_profiles::load_security_profiles;
use zann_server::infra::usage::UsageTracker;
use zann_server::oidc::OidcJwksCache;
use zann_server::passwords::{self, KdfParams};

struct TestApp {
    app: axum::Router,
    pool: PgPool,
    token_pepper: String,
    kdf_params: KdfParams,
    config: ServerConfig,
}

impl TestApp {
    async fn new() -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::new("zann_server=debug"))
                .with_test_writer()
                .try_init();
        });

        let pool = support::setup_db().await;

        let policies_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/policies.default.yaml");
        let rules: Vec<PolicyRule> =
            serde_yaml::from_str(&std::fs::read_to_string(policies_path).expect("policy file"))
                .expect("parse policies");

        let mut config = ServerConfig::default();
        config.auth.mode = AuthMode::Internal;
        config.auth.internal.enabled = true;
        config.auth.internal.registration = InternalRegistration::Open;
        let config_for_state = config.clone();

        let usage_tracker = std::sync::Arc::new(UsageTracker::new(pool.clone(), 100));
        let (secret_policies, secret_default_policy) = support::default_secret_policies();
        let token_pepper = "pepper".to_string();
        let kdf_params = KdfParams {
            algorithm: config.auth.kdf.algorithm.clone(),
            iterations: config.auth.kdf.iterations,
            memory_kb: config.auth.kdf.memory_kb,
            parallelism: config.auth.kdf.parallelism,
        };
        let state = AppState {
            db: pool.clone(),
            started_at: std::time::Instant::now(),
            password_pepper: "pepper".to_string(),
            token_pepper: token_pepper.clone(),
            server_master_key: Some(std::sync::Arc::new(SecretKey::generate())),
            access_token_ttl_seconds: 3600,
            refresh_token_ttl_seconds: 3600,
            argon2_semaphore: std::sync::Arc::new(Semaphore::new(4)),
            oidc_jwks_cache: OidcJwksCache::new(),
            config: config_for_state,
            policy_store: PolicyStore::new(PolicySet::from_rules(rules)),
            usage_tracker,
            security_profiles: load_security_profiles(),
            secret_policies,
            secret_default_policy,
        };

        let app = build_router(state);
        Self {
            app,
            pool,
            token_pepper,
            kdf_params,
            config,
        }
    }

    async fn send_json(
        &self,
        method: Method,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("encode json")))
            .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json")
        };
        (status, json)
    }

    async fn get_json(&self, uri: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json")
        };
        (status, json)
    }

    async fn get_status(&self, uri: &str) -> StatusCode {
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        response.status()
    }

    async fn send_json_status(
        &self,
        method: Method,
        uri: &str,
        body: serde_json::Value,
    ) -> StatusCode {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("encode json")))
            .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        response.status()
    }

    async fn register(&self, email: &str, password: &str) -> serde_json::Value {
        let payload = json!({
            "email": email,
            "password": password,
            "device_name": "test",
            "device_platform": "tests",
        });
        let (status, json) = self
            .send_json(Method::POST, "/v1/auth/register", payload)
            .await;
        assert_eq!(status, StatusCode::CREATED, "register failed: {:?}", json);
        json
    }

    async fn create_service_account(&self, owner_email: &str) -> String {
        let owner = UserRepo::new(&self.pool)
            .get_by_email(owner_email)
            .await
            .expect("user lookup")
            .expect("user exists");
        let token = format!("zann_sa_{}", Uuid::now_v7().simple());
        let token_prefix: String = token.chars().take(12).collect();
        let token_hash =
            passwords::hash_service_token(&token, &self.token_pepper, &self.kdf_params)
                .expect("hash token");
        let account = ServiceAccount {
            id: Uuid::now_v7(),
            owner_user_id: owner.id,
            name: "auth-sa".to_string(),
            description: None,
            token_hash,
            token_prefix,
            scopes: sqlx_core::types::Json(Vec::new()),
            allowed_ips: None,
            expires_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            use_count: 0,
            created_at: chrono::Utc::now(),
            revoked_at: None,
        };
        ServiceAccountRepo::new(&self.pool)
            .create(&account)
            .await
            .expect("create service account");
        token
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn prelogin_returns_kdf_params() {
    let app = TestApp::new().await;
    let email = "prelogin@example.com";

    let (status, body) = app
        .get_json(&format!("/v1/auth/prelogin?email={}", email))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["kdf_salt"].as_str().is_some());
    assert!(body["salt_fingerprint"].as_str().is_some());
    assert_eq!(
        body["kdf_params"]["algorithm"],
        app.config.auth.kdf.algorithm
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn prelogin_requires_email() {
    let app = TestApp::new().await;
    let status = app.get_status("/v1/auth/prelogin").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn login_issues_tokens() {
    let app = TestApp::new().await;
    let email = "login@example.com";
    let password = "password-1";
    app.register(email, password).await;

    let payload = json!({
        "email": email,
        "password": password,
        "device_name": "cli",
        "device_platform": "tests",
    });
    let (status, body) = app.send_json(Method::POST, "/v1/auth/login", payload).await;
    assert_eq!(status, StatusCode::OK, "login failed: {:?}", body);
    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn login_requires_password() {
    let app = TestApp::new().await;
    let payload = json!({ "email": "missing-password@example.com" });
    let status = app
        .send_json_status(Method::POST, "/v1/auth/login", payload)
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn login_rejects_invalid_password() {
    let app = TestApp::new().await;
    let email = "bad-login@example.com";
    app.register(email, "password-1").await;

    let payload = json!({
        "email": email,
        "password": "wrong",
        "device_name": "cli",
        "device_platform": "tests",
    });
    let (status, body) = app.send_json(Method::POST, "/v1/auth/login", payload).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_credentials");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn oidc_login_disabled_returns_forbidden() {
    let app = TestApp::new().await;
    let payload = json!({ "token": "not-a-real-token" });
    let (status, body) = app
        .send_json(Method::POST, "/v1/auth/login/oidc", payload)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "oidc_disabled");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn service_account_login_accepts_valid_token() {
    let app = TestApp::new().await;
    let email = "service-account@example.com";
    app.register(email, "password-1").await;
    let token = app.create_service_account(email).await;

    let payload = json!({ "token": token });
    let (status, body) = app
        .send_json(Method::POST, "/v1/auth/service-account", payload)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "service account login failed: {:?}",
        body
    );
    assert!(body["access_token"].as_str().is_some());
    assert!(body["service_account_id"].as_str().is_some());
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn service_account_login_rejects_invalid_format() {
    let app = TestApp::new().await;
    let payload = json!({ "token": "not-a-service-account-token" });
    let (status, body) = app
        .send_json(Method::POST, "/v1/auth/service-account", payload)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_token");
}
