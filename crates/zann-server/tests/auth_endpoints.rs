use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod support;

use tokio::sync::Semaphore;
use zann_core::ServiceAccount;
use zann_crypto::crypto::SecretKey;
use zann_db::repo::{DeviceRepo, ServiceAccountRepo, SessionRepo, UserRepo};
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
    _guard: support::TestGuard,
    app: axum::Router,
    pool: PgPool,
    token_pepper: String,
    kdf_params: KdfParams,
    config: ServerConfig,
}

impl TestApp {
    async fn new() -> Self {
        Self::with_kdf_permits(4).await
    }

    /// `kdf_permits` sizes the Argon2 semaphore. Zero makes any code path that
    /// takes a KDF permit block forever, which is how
    /// `unknown_service_account_token_skips_kdf` observes whether hashing happens.
    async fn with_kdf_permits(kdf_permits: usize) -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::new("zann_server=debug"))
                .with_test_writer()
                .try_init();
        });

        let guard = support::test_guard().await;

        let pool = support::setup_shared_db().await;
        support::reset_db(&pool).await;
        let rules: Vec<PolicyRule> = support::load_policy_rules();

        let mut config = ServerConfig::default();

        support::tune_test_kdf(&mut config);
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
            db_tx_isolation: zann_server::settings::DbTxIsolation::ReadCommitted,
            started_at: std::time::Instant::now(),
            password_pepper: "pepper".to_string(),
            token_pepper: token_pepper.clone(),
            server_master_key: Some(std::sync::Arc::new(SecretKey::generate())),

            identity_key: support::test_identity_key(),
            access_token_ttl_seconds: 3600,
            refresh_token_ttl_seconds: 3600,
            argon2_semaphore: std::sync::Arc::new(Semaphore::new(kdf_permits)),
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
            _guard: guard,
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

    async fn get_status_with_token(&self, uri: &str, token: &str) -> StatusCode {
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
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

    /// Inserts a user straight into the database. Unlike `register` this performs
    /// no KDF, so it is usable on an app built with no KDF permits.
    async fn seed_user(&self, email: &str) {
        let now = chrono::Utc::now();
        let user = zann_core::User {
            id: Uuid::now_v7(),
            email: email.to_string(),
            full_name: None,
            password_hash: None,
            kdf_salt: "salt".to_string(),
            kdf_algorithm: "argon2id".to_string(),
            kdf_iterations: 1,
            kdf_memory_kb: 8,
            kdf_parallelism: 1,
            recovery_key_hash: None,
            status: zann_core::UserStatus::Active,
            deleted_at: None,
            deleted_by_user_id: None,
            deleted_by_device_id: None,
            row_version: 1,
            created_at: now,
            updated_at: now,
            last_login_at: None,
        };
        UserRepo::new(&self.pool)
            .create(&user)
            .await
            .expect("create user");
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
async fn register_conflict_does_not_create_extra_records() {
    let app = TestApp::new().await;

    let payload = json!({
        "email": "conflict@example.com",
        "password": "password-1",
        "device_name": "test",
        "device_platform": "tests",
    });
    let (status, _) = app
        .send_json(Method::POST, "/v1/auth/register", payload.clone())
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let user = UserRepo::new(&app.pool)
        .get_by_email("conflict@example.com")
        .await
        .expect("user lookup")
        .expect("user");
    let devices_before = DeviceRepo::new(&app.pool)
        .list_by_user(user.id, 100, 0, "asc")
        .await
        .expect("devices list");
    let sessions_before = SessionRepo::new(&app.pool)
        .list_by_user(user.id)
        .await
        .expect("sessions list");

    let (status, _) = app
        .send_json(Method::POST, "/v1/auth/register", payload)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let devices_after = DeviceRepo::new(&app.pool)
        .list_by_user(user.id, 100, 0, "asc")
        .await
        .expect("devices list");
    let sessions_after = SessionRepo::new(&app.pool)
        .list_by_user(user.id)
        .await
        .expect("sessions list");

    assert_eq!(devices_before.len(), devices_after.len());
    assert_eq!(sessions_before.len(), sessions_after.len());
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

/// The service-account branch of the auth middleware runs before any credential
/// is proven, so a well-formed but unknown token must be rejected without
/// spending an Argon2id hash — otherwise it is a free unauthenticated CPU sink.
///
/// Observed structurally rather than by timing: with a zero-permit KDF semaphore
/// any path that hashes blocks forever, so "returns promptly" means "did not hash"
/// and "times out" means "did".
#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn unknown_service_account_token_skips_kdf() {
    use std::time::Duration;

    let app = TestApp::with_kdf_permits(0).await;
    // Seeded directly: registering would itself need a KDF permit.
    app.seed_user("sa-owner@example.com").await;
    let known_token = app.create_service_account("sa-owner@example.com").await;

    // Unknown prefix: no candidate to compare against, so no KDF and no permit.
    // Seeded tokens are hex, so a `z` in the prefix cannot collide with one.
    let unknown_token = format!("zann_sa_zzzz{}", Uuid::now_v7().simple());
    let status = tokio::time::timeout(
        Duration::from_secs(5),
        app.get_status_with_token("/v1/vaults", &unknown_token),
    )
    .await
    .expect("unknown service-account token must not wait on a KDF permit");
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A token whose prefix does exist still has to be verified, which needs a
    // permit. This is what keeps the assertion above from passing vacuously.
    let blocked = tokio::time::timeout(
        Duration::from_secs(1),
        app.get_status_with_token("/v1/vaults", &known_token),
    )
    .await;
    assert!(
        blocked.is_err(),
        "a real service-account token must verify under the KDF semaphore"
    );
}
