use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;

mod support;

use tokio::sync::Semaphore;
use zann_core::{CachePolicy, ChangeType, VaultKind};
use zann_core::{Device, Session, User, UserStatus};
use zann_db::repo::{DeviceRepo, SessionRepo, UserRepo};
use zann_db::PgPool;
use zann_server::app::{build_router, AppState};
use zann_server::config::{AuthMode, InternalRegistration, ServerConfig, DEFAULT_MAX_BODY_BYTES};
use zann_server::domains::access_control::policies::{PolicyRule, PolicySet};
use zann_server::domains::access_control::policy_store::PolicyStore;
use zann_server::infra::security_profiles::load_security_profiles;
use zann_server::infra::usage::UsageTracker;
use zann_server::oidc::OidcJwksCache;
use zann_server::tokens::hash_token;

struct TestApp {
    _guard: support::TestGuard,
    app: axum::Router,
    pool: PgPool,
    config: ServerConfig,
}

impl TestApp {
    async fn new() -> Self {
        Self::new_with_auth(AuthMode::Internal, true).await
    }

    async fn new_with_auth(mode: AuthMode, internal_enabled: bool) -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new("zann_server=debug"))
                .with_test_writer()
                .try_init();
        });

        let guard = support::test_guard().await;

        let pool = support::setup_shared_db().await;
        support::reset_db(&pool).await;
        let rules: Vec<PolicyRule> = support::load_policy_rules();

        let mut config = ServerConfig::default();

        support::tune_test_kdf(&mut config);
        config.auth.mode = mode;
        config.auth.internal.enabled = internal_enabled;
        config.auth.internal.registration = InternalRegistration::Open;
        let config_for_state = config.clone();

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
            config,
        }
    }

    fn config(&self) -> &ServerConfig {
        &self.config
    }

    async fn send_json(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {}", token));
        }
        let request = builder
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

    async fn send_json_status(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: serde_json::Value,
    ) -> StatusCode {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {}", token));
        }
        let request = builder
            .body(Body::from(serde_json::to_vec(&body).expect("encode json")))
            .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        response.status()
    }

    async fn get_json(&self, uri: &str, token: Option<&str>) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().method(Method::GET).uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {}", token));
        }
        let request = builder.body(Body::empty()).expect("request");
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

    async fn register(&self, email: &str, password: &str) -> serde_json::Value {
        let payload = serde_json::json!({
            "email": email,
            "password": password,
            "device_name": "test",
            "device_platform": "tests",
        });
        let (status, json) = self
            .send_json(Method::POST, "/v1/auth/register", None, payload)
            .await;
        assert_eq!(status, StatusCode::CREATED, "register failed: {:?}", json);
        json
    }

    async fn personal_vault(&self, token: &str, slug: &str) -> serde_json::Value {
        let (status, json) = self.get_json("/v1/vaults", Some(token)).await;
        assert_eq!(status, StatusCode::OK, "vault list failed: {:?}", json);
        if let Some(vaults) = json.get("vaults").and_then(|value| value.as_array()) {
            if let Some(vault) = vaults.iter().find(|vault| {
                vault
                    .get("kind")
                    .and_then(|value| value.as_i64())
                    .is_some_and(|value| value == i64::from(VaultKind::Personal.as_i32()))
            }) {
                return vault.clone();
            }
        }

        let payload = serde_json::json!({
            "slug": slug,
            "name": "Test Vault",
            "kind": VaultKind::Personal.as_i32(),
            "cache_policy": CachePolicy::Full.as_i32(),
            "vault_key_enc": [1, 2, 3],
        });
        let (status, json) = self
            .send_json(Method::POST, "/v1/vaults", Some(token), payload)
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "vault create failed: {:?}",
            json
        );
        json
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn payload_too_large_is_rejected() {
    let app = TestApp::new().await;

    let user = app.register("dos@example.com", "password-1").await;
    let token = user["access_token"].as_str().expect("token");
    let vault = app.personal_vault(token, "vault-dos").await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("uuid");
    let payload_enc = vec![7u8; DEFAULT_MAX_BODY_BYTES + 1];
    let payload = serde_json::json!({
        "vault_id": vault_id,
        "changes": [{
            "item_id": Uuid::now_v7(),
            "operation": ChangeType::Create.as_i32(),
            "payload_enc": payload_enc,
            "checksum": "checksum",
            "path": "dos/path",
            "name": "DOS",
            "type_id": "login"
        }]
    });

    let status = app
        .send_json_status(Method::POST, "/v1/sync/push", Some(token), payload)
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn invalid_item_is_rejected() {
    let app = TestApp::new().await;

    let user = app.register("invalid@example.com", "password-1").await;
    let token = user["access_token"].as_str().expect("token");
    let vault = app.personal_vault(token, "vault-invalid").await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("uuid");
    let payload = serde_json::json!({
        "vault_id": vault_id,
        "changes": [{
            "item_id": Uuid::now_v7(),
            "operation": ChangeType::Create.as_i32(),
            "payload_enc": [1, 2, 3],
            "checksum": "checksum",
            "path": "",
            "name": "Invalid",
            "type_id": "login"
        }]
    });

    let (status, _) = app
        .send_json(Method::POST, "/v1/sync/push", Some(token), payload)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn revoked_refresh_token_is_rejected() {
    let app = TestApp::new().await;

    let user = app.register("logout@example.com", "password-1").await;
    let refresh = user["refresh_token"].as_str().expect("refresh token");

    let logout_payload = serde_json::json!({
        "refresh_token": refresh,
    });
    let (status, _) = app
        .send_json(Method::POST, "/v1/auth/logout", None, logout_payload)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let refresh_payload = serde_json::json!({
        "refresh_token": refresh,
    });
    let (status, _) = app
        .send_json(Method::POST, "/v1/auth/refresh", None, refresh_payload)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn oidc_mode_accepts_session_tokens() {
    let app = TestApp::new_with_auth(AuthMode::Oidc, false).await;
    let now = chrono::Utc::now();

    let user = User {
        id: Uuid::now_v7(),
        email: "oidc-session@example.com".to_string(),
        full_name: None,
        password_hash: None,
        kdf_salt: "salt".to_string(),
        kdf_algorithm: app.config().auth.kdf.algorithm.clone(),
        kdf_iterations: i64::from(app.config().auth.kdf.iterations),
        kdf_memory_kb: i64::from(app.config().auth.kdf.memory_kb),
        kdf_parallelism: i64::from(app.config().auth.kdf.parallelism),
        recovery_key_hash: None,
        status: UserStatus::Active,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        row_version: 1,
        created_at: now,
        updated_at: now,
        last_login_at: None,
    };

    let user_repo = UserRepo::new(&app.pool);
    user_repo.create(&user).await.expect("create user");

    let device = Device {
        id: Uuid::now_v7(),
        user_id: user.id,
        name: "oidc-device".to_string(),
        fingerprint: "fingerprint".to_string(),
        os: None,
        os_version: None,
        app_version: None,
        last_seen_at: None,
        last_ip: None,
        revoked_at: None,
        created_at: now,
    };
    let device_repo = DeviceRepo::new(&app.pool);
    device_repo.create(&device).await.expect("create device");

    let access_token = "access-token";
    let refresh_token = "refresh-token";
    let session = Session {
        id: Uuid::now_v7(),
        user_id: user.id,
        device_id: device.id,
        access_token_hash: hash_token(access_token, "pepper"),
        access_expires_at: now + chrono::Duration::seconds(3600),
        refresh_token_hash: hash_token(refresh_token, "pepper"),
        expires_at: now + chrono::Duration::seconds(3600),
        created_at: now,
    };
    let session_repo = SessionRepo::new(&app.pool);
    session_repo.create(&session).await.expect("create session");

    let (status, json) = app.get_json("/v1/users/me", Some(access_token)).await;
    assert_eq!(status, StatusCode::OK, "expected ok: {:?}", json);
    assert_eq!(json["email"], user.email);
}
