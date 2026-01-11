use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod support;

use chrono::Utc;
use tokio::sync::Semaphore;
use zann_core::{Group, GroupMember};
use zann_db::repo::{GroupMemberRepo, GroupRepo, UserRepo};
use zann_db::PgPool;
use zann_server::app::{build_router, AppState};
use zann_server::config::{AuthMode, InternalRegistration, ServerConfig};
use zann_server::domains::access_control::policies::{PolicyRule, PolicySet};
use zann_server::domains::access_control::policy_store::PolicyStore;
use zann_server::infra::security_profiles::load_security_profiles;
use zann_server::infra::usage::UsageTracker;
use zann_server::oidc::OidcJwksCache;

struct TestApp {
    _guard: support::TestGuard,
    app: axum::Router,
    pool: PgPool,
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
        }
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

    async fn send_empty(&self, method: Method, uri: &str, token: Option<&str>) -> StatusCode {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {}", token));
        }
        let request = builder.body(Body::empty()).expect("request");
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
        let payload = json!({
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

    async fn login(&self, email: &str, password: &str) -> String {
        let payload = json!({
            "email": email,
            "password": password,
            "device_name": "test",
            "device_platform": "tests",
        });
        let (status, json) = self
            .send_json(Method::POST, "/v1/auth/login", None, payload)
            .await;
        assert_eq!(status, StatusCode::OK, "login failed: {:?}", json);
        json["access_token"].as_str().expect("token").to_string()
    }

    async fn add_admin_group(&self, user_id: Uuid) {
        let group_repo = GroupRepo::new(&self.pool);
        let member_repo = GroupMemberRepo::new(&self.pool);
        let now = Utc::now();

        let group = Group {
            id: Uuid::now_v7(),
            slug: "admins".to_string(),
            name: "Admins".to_string(),
            created_at: now,
        };
        let group_id = match group_repo.get_by_slug("admins").await {
            Ok(Some(existing)) => existing.id,
            _ => {
                group_repo.create(&group).await.expect("create group");
                group.id
            }
        };

        let member = GroupMember {
            group_id,
            user_id,
            created_at: now,
        };
        let _ = member_repo.create(&member).await;
    }

    async fn user_id_by_email(&self, email: &str) -> Uuid {
        let repo = UserRepo::new(&self.pool);
        repo.get_by_email(email)
            .await
            .expect("user lookup")
            .expect("user exists")
            .id
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn users_me_update_and_password_change() {
    let app = TestApp::new().await;
    let email = "me-update@example.com";
    let password = "password-1";
    app.register(email, password).await;
    let token = app.login(email, password).await;

    let payload = json!({ "full_name": "Updated Name" });
    let (status, body) = app
        .send_json(Method::PUT, "/v1/users/me", Some(&token), payload)
        .await;
    assert_eq!(status, StatusCode::OK, "update failed: {:?}", body);
    assert_eq!(body["full_name"], "Updated Name");

    let payload = json!({
        "current_password": password,
        "new_password": "password-2",
    });
    let (status, _) = app
        .send_json(Method::POST, "/v1/users/me/password", Some(&token), payload)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let new_token = app.login(email, "password-2").await;
    assert!(!new_token.is_empty());
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn users_me_recovery_kit() {
    let app = TestApp::new().await;
    let email = "recovery@example.com";
    let password = "password-1";
    app.register(email, password).await;
    let token = app.login(email, password).await;

    let (status, body) = app
        .send_json(
            Method::POST,
            "/v1/users/me/recovery-kit",
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "recovery kit failed: {:?}", body);
    assert!(body["recovery_key"].as_str().is_some());
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn admin_user_lifecycle() {
    let app = TestApp::new().await;
    let admin_email = "admin@example.com";
    let admin_password = "password-1";
    app.register(admin_email, admin_password).await;
    let admin_id = app.user_id_by_email(admin_email).await;
    app.add_admin_group(admin_id).await;
    let admin_token = app.login(admin_email, admin_password).await;

    let (status, body) = app.get_json("/v1/users", Some(&admin_token)).await;
    assert_eq!(status, StatusCode::OK, "list users failed: {:?}", body);

    let payload = json!({
        "email": "managed@example.com",
        "password": "password-1",
        "full_name": "Managed User",
    });
    let (status, created) = app
        .send_json(Method::POST, "/v1/users", Some(&admin_token), payload)
        .await;
    assert_eq!(status, StatusCode::OK, "create user failed: {:?}", created);
    let user_id = created["id"].as_str().expect("created id");

    let (status, user) = app
        .get_json(&format!("/v1/users/{}", user_id), Some(&admin_token))
        .await;
    assert_eq!(status, StatusCode::OK, "get user failed: {:?}", user);

    let (status, _user) = app
        .send_json(
            Method::POST,
            &format!("/v1/users/{}/block", user_id),
            Some(&admin_token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, user) = app
        .get_json(&format!("/v1/users/{}", user_id), Some(&admin_token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(user["status"], "blocked");

    let (status, _user) = app
        .send_json(
            Method::POST,
            &format!("/v1/users/{}/unblock", user_id),
            Some(&admin_token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, user) = app
        .get_json(&format!("/v1/users/{}", user_id), Some(&admin_token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(user["status"], "active");

    let payload = json!({ "password": "reset-1" });
    let (status, reset) = app
        .send_json(
            Method::POST,
            &format!("/v1/users/{}/reset-password", user_id),
            Some(&admin_token),
            payload,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "reset password failed: {:?}", reset);
    assert_eq!(reset["password"], "reset-1");

    let status = app
        .send_empty(
            Method::DELETE,
            &format!("/v1/users/{}", user_id),
            Some(&admin_token),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn admin_endpoints_forbidden_for_non_admin() {
    let app = TestApp::new().await;
    let email = "noadmin@example.com";
    let password = "password-1";
    app.register(email, password).await;
    let token = app.login(email, password).await;

    let (status, _) = app.get_json("/v1/users", Some(&token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
