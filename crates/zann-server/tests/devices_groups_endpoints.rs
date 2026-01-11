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
            config: config_for_state,
            policy_store: PolicyStore::new(PolicySet::from_rules(rules)),
            usage_tracker,
            security_profiles: load_security_profiles(),
            secret_policies,
            secret_default_policy,
        };

        let app = build_router(state);
        Self { app, pool }
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

    async fn send_empty(&self, method: Method, uri: &str, token: Option<&str>) -> StatusCode {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {}", token));
        }
        let request = builder.body(Body::empty()).expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        response.status()
    }

    async fn register(&self, email: &str, password: &str) {
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
async fn devices_list_current_and_revoke() {
    let app = TestApp::new().await;
    let email = "device@example.com";
    let password = "password-1";
    app.register(email, password).await;
    let token = app.login(email, password).await;

    let (status, list) = app.get_json("/v1/devices", Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "devices list failed: {:?}", list);
    let devices = list["devices"].as_array().expect("devices array");
    assert!(!devices.is_empty());

    let (status, current) = app.get_json("/v1/devices/current", Some(&token)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "current device failed: {:?}",
        current
    );
    let device_id = current["id"].as_str().expect("device id");

    let status = app
        .send_empty(
            Method::DELETE,
            &format!("/v1/devices/{}", device_id),
            Some(&token),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, list) = app.get_json("/v1/devices", Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "devices list failed: {:?}", list);
    let devices = list["devices"].as_array().expect("devices array");
    let revoked = devices
        .iter()
        .find(|device| device["id"] == device_id)
        .and_then(|device| device["revoked_at"].as_str());
    assert!(revoked.is_some());
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn devices_revoke_other_user_is_not_found() {
    let app = TestApp::new().await;
    app.register("device-owner@example.com", "password-1").await;
    let owner_token = app.login("device-owner@example.com", "password-1").await;
    let (status, current) = app
        .get_json("/v1/devices/current", Some(&owner_token))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "current device failed: {:?}",
        current
    );
    let device_id = current["id"].as_str().expect("device id");

    app.register("device-stranger@example.com", "password-1")
        .await;
    let stranger_token = app.login("device-stranger@example.com", "password-1").await;
    let status = app
        .send_empty(
            Method::DELETE,
            &format!("/v1/devices/{}", device_id),
            Some(&stranger_token),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn groups_admin_flow() {
    let app = TestApp::new().await;
    let admin_email = "group-admin@example.com";
    let admin_password = "password-1";
    app.register(admin_email, admin_password).await;
    let admin_id = app.user_id_by_email(admin_email).await;
    app.add_admin_group(admin_id).await;
    let admin_token = app.login(admin_email, admin_password).await;

    let payload = json!({ "slug": "devs", "name": "Developers" });
    let (status, group) = app
        .send_json(Method::POST, "/v1/groups", Some(&admin_token), payload)
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "group create failed: {:?}",
        group
    );

    let (status, list) = app.get_json("/v1/groups", Some(&admin_token)).await;
    assert_eq!(status, StatusCode::OK, "group list failed: {:?}", list);
    let groups = list["groups"].as_array().expect("groups array");
    assert!(groups.iter().any(|g| g["slug"] == "devs"));

    app.register("member@example.com", "password-1").await;
    let member_id = app.user_id_by_email("member@example.com").await;
    let payload = json!({ "user_id": member_id });
    let (status, member) = app
        .send_json(
            Method::POST,
            "/v1/groups/devs/members",
            Some(&admin_token),
            payload,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "add member failed: {:?}",
        member
    );

    let status = app
        .send_empty(
            Method::DELETE,
            &format!("/v1/groups/devs/members/{}", member_id),
            Some(&admin_token),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn groups_require_admin_and_validate_payload() {
    let app = TestApp::new().await;
    app.register("groups-user@example.com", "password-1").await;
    let user_token = app.login("groups-user@example.com", "password-1").await;

    let payload = json!({ "slug": "qa", "name": "QA" });
    let (status, _) = app
        .send_json(Method::POST, "/v1/groups", Some(&user_token), payload)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    app.register("groups-admin@example.com", "password-1").await;
    let admin_id = app.user_id_by_email("groups-admin@example.com").await;
    app.add_admin_group(admin_id).await;
    let admin_token = app.login("groups-admin@example.com", "password-1").await;

    let payload = json!({ "slug": "   ", "name": "Admins" });
    let (status, error) = app
        .send_json(Method::POST, "/v1/groups", Some(&admin_token), payload)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["error"], "invalid_slug");

    let payload = json!({ "slug": "ops", "name": "   " });
    let (status, error) = app
        .send_json(Method::POST, "/v1/groups", Some(&admin_token), payload)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["error"], "invalid_name");

    let payload = json!({ "slug": "ops", "name": "Ops" });
    let (status, _) = app
        .send_json(Method::POST, "/v1/groups", Some(&admin_token), payload)
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let payload = json!({ "slug": "ops", "name": "Ops Again" });
    let (status, error) = app
        .send_json(Method::POST, "/v1/groups", Some(&admin_token), payload)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["error"], "slug_taken");
}
