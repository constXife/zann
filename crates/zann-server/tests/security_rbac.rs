use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use tower::ServiceExt;
use uuid::Uuid;

use tracing_subscriber::EnvFilter;
mod support;

use tokio::sync::Semaphore;
use zann_db::repo::{UserRepo, VaultMemberRepo};
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
    async fn new(access_ttl_seconds: i64) -> Self {
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
        config.auth.internal.registration = InternalRegistration::Open;

        let usage_tracker = std::sync::Arc::new(UsageTracker::new(pool.clone(), 100));
        let (secret_policies, secret_default_policy) = support::default_secret_policies();
        let state = AppState {
            db: pool.clone(),
            started_at: std::time::Instant::now(),
            password_pepper: "pepper".to_string(),
            token_pepper: "pepper".to_string(),
            server_master_key: None,

            identity_key: support::test_identity_key(),
            access_token_ttl_seconds: access_ttl_seconds,
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
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case("personal"))
            }) {
                return vault.clone();
            }
        }

        let payload = serde_json::json!({
            "slug": slug,
            "name": "Test Vault",
            "kind": "personal",
            "cache_policy": "full",
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
async fn foreign_vault_access_is_forbidden() {
    let app = TestApp::new(3600).await;

    let user_a = app.register("user_a@example.com", "password-1").await;
    let user_b = app.register("user_b@example.com", "password-2").await;
    let token_a = user_a["access_token"].as_str().expect("token");
    let token_b = user_b["access_token"].as_str().expect("token");

    let vault = app.personal_vault(token_a, "vault-a").await;
    let vault_id = vault["id"].as_str().expect("vault id");

    let status = app
        .send_empty(
            Method::GET,
            &format!("/v1/vaults/{}", vault_id),
            Some(token_b),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn readonly_member_cannot_push_sync() {
    let app = TestApp::new(3600).await;

    let user_a = app.register("owner@example.com", "password-1").await;
    let user_b = app.register("readonly@example.com", "password-2").await;
    let token_a = user_a["access_token"].as_str().expect("token");
    let token_b = user_b["access_token"].as_str().expect("token");

    let vault = app.personal_vault(token_a, "vault-ro").await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("uuid");

    let user_repo = UserRepo::new(&app.pool);
    let user_b_row = user_repo
        .get_by_email("readonly@example.com")
        .await
        .expect("user lookup")
        .expect("user");
    let member_repo = VaultMemberRepo::new(&app.pool);
    member_repo
        .create(&zann_core::VaultMember {
            vault_id,
            user_id: user_b_row.id,
            role: zann_core::VaultMemberRole::Readonly,
            created_at: Utc::now(),
        })
        .await
        .expect("member create");

    let payload = serde_json::json!({
        "vault_id": vault_id,
        "changes": [{
            "item_id": Uuid::now_v7(),
            "operation": "upsert",
        }],
    });

    let (status, _) = app
        .send_json(Method::POST, "/v1/sync/push", Some(token_b), payload)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn expired_access_token_is_rejected() {
    let app = TestApp::new(1).await;

    let user = app.register("expired@example.com", "password-1").await;
    let token = user["access_token"].as_str().expect("token");

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let status = app.send_empty(Method::GET, "/v1/vaults", Some(token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
