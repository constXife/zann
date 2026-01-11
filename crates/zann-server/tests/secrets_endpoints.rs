use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;

mod support;

use tokio::sync::Semaphore;
use zann_core::crypto::SecretKey;
use zann_server::app::{build_router, AppState};
use zann_server::config::{AuthMode, InternalRegistration, ServerConfig};
use zann_server::domains::access_control::policies::{PolicyRule, PolicySet};
use zann_server::domains::access_control::policy_store::PolicyStore;
use zann_server::infra::security_profiles::load_security_profiles;
use zann_server::infra::usage::UsageTracker;
use zann_server::oidc::OidcJwksCache;

struct TestApp {
    app: axum::Router,
}

impl TestApp {
    async fn new_with_smk() -> Self {
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
            db_tx_isolation: zann_server::settings::DbTxIsolation::ReadCommitted,
            started_at: std::time::Instant::now(),
            password_pepper: "pepper".to_string(),
            token_pepper: "pepper".to_string(),
            server_master_key: Some(std::sync::Arc::new(SecretKey::generate())),

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
        Self { app }
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

    async fn create_shared_vault(&self, token: &str, slug: &str) -> serde_json::Value {
        let payload = json!({
            "slug": slug,
            "name": "Shared Vault",
            "kind": "shared",
            "cache_policy": "full",
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
async fn secrets_ensure_get_rotate_roundtrip() {
    let app = TestApp::new_with_smk().await;
    let email = "secrets@example.com";
    let password = "password-1";
    app.register(email, password).await;
    let token = app.login(email, password).await;

    let vault = app.create_shared_vault(&token, "secrets-vault").await;
    let vault_id = vault["id"].as_str().expect("vault id");

    let payload = json!({ "path": "db/password" });
    let (status, ensured) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{}/secrets/ensure", vault_id),
            Some(&token),
            payload,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "ensure failed: {:?}", ensured);
    assert_eq!(ensured["created"], true);
    let first_value = ensured["value"].as_str().expect("value");
    let first_version = ensured["version"].as_i64().expect("version");

    let (status, fetched) = app
        .get_json(
            &format!("/v1/vaults/{}/secrets/db/password", vault_id),
            Some(&token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "get failed: {:?}", fetched);
    assert_eq!(fetched["value"], first_value);

    let payload = json!({ "path": "db/password" });
    let (status, rotated) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{}/secrets/rotate", vault_id),
            Some(&token),
            payload,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "rotate failed: {:?}", rotated);
    assert_eq!(rotated["previous_version"], first_version);
    assert!(rotated["version"].as_i64().unwrap_or(0) > first_version);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn secrets_batch_endpoints() {
    let app = TestApp::new_with_smk().await;
    let email = "secrets-batch@example.com";
    let password = "password-1";
    app.register(email, password).await;
    let token = app.login(email, password).await;

    let vault = app.create_shared_vault(&token, "secrets-batch").await;
    let vault_id = vault["id"].as_str().expect("vault id");

    let payload = json!({
        "secrets": [
            { "path": "one" },
            { "path": "two" }
        ]
    });
    let (status, results) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{}/secrets/batch/ensure", vault_id),
            Some(&token),
            payload,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let results = results.as_array().expect("results array");
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|r| r["status"] == "created"));

    let payload = json!({ "paths": ["one", "two", "missing"] });
    let (status, results) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{}/secrets/batch/get", vault_id),
            Some(&token),
            payload,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let results = results.as_array().expect("results array");
    assert_eq!(results.len(), 3);
    assert!(results.iter().any(|r| r["status"] == "ok"));
    assert!(results.iter().any(|r| r["status"] == "error"));
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn secrets_access_forbidden_for_non_member() {
    let app = TestApp::new_with_smk().await;
    app.register("owner@example.com", "password-1").await;
    let owner_token = app.login("owner@example.com", "password-1").await;
    let vault = app.create_shared_vault(&owner_token, "secrets-guard").await;
    let vault_id = vault["id"].as_str().expect("vault id");

    let payload = json!({ "path": "guarded" });
    let (status, _) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{}/secrets/ensure", vault_id),
            Some(&owner_token),
            payload,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    app.register("intruder@example.com", "password-1").await;
    let intruder_token = app.login("intruder@example.com", "password-1").await;
    let (status, _) = app
        .get_json(
            &format!("/v1/vaults/{}/secrets/guarded", vault_id),
            Some(&intruder_token),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn secrets_reject_invalid_path_and_unknown_policy() {
    let app = TestApp::new_with_smk().await;
    let email = "secrets-invalid@example.com";
    let password = "password-1";
    app.register(email, password).await;
    let token = app.login(email, password).await;

    let vault = app.create_shared_vault(&token, "secrets-invalid").await;
    let vault_id = vault["id"].as_str().expect("vault id");

    let payload = json!({ "path": "   " });
    let (status, error) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{}/secrets/ensure", vault_id),
            Some(&token),
            payload,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["error"], "invalid_path");

    let payload = json!({ "path": "db/password", "policy": "missing" });
    let (status, error) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{}/secrets/ensure", vault_id),
            Some(&token),
            payload,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["error"], "unknown_policy");
}
