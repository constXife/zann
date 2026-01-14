use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use sqlx_core::row::Row;
use sqlx_postgres::Postgres;
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod support;

use tokio::sync::Semaphore;
use zann_core::{CachePolicy, VaultKind};
use zann_crypto::crypto::SecretKey;
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
        Self { _guard: guard, app }
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

    async fn create_shared_vault(&self, token: &str, slug: &str) -> serde_json::Value {
        let payload = json!({
            "slug": slug,
            "name": "Shared Vault",
            "kind": VaultKind::Shared.as_i32(),
            "cache_policy": CachePolicy::Full.as_i32(),
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

    async fn create_shared_item(
        &self,
        token: &str,
        vault_id: &str,
        path: &str,
    ) -> serde_json::Value {
        let payload = json!({
            "path": path,
            "name": path,
            "type_id": "login",
            "payload": {
                "v": 1,
                "typeId": "login",
                "fields": {
                    "password": { "kind": "password", "value": "secret" }
                }
            }
        });
        let (status, json) = self
            .send_json(
                Method::POST,
                &format!("/v1/vaults/{}/items", vault_id),
                Some(token),
                payload,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "create item failed: {:?}",
            json
        );
        json
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn system_endpoints_return_expected_shapes() {
    let app = TestApp::new_with_smk().await;

    let (status, info) = app.get_json("/v1/system/info", None).await;
    assert_eq!(status, StatusCode::OK, "system info failed: {:?}", info);
    assert!(info["version"].as_str().is_some());
    assert!(info["server_fingerprint"].as_str().is_some());

    let (status, profiles) = app.get_json("/v1/system/security-profiles", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(profiles["profiles"].is_object());
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_rotation_flow() {
    let app = TestApp::new_with_smk().await;
    app.register("rotate@example.com", "password-1").await;
    let token = app.login("rotate@example.com", "password-1").await;

    let vault = app.create_shared_vault(&token, "rotate-vault").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let item = app
        .create_shared_item(&token, vault_id, "rotation/login")
        .await;
    let item_id = item["id"].as_str().expect("item id");

    let (status, start) = app
        .send_json(
            Method::POST,
            &format!("/v1/shared/items/{}/rotate/start", item_id),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "start failed: {:?}", start);
    assert_eq!(start["state"], "rotating");
    let candidate = start["candidate"].as_str().expect("candidate");

    let (status, status_body) = app
        .get_json(
            &format!("/v1/shared/items/{}/rotate/status", item_id),
            Some(&token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "status failed: {:?}", status_body);
    assert_eq!(status_body["state"], "rotating");

    let (status, candidate_body) = app
        .send_json(
            Method::POST,
            &format!("/v1/shared/items/{}/rotate/candidate", item_id),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "candidate failed: {:?}",
        candidate_body
    );
    assert_eq!(candidate_body["candidate"], candidate);

    let (status, commit) = app
        .send_json(
            Method::POST,
            &format!("/v1/shared/items/{}/rotate/commit", item_id),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "commit failed: {:?}", commit);
    assert_eq!(commit["status"], "committed");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_rotation_rejects_missing_or_duplicate_steps() {
    let app = TestApp::new_with_smk().await;
    app.register("rotate-errors@example.com", "password-1")
        .await;
    let token = app.login("rotate-errors@example.com", "password-1").await;

    let vault = app.create_shared_vault(&token, "rotate-errors").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let item = app
        .create_shared_item(&token, vault_id, "rotation/errors")
        .await;
    let item_id = item["id"].as_str().expect("item id");

    let (status, error) = app
        .send_json(
            Method::POST,
            &format!("/v1/shared/items/{}/rotate/candidate", item_id),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["error"], "rotation_not_active");

    let (status, error) = app
        .send_json(
            Method::POST,
            &format!("/v1/shared/items/{}/rotate/commit", item_id),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["error"], "rotation_missing");

    let (status, _) = app
        .send_json(
            Method::POST,
            &format!("/v1/shared/items/{}/rotate/start", item_id),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, error) = app
        .send_json(
            Method::POST,
            &format!("/v1/shared/items/{}/rotate/start", item_id),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["error"], "rotation_in_progress");

    let (status, _) = app
        .send_json(
            Method::POST,
            &format!("/v1/shared/items/{}/rotate/commit", item_id),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, error) = app
        .send_json(
            Method::POST,
            &format!("/v1/shared/items/{}/rotate/commit", item_id),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["error"], "rotation_missing");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_rotation_commit_rejects_null_payload_enc() {
    let app = TestApp::new_with_smk().await;
    app.register("rotate-null-payload@example.com", "password-1")
        .await;
    let token = app
        .login("rotate-null-payload@example.com", "password-1")
        .await;

    let vault = app.create_shared_vault(&token, "rotate-null-payload").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let item = app
        .create_shared_item(&token, vault_id, "rotation/null-payload")
        .await;
    let item_id = item["id"].as_str().expect("item id");
    let item_uuid = Uuid::parse_str(item_id).expect("item uuid");

    let (status, start) = app
        .send_json(
            Method::POST,
            &format!("/v1/shared/items/{}/rotate/start", item_id),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "start failed: {:?}", start);

    let pool = support::setup_shared_db().await;
    let row = sqlx_core::query::query::<Postgres>("SELECT payload_enc FROM items WHERE id = $1")
        .bind(item_uuid)
        .fetch_one(&pool)
        .await
        .expect("fetch payload");
    let payload_enc: Vec<u8> = row.get("payload_enc");

    sqlx_core::query::query::<Postgres>("ALTER TABLE items ALTER COLUMN payload_enc DROP NOT NULL")
        .execute(&pool)
        .await
        .expect("drop not null");
    sqlx_core::query::query::<Postgres>("UPDATE items SET payload_enc = NULL WHERE id = $1")
        .bind(item_uuid)
        .execute(&pool)
        .await
        .expect("null payload");

    let (status, error) = app
        .send_json(
            Method::POST,
            &format!("/v1/shared/items/{}/rotate/commit", item_id),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error["error"], "db_error");

    sqlx_core::query::query::<Postgres>("UPDATE items SET payload_enc = $2 WHERE id = $1")
        .bind(item_uuid)
        .bind(payload_enc)
        .execute(&pool)
        .await
        .expect("restore payload");
    sqlx_core::query::query::<Postgres>("ALTER TABLE items ALTER COLUMN payload_enc SET NOT NULL")
        .execute(&pool)
        .await
        .expect("restore not null");
}
