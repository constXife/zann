use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use tracing_subscriber::EnvFilter;
use zann_core::{CachePolicy, VaultKind};
use zann_crypto::crypto::SecretKey;
mod support;

use tokio::sync::Semaphore;
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
    #[allow(dead_code)]
    pool: PgPool,
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
        config.auth.internal.registration = InternalRegistration::Open;

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
            config,
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
            "shared vault create failed: {:?}",
            json
        );
        json
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

    async fn create_personal_vault(&self, token: &str, slug: &str) -> serde_json::Value {
        let (status, json) = self.get_json("/v1/vaults", Some(token)).await;
        assert_eq!(status, StatusCode::OK, "vault list failed: {:?}", json);
        if let Some(vaults) = json.get("vaults").and_then(|v| v.as_array()) {
            if let Some(vault) = vaults.iter().find(|v| {
                v.get("kind")
                    .and_then(|k| k.as_i64())
                    .is_some_and(|k| k == i64::from(VaultKind::Personal.as_i32()))
            }) {
                return vault.clone();
            }
        }

        let payload = json!({
            "slug": slug,
            "name": "Personal Vault",
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
            "personal vault create failed: {:?}",
            json
        );
        json
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_vault_accepts_plaintext_payload() {
    let app = TestApp::new_with_smk().await;
    let user = app.register("shared_plain@example.com", "password").await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token, "shared-vault-1").await;
    let vault_id = vault["id"].as_str().expect("vault id");

    let (status, json) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{}/items", vault_id),
            Some(token),
            json!({
                "path": "test",
                "name": "test",
                "type_id": "kv",
                "payload": {
                    "public": {"user": "test"},
                    "secret": {}
                }
            }),
        )
        .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "create item failed: {:?}",
        json
    );
    assert!(json["id"].as_str().is_some(), "item id missing");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_vault_rejects_plaintext_payload() {
    let app = TestApp::new_with_smk().await;
    let user = app.register("personal_plain@example.com", "password").await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_personal_vault(token, "personal-vault-1").await;
    let vault_id = vault["id"].as_str().expect("vault id");

    let (status, json) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{}/items", vault_id),
            Some(token),
            json!({
                "path": "test",
                "name": "test",
                "type_id": "kv",
                "payload": {
                    "public": {"user": "test"},
                    "secret": {}
                }
            }),
        )
        .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected rejection: {:?}",
        json
    );
    assert_eq!(json["error"], "payload_enc_required");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_vault_accepts_encrypted_payload() {
    let app = TestApp::new_with_smk().await;
    let user = app.register("personal_enc@example.com", "password").await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_personal_vault(token, "personal-vault-2").await;
    let vault_id = vault["id"].as_str().expect("vault id");

    let (status, json) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{}/items", vault_id),
            Some(token),
            json!({
                "path": "test",
                "name": "test",
                "type_id": "kv",
                "payload_enc": [1, 2, 3, 4, 5],
                "checksum": "abc123"
            }),
        )
        .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "create item failed: {:?}",
        json
    );
    assert!(json["id"].as_str().is_some(), "item id missing");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_vault_update_accepts_plaintext() {
    let app = TestApp::new_with_smk().await;
    let user = app.register("shared_update@example.com", "password").await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token, "shared-vault-update").await;
    let vault_id = vault["id"].as_str().expect("vault id");

    let (status, json) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{}/items", vault_id),
            Some(token),
            json!({
                "path": "test",
                "name": "test",
                "type_id": "kv",
                "payload": {
                    "public": {"user": "test"},
                    "secret": {}
                }
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create item failed: {:?}",
        json
    );
    let item_id = json["id"].as_str().expect("item id");

    let (status, json) = app
        .send_json(
            Method::PUT,
            &format!("/v1/vaults/{}/items/{}", vault_id, item_id),
            Some(token),
            json!({
                "payload": {
                    "public": {"user": "updated"},
                    "secret": {"password": "secret123"}
                }
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "update item failed: {:?}", json);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_vault_update_rejects_plaintext() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("personal_update@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app
        .create_personal_vault(token, "personal-vault-update")
        .await;
    let vault_id = vault["id"].as_str().expect("vault id");

    let (status, json) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{}/items", vault_id),
            Some(token),
            json!({
                "path": "test",
                "name": "test",
                "type_id": "kv",
                "payload_enc": [1, 2, 3, 4, 5],
                "checksum": "abc123"
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create item failed: {:?}",
        json
    );
    let item_id = json["id"].as_str().expect("item id");

    let (status, json) = app
        .send_json(
            Method::PUT,
            &format!("/v1/vaults/{}/items/{}", vault_id, item_id),
            Some(token),
            json!({
                "payload": {
                    "public": {"user": "hacked"},
                    "secret": {}
                }
            }),
        )
        .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected rejection: {:?}",
        json
    );
    assert_eq!(json["error"], "plaintext_not_allowed");
}
