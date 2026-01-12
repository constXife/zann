use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use sqlx_core::row::Row;
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use zann_core::crypto::SecretKey;
use zann_core::{CachePolicy, VaultKind};

mod support;

use tokio::sync::Semaphore;
use zann_db::PgPool;
use zann_server::app::{build_router, AppState};
use zann_server::config::{AuthMode, InternalRegistration, ServerConfig};
use zann_server::domains::access_control::policies::{PolicyRule, PolicySet};
use zann_server::domains::access_control::policy_store::PolicyStore;
use zann_server::infra::history::prune_item_history_ttl;
use zann_server::infra::security_profiles::load_security_profiles;
use zann_server::infra::usage::UsageTracker;
use zann_server::oidc::OidcJwksCache;

struct TestApp {
    _guard: support::TestGuard,
    app: axum::Router,
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

    async fn create_item(&self, token: &str, vault_id: &str, password: &str) -> serde_json::Value {
        let payload = json!({
            "path": "login",
            "name": "login",
            "type_id": "login",
            "payload": {
                "v": 1,
                "typeId": "login",
                "fields": {
                    "password": { "kind": "password", "value": password }
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

    async fn update_item(
        &self,
        token: &str,
        vault_id: &str,
        item_id: &str,
        password: &str,
    ) -> serde_json::Value {
        let payload = json!({
            "path": "login",
            "name": "login",
            "type_id": "login",
            "payload": {
                "v": 1,
                "typeId": "login",
                "fields": {
                    "password": { "kind": "password", "value": password }
                }
            }
        });
        let (status, json) = self
            .send_json(
                Method::PUT,
                &format!("/v1/vaults/{}/items/{}", vault_id, item_id),
                Some(token),
                payload,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "update item failed: {:?}", json);
        json
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn history_retains_five_versions_and_skips_metadata_only_changes() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("history_retention@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token, "shared-history").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let item = app.create_item(token, vault_id, "pw-1").await;
    let item_id = item["id"].as_str().expect("item id");

    for idx in 2..=7 {
        app.update_item(token, vault_id, item_id, &format!("pw-{}", idx))
            .await;
    }

    let (status, json) = app
        .get_json(
            &format!("/v1/vaults/{}/items/{}/versions?limit=5", vault_id, item_id),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "history list failed: {:?}", json);
    let versions = json["versions"].as_array().expect("versions");
    assert_eq!(versions.len(), 5, "history should be capped at 5");

    let (status, _) = app
        .send_json(
            Method::PUT,
            &format!("/v1/vaults/{}/items/{}", vault_id, item_id),
            Some(token),
            json!({
                "name": "login-rename"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "rename failed");

    let (status, json) = app
        .get_json(
            &format!("/v1/vaults/{}/items/{}/versions?limit=5", vault_id, item_id),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "history list failed: {:?}", json);
    let versions = json["versions"].as_array().expect("versions");
    assert_eq!(
        versions.len(),
        5,
        "metadata-only updates should not create history"
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn history_restore_replaces_payload_and_prunes_ttl() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("history_restore@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token, "shared-restore").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let item = app.create_item(token, vault_id, "pw-1").await;
    let item_id = item["id"].as_str().expect("item id");

    app.update_item(token, vault_id, item_id, "pw-2").await;
    app.update_item(token, vault_id, item_id, "pw-3").await;

    let (status, json) = app
        .get_json(
            &format!("/v1/vaults/{}/items/{}/versions?limit=5", vault_id, item_id),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "history list failed: {:?}", json);
    let versions = json["versions"].as_array().expect("versions");
    let target = versions
        .first()
        .and_then(|entry| entry.get("version"))
        .and_then(|value| value.as_i64())
        .expect("history version");
    let target_checksum = versions
        .first()
        .and_then(|entry| entry.get("checksum"))
        .and_then(|value| value.as_str())
        .expect("checksum")
        .to_string();

    let (status, json) = app
        .send_json(
            Method::POST,
            &format!(
                "/v1/vaults/{}/items/{}/versions/{}/restore",
                vault_id, item_id, target
            ),
            Some(token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "restore failed: {:?}", json);

    let (status, json) = app
        .get_json(
            &format!("/v1/vaults/{}/items/{}", vault_id, item_id),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "item get failed: {:?}", json);
    assert_eq!(
        json["checksum"].as_str().unwrap_or_default(),
        target_checksum
    );

    let item_uuid = Uuid::parse_str(item_id).expect("item uuid");
    sqlx_core::query::query::<sqlx_postgres::Postgres>(
        r#"
        UPDATE item_history
        SET created_at = NOW() - INTERVAL '10 days'
        WHERE item_id = $1
        "#,
    )
    .bind(item_uuid)
    .execute(&app.pool)
    .await
    .expect("backdate history");

    let deleted = prune_item_history_ttl(&app.pool, 5).await.expect("prune");
    assert!(deleted > 0, "expected ttl prune to delete rows");

    let count = sqlx_core::query::query::<sqlx_postgres::Postgres>(
        "SELECT COUNT(*) as count FROM item_history WHERE item_id = $1",
    )
    .bind(item_uuid)
    .fetch_one(&app.pool)
    .await
    .expect("count history");
    let remaining: i64 = count.try_get("count").expect("count");
    assert_eq!(remaining, 0);
}
