use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;

mod support;

use tokio::sync::Semaphore;
use zann_core::{CachePolicy, ChangeType, VaultKind};
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
    async fn new() -> Self {
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
            server_master_key: None,

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
        Self { _guard: guard, app }
    }

    async fn send_json(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        send_json_with_app(
            self.app.clone(),
            method,
            uri.to_string(),
            token.map(str::to_string),
            body,
        )
        .await
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

async fn send_json_with_app(
    app: axum::Router,
    method: Method,
    uri: String,
    token: Option<String>,
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
    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            serde_json::Value::String(String::from_utf8_lossy(&bytes).to_string())
        })
    };
    (status, json)
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn sync_push_is_atomic_on_error() {
    let app = TestApp::new().await;

    let user = app.register("atomic@example.com", "password-1").await;
    let token = user["access_token"].as_str().expect("token");
    let vault = app.personal_vault(token, "vault-atomic").await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("uuid");
    let payload = serde_json::json!({
        "vault_id": vault_id,
        "changes": [
            {
                "item_id": Uuid::now_v7(),
                "operation": ChangeType::Create.as_i32(),
                "payload_enc": [1, 2, 3],
                "checksum": "checksum-1",
                "path": "dup/path",
                "name": "Item A",
                "type_id": "login"
            },
            {
                "item_id": Uuid::now_v7(),
                "operation": ChangeType::Create.as_i32(),
                "payload_enc": [4, 5, 6],
                "path": "dup/path",
                "name": "Item B",
                "type_id": "login"
            }
        ]
    });

    let (status, _) = app
        .send_json(Method::POST, "/v1/sync/push", Some(token), payload)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = app
        .get_json(&format!("/v1/vaults/{}/items", vault_id), Some(token))
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 0);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn sync_push_conflict_is_atomic() {
    let app = TestApp::new().await;

    let user = app
        .register("conflict-batch@example.com", "password-1")
        .await;
    let token = user["access_token"].as_str().expect("token");
    let vault = app.personal_vault(token, "vault-conflict").await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("uuid");

    let payload = serde_json::json!({
        "vault_id": vault_id,
        "changes": [
            {
                "item_id": Uuid::now_v7(),
                "operation": ChangeType::Create.as_i32(),
                "payload_enc": [1, 2, 3],
                "checksum": "checksum-1",
                "path": "dup/path",
                "type_id": "login"
            },
            {
                "item_id": Uuid::now_v7(),
                "operation": ChangeType::Create.as_i32(),
                "payload_enc": [4, 5, 6],
                "checksum": "checksum-2",
                "path": "dup/path",
                "type_id": "login"
            }
        ]
    });

    let (status, body) = app
        .send_json(Method::POST, "/v1/sync/push", Some(token), payload)
        .await;
    assert_eq!(status, StatusCode::OK, "sync push failed: {:?}", body);
    assert_eq!(body["applied"].as_array().map(|v| v.len()), Some(0));
    assert_eq!(body["applied_changes"].as_array().map(|v| v.len()), Some(0));
    assert_eq!(body["conflicts"].as_array().map(|v| v.len()), Some(1));

    let (status, body) = app
        .get_json(&format!("/v1/vaults/{}/items", vault_id), Some(token))
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 0);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn concurrent_updates_resolve_with_single_conflict() {
    let app = TestApp::new().await;

    let user = app.register("race@example.com", "password-1").await;
    let token = user["access_token"].as_str().expect("token");
    let vault = app.personal_vault(token, "vault-race").await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("uuid");
    let item_id = Uuid::now_v7();

    let create_payload = serde_json::json!({
        "vault_id": vault_id,
        "changes": [{
            "item_id": item_id,
            "operation": ChangeType::Create.as_i32(),
            "payload_enc": [9, 9, 9],
            "checksum": "checksum-create",
            "path": "race/path",
            "name": "Race Item",
            "type_id": "login"
        }]
    });
    let (status, create_response) = app
        .send_json(Method::POST, "/v1/sync/push", Some(token), create_payload)
        .await;
    assert_eq!(status, StatusCode::OK);
    let base_seq = create_response["applied_changes"][0]["seq"]
        .as_i64()
        .expect("create seq");

    let warmup_payload = serde_json::json!({
        "vault_id": vault_id,
        "changes": [{
            "item_id": item_id,
            "operation": ChangeType::Update.as_i32(),
            "payload_enc": [8],
            "checksum": "checksum-warmup",
            "base_seq": base_seq
        }]
    });
    let (status, warmup_response) = app
        .send_json(Method::POST, "/v1/sync/push", Some(token), warmup_payload)
        .await;
    assert_eq!(status, StatusCode::OK);
    let current_seq = warmup_response["applied_changes"][0]["seq"]
        .as_i64()
        .expect("warmup seq");

    let payload_one = serde_json::json!({
        "vault_id": vault_id,
        "changes": [{
            "item_id": item_id,
            "operation": ChangeType::Update.as_i32(),
            "payload_enc": [1],
            "checksum": "checksum-one",
            "base_seq": current_seq
        }]
    });
    let payload_two = serde_json::json!({
        "vault_id": vault_id,
        "changes": [{
            "item_id": item_id,
            "operation": ChangeType::Update.as_i32(),
            "payload_enc": [2],
            "checksum": "checksum-two",
            "base_seq": base_seq
        }]
    });

    let app_one = app.app.clone();
    let app_two = app.app.clone();
    let token_one = token.to_string();
    let token_two = token.to_string();

    let task_one = tokio::spawn(async move {
        send_json_with_app(
            app_one,
            Method::POST,
            "/v1/sync/push".to_string(),
            Some(token_one),
            payload_one,
        )
        .await
    });
    let task_two = tokio::spawn(async move {
        send_json_with_app(
            app_two,
            Method::POST,
            "/v1/sync/push".to_string(),
            Some(token_two),
            payload_two,
        )
        .await
    });

    let (status_one, json_one) = task_one.await.expect("task one");
    let (status_two, json_two) = task_two.await.expect("task two");
    assert_eq!(status_one, StatusCode::OK);
    assert_eq!(status_two, StatusCode::OK);

    let conflicts_one = json_one["conflicts"]
        .as_array()
        .map(|c| c.len())
        .unwrap_or(0);
    let conflicts_two = json_two["conflicts"]
        .as_array()
        .map(|c| c.len())
        .unwrap_or(0);
    assert_eq!(conflicts_one + conflicts_two, 1);
}

#[tokio::test]
async fn push_cannot_touch_items_from_another_vault() {
    let app = TestApp::new().await;

    let victim = app.register("victim@example.com", "password-1").await;
    let victim_token = victim["access_token"].as_str().expect("token");
    let victim_vault = app.personal_vault(victim_token, "vault-victim").await;
    let victim_vault_id =
        Uuid::parse_str(victim_vault["id"].as_str().expect("vault id")).expect("uuid");
    let item_id = Uuid::now_v7();

    let (status, created) = app
        .send_json(
            Method::POST,
            "/v1/sync/push",
            Some(victim_token),
            serde_json::json!({
                "vault_id": victim_vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Create.as_i32(),
                    "payload_enc": [1, 2, 3],
                    "checksum": "checksum-victim",
                    // Basename matches the name so path normalization is a no-op
                    // and the assertions below stay about the attacker, not it.
                    "path": "victim/secret",
                    "name": "secret",
                    "type_id": "login"
                }]
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "victim create failed: {created:?}");

    // A separate account that only knows the victim's item id.
    let attacker = app.register("attacker@example.com", "password-2").await;
    let attacker_token = attacker["access_token"].as_str().expect("token");
    let attacker_vault = app.personal_vault(attacker_token, "vault-attacker").await;
    let attacker_vault_id =
        Uuid::parse_str(attacker_vault["id"].as_str().expect("vault id")).expect("uuid");

    for operation in [ChangeType::Update, ChangeType::Delete, ChangeType::Restore] {
        let (status, response) = app
            .send_json(
                Method::POST,
                "/v1/sync/push",
                Some(attacker_token),
                serde_json::json!({
                    "vault_id": attacker_vault_id,
                    "changes": [{
                        "item_id": item_id,
                        "operation": operation.as_i32(),
                        "payload_enc": [6, 6, 6],
                        "checksum": "checksum-attacker",
                        "path": "attacker/pwned",
                        "name": "Pwned"
                    }]
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{operation:?}: {response:?}");
        assert_eq!(
            response["applied_changes"]
                .as_array()
                .map_or(0, |list| list.len()),
            0,
            "{operation:?} must not apply across vaults: {response:?}"
        );
        assert_eq!(
            response["conflicts"][0]["reason"].as_str(),
            Some("missing_item"),
            "{operation:?} must not reveal the foreign item: {response:?}"
        );
    }

    // Reusing the id via Create must conflict instead of hitting the primary key.
    let (status, response) = app
        .send_json(
            Method::POST,
            "/v1/sync/push",
            Some(attacker_token),
            serde_json::json!({
                "vault_id": attacker_vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Create.as_i32(),
                    "payload_enc": [6, 6, 6],
                    "checksum": "checksum-attacker",
                    "path": "attacker/pwned",
                    "name": "Pwned",
                    "type_id": "login"
                }]
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "cross-vault create: {response:?}");
    assert_eq!(
        response["applied_changes"]
            .as_array()
            .map_or(0, |list| list.len()),
        0,
        "cross-vault create must not apply: {response:?}"
    );

    // The victim's item is untouched: still active, still their payload.
    let (status, pull) = app
        .send_json(
            Method::POST,
            "/v1/sync/pull",
            Some(victim_token),
            serde_json::json!({ "vault_id": victim_vault_id }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "victim pull failed: {pull:?}");
    let changes = pull["changes"].as_array().expect("changes");
    let change = changes
        .iter()
        .find(|change| change["item_id"].as_str() == Some(&item_id.to_string()))
        .unwrap_or_else(|| panic!("victim item vanished: {pull:?}"));
    assert_eq!(
        change["checksum"].as_str(),
        Some("checksum-victim"),
        "victim payload was overwritten: {change:?}"
    );
    assert_eq!(
        change["path"].as_str(),
        Some("victim/secret"),
        "victim path was overwritten: {change:?}"
    );
    assert_ne!(
        change["operation"].as_i64(),
        Some(i64::from(ChangeType::Delete.as_i32())),
        "victim item was tombstoned: {change:?}"
    );
}
