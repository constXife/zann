use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod support;

use tokio::sync::Semaphore;
use zann_core::crypto::SecretKey;
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
        config.server.max_body_bytes = 12 * 1024 * 1024;

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

    async fn send_bytes(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        bytes: Vec<u8>,
    ) -> (StatusCode, Vec<u8>) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/octet-stream");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {}", token));
        }
        let request = builder.body(Body::from(bytes)).expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (status, bytes.to_vec())
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

    async fn get_bytes(&self, uri: &str, token: Option<&str>) -> (StatusCode, Vec<u8>) {
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
        (status, bytes.to_vec())
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
            "kind": "shared",
            "cache_policy": "full",
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

    async fn create_personal_vault(&self, token: &str, slug: &str) -> serde_json::Value {
        let (status, json) = self.get_json("/v1/vaults", Some(token)).await;
        assert_eq!(status, StatusCode::OK, "vault list failed: {:?}", json);
        if let Some(vaults) = json.get("vaults").and_then(|v| v.as_array()) {
            if let Some(vault) = vaults.iter().find(|v| {
                v.get("kind")
                    .and_then(|k| k.as_str())
                    .is_some_and(|k| k.eq_ignore_ascii_case("personal"))
            }) {
                return vault.clone();
            }
        }

        let payload = json!({
            "slug": slug,
            "name": "Personal Vault",
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
            "personal vault create failed: {:?}",
            json
        );
        json
    }

    async fn create_shared_file_item(
        &self,
        token: &str,
        vault_id: &str,
        file_id: &str,
    ) -> serde_json::Value {
        let payload = json!({
            "v": 1,
            "typeId": "file_secret",
            "fields": {},
            "extra": {
                "file_id": file_id,
                "upload_state": "pending",
                "filename": "secret.bin",
                "mime": "application/octet-stream"
            }
        });
        let (status, json) = self
            .send_json(
                Method::POST,
                &format!("/v1/vaults/{}/items", vault_id),
                Some(token),
                json!({
                    "path": "infra/file-secret",
                    "name": "File Secret",
                    "type_id": "file_secret",
                    "payload": payload
                }),
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

    async fn create_personal_file_item(&self, token: &str, vault_id: &str) -> serde_json::Value {
        let (status, json) = self
            .send_json(
                Method::POST,
                &format!("/v1/vaults/{}/items", vault_id),
                Some(token),
                json!({
                    "path": "infra/file-secret",
                    "name": "File Secret",
                    "type_id": "file_secret",
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
        json
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_file_upload_and_download_plain() {
    let app = TestApp::new_with_smk().await;
    let user = app.register("shared_files@example.com", "password").await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token, "shared-file-vault").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let file_id = Uuid::now_v7().to_string();
    let item = app.create_shared_file_item(token, vault_id, &file_id).await;
    let item_id = item["id"].as_str().expect("item id");

    let bytes = b"hello-file".to_vec();
    let (status, response_bytes) = app
        .send_bytes(
            Method::POST,
            &format!(
                "/v1/vaults/{}/items/{}/file?representation=plain&file_id={}",
                vault_id, item_id, file_id
            ),
            Some(token),
            bytes.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "upload failed");
    let response_json: serde_json::Value =
        serde_json::from_slice(&response_bytes).expect("upload json");
    assert_eq!(response_json["file_id"], file_id);
    assert_eq!(response_json["upload_state"], "ready");

    let (status, downloaded) = app
        .get_bytes(
            &format!(
                "/v1/vaults/{}/items/{}/file?representation=plain",
                vault_id, item_id
            ),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "download failed");
    assert_eq!(downloaded, bytes);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_file_upload_and_download_opaque() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("shared_files_opaque@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app
        .create_shared_vault(token, "shared-file-opaque-vault")
        .await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let file_id = Uuid::now_v7().to_string();
    let item = app.create_shared_file_item(token, vault_id, &file_id).await;
    let item_id = item["id"].as_str().expect("item id");

    let bytes = b"opaque-shared".to_vec();
    let (status, response_bytes) = app
        .send_bytes(
            Method::POST,
            &format!(
                "/v1/vaults/{}/items/{}/file?representation=opaque&file_id={}",
                vault_id, item_id, file_id
            ),
            Some(token),
            bytes.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "upload failed");
    let response_json: serde_json::Value =
        serde_json::from_slice(&response_bytes).expect("upload json");
    assert_eq!(response_json["file_id"], file_id);
    assert_eq!(response_json["upload_state"], "ready");

    let (status, downloaded) = app
        .get_bytes(
            &format!(
                "/v1/vaults/{}/items/{}/file?representation=opaque",
                vault_id, item_id
            ),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "download failed");
    assert_eq!(downloaded, bytes);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_plain_download_rejects_opaque_storage() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("shared_files_plain_reject@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app
        .create_shared_vault(token, "shared-file-plain-reject-vault")
        .await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let file_id = Uuid::now_v7().to_string();
    let item = app.create_shared_file_item(token, vault_id, &file_id).await;
    let item_id = item["id"].as_str().expect("item id");

    let bytes = b"opaque-shared".to_vec();
    let (status, _) = app
        .send_bytes(
            Method::POST,
            &format!(
                "/v1/vaults/{}/items/{}/file?representation=opaque&file_id={}",
                vault_id, item_id, file_id
            ),
            Some(token),
            bytes,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "upload failed");

    let (status, response) = app
        .get_bytes(
            &format!(
                "/v1/vaults/{}/items/{}/file?representation=plain",
                vault_id, item_id
            ),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "expected conflict");
    let response_json: serde_json::Value = serde_json::from_slice(&response).expect("error json");
    assert_eq!(response_json["error"], "representation_not_available");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_opaque_download_returns_ciphertext_for_plain_storage() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("shared_files_opaque_from_plain@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app
        .create_shared_vault(token, "shared-file-opaque-from-plain-vault")
        .await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let file_id = Uuid::now_v7().to_string();
    let item = app.create_shared_file_item(token, vault_id, &file_id).await;
    let item_id = item["id"].as_str().expect("item id");

    let bytes = b"plain-storage".to_vec();
    let (status, _) = app
        .send_bytes(
            Method::POST,
            &format!(
                "/v1/vaults/{}/items/{}/file?representation=plain&file_id={}",
                vault_id, item_id, file_id
            ),
            Some(token),
            bytes.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "upload failed");

    let (status, downloaded) = app
        .get_bytes(
            &format!(
                "/v1/vaults/{}/items/{}/file?representation=opaque",
                vault_id, item_id
            ),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "download failed");
    assert_ne!(downloaded, bytes);
    assert!(!downloaded.is_empty(), "ciphertext should not be empty");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_file_upload_and_download_opaque() {
    let app = TestApp::new_with_smk().await;
    let user = app.register("personal_files@example.com", "password").await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app
        .create_personal_vault(token, "personal-file-vault")
        .await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let file_id = Uuid::now_v7().to_string();
    let item = app.create_personal_file_item(token, vault_id).await;
    let item_id = item["id"].as_str().expect("item id");

    let bytes = b"opaque-bytes".to_vec();
    let (status, response_bytes) = app
        .send_bytes(
            Method::POST,
            &format!(
                "/v1/vaults/{}/items/{}/file?representation=opaque&file_id={}",
                vault_id, item_id, file_id
            ),
            Some(token),
            bytes.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "upload failed");
    let response_json: serde_json::Value =
        serde_json::from_slice(&response_bytes).expect("upload json");
    assert_eq!(response_json["file_id"], file_id);
    assert_eq!(response_json["upload_state"], "ready");

    let (status, downloaded) = app
        .get_bytes(
            &format!(
                "/v1/vaults/{}/items/{}/file?representation=opaque",
                vault_id, item_id
            ),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "download failed");
    assert_eq!(downloaded, bytes);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_plain_download_forbidden() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("personal_plain_files@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app
        .create_personal_vault(token, "personal-plain-file-vault")
        .await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let file_id = Uuid::now_v7().to_string();
    let item = app.create_personal_file_item(token, vault_id).await;
    let item_id = item["id"].as_str().expect("item id");

    let bytes = b"opaque-bytes".to_vec();
    let (status, _) = app
        .send_bytes(
            Method::POST,
            &format!(
                "/v1/vaults/{}/items/{}/file?representation=opaque&file_id={}",
                vault_id, item_id, file_id
            ),
            Some(token),
            bytes,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "upload failed");

    let (status, response) = app
        .get_bytes(
            &format!(
                "/v1/vaults/{}/items/{}/file?representation=plain",
                vault_id, item_id
            ),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "expected forbidden");
    let response_json: serde_json::Value = serde_json::from_slice(&response).expect("error json");
    assert_eq!(response_json["error"], "representation_not_allowed");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn file_upload_rejects_large_payload() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("shared_large_files@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app
        .create_shared_vault(token, "shared-large-file-vault")
        .await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let file_id = Uuid::now_v7().to_string();
    let item = app.create_shared_file_item(token, vault_id, &file_id).await;
    let item_id = item["id"].as_str().expect("item id");

    let bytes = vec![0u8; 10 * 1024 * 1024 + 1];
    let (status, response_bytes) = app
        .send_bytes(
            Method::POST,
            &format!(
                "/v1/vaults/{}/items/{}/file?representation=plain&file_id={}",
                vault_id, item_id, file_id
            ),
            Some(token),
            bytes,
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let response_json: serde_json::Value =
        serde_json::from_slice(&response_bytes).expect("error json");
    assert_eq!(response_json["error"], "file_too_large");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn file_upload_is_idempotent_by_file_id() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("shared_idempotent_files@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app
        .create_shared_vault(token, "shared-idempotent-file-vault")
        .await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let file_id = Uuid::now_v7().to_string();
    let item = app.create_shared_file_item(token, vault_id, &file_id).await;
    let item_id = item["id"].as_str().expect("item id");

    let bytes = b"idempotent-file".to_vec();
    for _ in 0..2 {
        let (status, response_bytes) = app
            .send_bytes(
                Method::POST,
                &format!(
                    "/v1/vaults/{}/items/{}/file?representation=plain&file_id={}",
                    vault_id, item_id, file_id
                ),
                Some(token),
                bytes.clone(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "upload failed");
        let response_json: serde_json::Value =
            serde_json::from_slice(&response_bytes).expect("upload json");
        assert_eq!(response_json["file_id"], file_id);
        assert_eq!(response_json["upload_state"], "ready");
    }
}
