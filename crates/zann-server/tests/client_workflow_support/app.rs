#![allow(dead_code)]

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use serde_json::json;
use tokio::sync::Semaphore;
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use zann_core::crypto::SecretKey;
use zann_core::{VaultMember, VaultMemberRole};
use zann_server::app::{build_router, AppState};
use zann_server::config::{AuthMode, InternalRegistration, ServerConfig};
use zann_server::domains::access_control::policies::{PolicyRule, PolicySet};
use zann_server::domains::access_control::policy_store::PolicyStore;
use zann_server::infra::security_profiles::load_security_profiles;
use zann_server::infra::usage::UsageTracker;
use zann_server::oidc::OidcJwksCache;

use crate::support;

pub struct TestApp {
    _guard: support::TestGuard,
    pub(super) app: axum::Router,
    pub(super) pool: zann_db::PgPool,
}

impl TestApp {
    pub async fn new_with_smk() -> Self {
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
        Self { _guard: guard, app, pool }
    }

    pub async fn send_json(
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

    pub async fn register(&self, email: &str, password: &str) -> serde_json::Value {
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

    pub async fn update_vault_key(&self, token: &str, vault_id: Uuid, vault_key_enc: Vec<u8>) {
        let payload = json!({ "vault_key_enc": vault_key_enc });
        let (status, json) = self
            .send_json(
                Method::PUT,
                &format!("/v1/vaults/{}/key", vault_id),
                Some(token),
                payload,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "update vault key failed: {:?}",
            json
        );
    }

    pub async fn create_shared_vault(&self, token: &str, slug: &str) -> serde_json::Value {
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

    pub async fn create_shared_item(
        &self,
        token: &str,
        vault_id: &str,
        path: &str,
        type_id: &str,
        payload: serde_json::Value,
    ) {
        let body = json!({
            "path": path,
            "type_id": type_id,
            "payload": payload,
        });
        let (status, json) = self
            .send_json(
                Method::POST,
                &format!("/v1/vaults/{}/items", vault_id),
                Some(token),
                body,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "shared item create failed: {:?}",
            json
        );
    }

    pub async fn personal_vault_id(&self, email: &str) -> Uuid {
        let user_repo = zann_db::repo::UserRepo::new(&self.pool);
        let user = user_repo
            .get_by_email(email)
            .await
            .expect("user lookup")
            .expect("user exists");
        let vault_repo = zann_db::repo::VaultRepo::new(&self.pool);
        let vault = vault_repo
            .get_personal_by_user(user.id)
            .await
            .expect("personal vault")
            .expect("personal vault exists");
        vault.id
    }

    pub async fn item_payload_enc(&self, item_id: Uuid) -> Vec<u8> {
        let repo = zann_db::repo::ItemRepo::new(&self.pool);
        let item = repo
            .get_by_id(item_id)
            .await
            .expect("item lookup")
            .expect("item exists");
        item.payload_enc
    }

    pub async fn last_seq_for_vault(&self, vault_id: Uuid) -> i64 {
        let repo = zann_db::repo::ChangeRepo::new(&self.pool);
        repo.last_seq_for_vault(vault_id).await.expect("last seq")
    }

    pub async fn add_vault_member(&self, vault_id: Uuid, email: &str, role: VaultMemberRole) {
        let user_repo = zann_db::repo::UserRepo::new(&self.pool);
        let user = user_repo
            .get_by_email(email)
            .await
            .expect("user lookup")
            .expect("user exists");
        let repo = zann_db::repo::VaultMemberRepo::new(&self.pool);
        if repo
            .get(vault_id, user.id)
            .await
            .expect("member lookup")
            .is_some()
        {
            return;
        }
        let member = VaultMember {
            vault_id,
            user_id: user.id,
            role,
            created_at: Utc::now(),
        };
        repo.create(&member).await.expect("member create");
    }
}
