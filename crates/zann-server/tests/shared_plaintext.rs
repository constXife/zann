use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;
use zann_core::crypto::SecretKey;
use zann_core::{CachePolicy, VaultKind};

mod support;

use tokio::sync::Semaphore;
use zann_core::{Device, ServiceAccount, Session, User, UserStatus};
use zann_db::repo::{DeviceRepo, ServiceAccountRepo, SessionRepo, UserRepo};
use zann_db::PgPool;
use zann_server::app::{build_router, AppState};
use zann_server::config::{AuthMode, InternalRegistration, ServerConfig};
use zann_server::domains::access_control::policies::{PolicyRule, PolicySet};
use zann_server::domains::access_control::policy_store::PolicyStore;
use zann_server::infra::security_profiles::load_security_profiles;
use zann_server::infra::usage::UsageTracker;
use zann_server::oidc::OidcJwksCache;
use zann_server::passwords::{self, KdfParams};
use zann_server::tokens::hash_token;

struct TestApp {
    _guard: support::TestGuard,
    app: axum::Router,
    pool: PgPool,
    token_pepper: String,
    kdf_params: KdfParams,
    config: ServerConfig,
}

impl TestApp {
    async fn new_with_smk() -> Self {
        Self::new_with_auth(AuthMode::Internal, true).await
    }

    async fn new_with_auth(mode: AuthMode, internal_enabled: bool) -> Self {
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
        config.auth.mode = mode;
        config.auth.internal.enabled = internal_enabled;
        config.auth.internal.registration = InternalRegistration::Open;
        let config_for_state = config.clone();

        let usage_tracker = std::sync::Arc::new(UsageTracker::new(pool.clone(), 100));
        let (secret_policies, secret_default_policy) = support::default_secret_policies();
        let token_pepper = "pepper".to_string();
        let kdf_params = KdfParams {
            algorithm: config.auth.kdf.algorithm.clone(),
            iterations: config.auth.kdf.iterations,
            memory_kb: config.auth.kdf.memory_kb,
            parallelism: config.auth.kdf.parallelism,
        };
        let state = AppState {
            db: pool.clone(),
            db_tx_isolation: zann_server::settings::DbTxIsolation::ReadCommitted,
            started_at: std::time::Instant::now(),
            password_pepper: "pepper".to_string(),
            token_pepper: token_pepper.clone(),
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
        Self {
            _guard: guard,
            app,
            pool,
            token_pepper,
            kdf_params,
            config,
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

    async fn create_user_session(&self, email: &str) -> String {
        let now = chrono::Utc::now();
        let user = User {
            id: uuid::Uuid::now_v7(),
            email: email.to_string(),
            full_name: None,
            password_hash: None,
            kdf_salt: "salt".to_string(),
            kdf_algorithm: self.config.auth.kdf.algorithm.clone(),
            kdf_iterations: i64::from(self.config.auth.kdf.iterations),
            kdf_memory_kb: i64::from(self.config.auth.kdf.memory_kb),
            kdf_parallelism: i64::from(self.config.auth.kdf.parallelism),
            recovery_key_hash: None,
            status: UserStatus::Active,
            deleted_at: None,
            deleted_by_user_id: None,
            deleted_by_device_id: None,
            row_version: 1,
            created_at: now,
            updated_at: now,
            last_login_at: None,
        };

        let user_repo = UserRepo::new(&self.pool);
        user_repo.create(&user).await.expect("create user");

        let device = Device {
            id: uuid::Uuid::now_v7(),
            user_id: user.id,
            name: "oidc-device".to_string(),
            fingerprint: "fingerprint".to_string(),
            os: None,
            os_version: None,
            app_version: None,
            last_seen_at: None,
            last_ip: None,
            revoked_at: None,
            created_at: now,
        };
        let device_repo = DeviceRepo::new(&self.pool);
        device_repo.create(&device).await.expect("create device");

        let access_token = format!("access-{}", uuid::Uuid::now_v7().simple());
        let refresh_token = format!("refresh-{}", uuid::Uuid::now_v7().simple());
        let session = Session {
            id: uuid::Uuid::now_v7(),
            user_id: user.id,
            device_id: device.id,
            access_token_hash: hash_token(&access_token, &self.token_pepper),
            access_expires_at: now + chrono::Duration::seconds(3600),
            refresh_token_hash: hash_token(&refresh_token, &self.token_pepper),
            expires_at: now + chrono::Duration::seconds(3600),
            created_at: now,
        };
        let session_repo = SessionRepo::new(&self.pool);
        session_repo.create(&session).await.expect("create session");

        access_token
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

    async fn create_item(
        &self,
        token: &str,
        vault_id: &str,
        path: &str,
        password: &str,
    ) -> serde_json::Value {
        let payload = json!({
            "path": path,
            "name": path,
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
        path: &str,
        password: &str,
    ) {
        let payload = json!({
            "path": path,
            "name": path,
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
    }

    async fn create_service_account(
        &self,
        owner_email: &str,
        scopes: Vec<String>,
    ) -> serde_json::Value {
        let owner = UserRepo::new(&self.pool)
            .get_by_email(owner_email)
            .await
            .expect("user lookup")
            .expect("user exists");
        let token = format!("zann_sa_{}", uuid::Uuid::now_v7().simple());
        let token_prefix: String = token.chars().take(12).collect();
        let token_hash =
            passwords::hash_service_token(&token, &self.token_pepper, &self.kdf_params)
                .expect("hash token");
        let account = ServiceAccount {
            id: uuid::Uuid::now_v7(),
            owner_user_id: owner.id,
            name: "shared-sa".to_string(),
            description: None,
            token_hash,
            token_prefix,
            scopes: sqlx_core::types::Json(scopes),
            allowed_ips: None,
            expires_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            use_count: 0,
            created_at: chrono::Utc::now(),
            revoked_at: None,
        };
        ServiceAccountRepo::new(&self.pool)
            .create(&account)
            .await
            .expect("create service account");
        json!({ "token": token })
    }

    async fn set_user_status(&self, email: &str, status: UserStatus) {
        let repo = UserRepo::new(&self.pool);
        let user = repo
            .get_by_email(email)
            .await
            .expect("user lookup")
            .expect("user exists");
        let updated = repo
            .update_status(user.id, user.row_version, status)
            .await
            .expect("update status");
        assert_eq!(updated, 1, "expected 1 row updated");
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_history_returns_plaintext_payload() {
    let app = TestApp::new_with_smk().await;
    let user = app.register("shared-plain@example.com", "password").await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token, "shared-plain").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let item = app.create_item(token, vault_id, "login", "pw-1").await;
    let item_id = item["id"].as_str().expect("item id");
    app.update_item(token, vault_id, item_id, "login", "pw-2")
        .await;

    let (status, versions) = app
        .get_json(
            &format!("/v1/shared/items/{}/history?limit=1", item_id),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let version = versions["versions"][0]["version"]
        .as_i64()
        .expect("version");

    let (status, detail) = app
        .get_json(
            &format!("/v1/shared/items/{}/history/{}", item_id, version),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let payload_value = detail["payload"]["fields"]["password"]["value"]
        .as_str()
        .expect("payload password");
    assert_eq!(payload_value, "pw-1");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_history_respects_service_account_scopes() {
    let app = TestApp::new_with_smk().await;
    let email = "shared-history-scope@example.com";
    let user = app.register(email, "password").await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token, "shared-history-scope").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let slug = vault["slug"].as_str().expect("vault slug");
    let item = app
        .create_item(token, vault_id, "allowed/one", "pw-1")
        .await;
    let item_id = item["id"].as_str().expect("item id");
    app.update_item(token, vault_id, item_id, "allowed/one", "pw-2")
        .await;

    let scopes = vec![format!("{slug}/prefix:allowed:read_history")];
    let service_account = app.create_service_account(email, scopes).await;
    let sa_token = service_account["token"].as_str().expect("sa token");

    let (status, versions) = app
        .get_json(
            &format!("/v1/shared/items/{}/history?limit=1", item_id),
            Some(sa_token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "list failed: {:?}", versions);
    let version = versions["versions"][0]["version"]
        .as_i64()
        .expect("version");

    let (status, _) = app
        .get_json(
            &format!("/v1/shared/items/{}/history/{}", item_id, version),
            Some(sa_token),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let scopes = vec![format!("{slug}/prefix:allowed:read_previous")];
    let service_account = app.create_service_account(email, scopes).await;
    let sa_token = service_account["token"].as_str().expect("sa token");

    let (status, detail) = app
        .get_json(
            &format!("/v1/shared/items/{}/history/{}", item_id, version),
            Some(sa_token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "version get failed: {:?}", detail);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_list_enforces_service_account_prefix() {
    let app = TestApp::new_with_smk().await;
    let email = "shared-scope@example.com";
    let user = app.register(email, "password").await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token, "shared-scope").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    app.create_item(token, vault_id, "allowed/one", "pw-1")
        .await;
    app.create_item(token, vault_id, "other/two", "pw-2").await;

    let scopes = vec![format!(
        "{}/prefix:allowed:read",
        vault["slug"].as_str().expect("vault slug")
    )];
    let service_account = app.create_service_account(email, scopes).await;
    let sa_token = service_account["token"].as_str().expect("sa token");

    let (status, json) = app
        .get_json(
            &format!("/v1/shared/items?vault_id={}&prefix=allowed", vault_id),
            Some(sa_token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "list failed: {:?}", json);
    let items = json["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["path"].as_str().expect("path"), "allowed/one");

    let (status, _) = app
        .get_json(
            &format!("/v1/shared/items?vault_id={}&prefix=other", vault_id),
            Some(sa_token),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_list_supports_cursor_pagination() {
    let app = TestApp::new_with_smk().await;
    let user = app.register("shared-cursor@example.com", "password").await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token, "shared-cursor").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    app.create_item(token, vault_id, "alpha/one", "pw-1").await;
    app.create_item(token, vault_id, "alpha/two", "pw-2").await;
    app.create_item(token, vault_id, "alpha/three", "pw-3")
        .await;

    let (status, first) = app
        .get_json(
            &format!(
                "/v1/shared/items?vault_id={}&prefix=alpha&limit=1",
                vault_id
            ),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let cursor = first["next_cursor"].as_str().expect("cursor").to_string();

    let (status, second) = app
        .get_json(
            &format!(
                "/v1/shared/items?vault_id={}&prefix=alpha&limit=1&cursor={}",
                vault_id, cursor
            ),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = second["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn service_account_token_allows_shared_access() {
    let app = TestApp::new_with_smk().await;
    let email = "shared-direct@example.com";
    let user = app.register(email, "password").await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token, "shared-direct").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    app.create_item(token, vault_id, "allowed/one", "pw-1")
        .await;

    let slug = vault["slug"].as_str().expect("vault slug");
    let scopes = vec![format!("{slug}:read")];
    let service_account = app.create_service_account(email, scopes).await;
    let sa_token = service_account["token"].as_str().expect("sa token");

    let (status, list) = app.get_json("/v1/vaults", Some(sa_token)).await;
    assert_eq!(status, StatusCode::OK, "vault list failed: {:?}", list);
    let vaults = list["vaults"].as_array().expect("vaults array");
    assert!(
        vaults
            .iter()
            .any(|vault| vault["id"].as_str() == Some(vault_id)),
        "expected vault in list"
    );

    let (status, items) = app
        .get_json(
            &format!("/v1/shared/items?vault_id={}&prefix=allowed", vault_id),
            Some(sa_token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "shared list failed: {:?}", items);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn service_account_token_allows_shared_access_in_oidc_mode() {
    let app = TestApp::new_with_auth(AuthMode::Oidc, false).await;
    let email = "shared-oidc@example.com";
    let token = app.create_user_session(email).await;

    let vault = app.create_shared_vault(&token, "shared-oidc").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    app.create_item(&token, vault_id, "allowed/one", "pw-1")
        .await;

    let slug = vault["slug"].as_str().expect("vault slug");
    let scopes = vec![format!("{slug}:read")];
    let service_account = app.create_service_account(email, scopes).await;
    let sa_token = service_account["token"].as_str().expect("sa token");

    let (status, items) = app
        .get_json(
            &format!("/v1/shared/items?vault_id={}&prefix=allowed", vault_id),
            Some(sa_token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "shared list failed: {:?}", items);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn service_account_login_allows_shared_access_in_oidc_mode() {
    let app = TestApp::new_with_auth(AuthMode::Oidc, false).await;
    let email = "shared-oidc-login@example.com";
    let token = app.create_user_session(email).await;

    let vault = app.create_shared_vault(&token, "shared-oidc-login").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    app.create_item(&token, vault_id, "allowed/one", "pw-1")
        .await;

    let slug = vault["slug"].as_str().expect("vault slug");
    let scopes = vec![format!("{slug}:read")];
    let service_account = app.create_service_account(email, scopes).await;
    let sa_token = service_account["token"].as_str().expect("sa token");

    let (status, login) = app
        .send_json(
            Method::POST,
            "/v1/auth/service-account",
            None,
            json!({ "token": sa_token }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "sa login failed: {:?}", login);
    let access_token = login["access_token"].as_str().expect("access token");

    let (status, items) = app
        .get_json(
            &format!("/v1/shared/items?vault_id={}&prefix=allowed", vault_id),
            Some(access_token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "shared list failed: {:?}", items);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn service_account_token_allows_shared_access_for_system_owner() {
    let app = TestApp::new_with_smk().await;
    let email = "shared-system@example.com";
    let user = app.register(email, "password").await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token, "shared-system").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    app.create_item(token, vault_id, "allowed/one", "pw-1")
        .await;

    let slug = vault["slug"].as_str().expect("vault slug");
    let scopes = vec![format!("{slug}/prefix:allowed:read")];
    let service_account = app.create_service_account(email, scopes).await;
    let sa_token = service_account["token"].as_str().expect("sa token");

    app.set_user_status(email, UserStatus::System).await;

    let (status, items) = app
        .get_json(
            &format!("/v1/shared/items?vault_id={}&prefix=allowed", vault_id),
            Some(sa_token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "shared list failed: {:?}", items);
}
