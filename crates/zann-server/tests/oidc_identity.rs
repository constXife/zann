use chrono::Utc;
use serde_json::Map;
use tokio::sync::Semaphore;
use zann_core::{OidcIdentity, OidcToken, User, UserStatus};
use zann_db::repo::{OidcIdentityRepo, UserRepo};
use zann_db::PgPool;
use zann_server::app::AppState;
use zann_server::config::ServerConfig;
use zann_server::domains::access_control::policies::{PolicyRule, PolicySet};
use zann_server::domains::access_control::policy_store::PolicyStore;
use zann_server::domains::auth::core::identity::identity_from_oidc;
use zann_server::domains::auth::core::oidc::OidcJwksCache;
use zann_server::domains::auth::core::passwords::random_kdf_salt;
use zann_server::infra::security_profiles::load_security_profiles;
use zann_server::infra::usage::UsageTracker;

mod support;

async fn build_state(pool: PgPool, mut config: ServerConfig) -> AppState {
    let policy_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policies.default.yaml");
    let rules: Vec<PolicyRule> =
        serde_yaml::from_str(&std::fs::read_to_string(policy_path).expect("policy file"))
            .expect("parse policies");
    config.auth.oidc.enabled = true;
    let (secret_policies, secret_default_policy) = support::default_secret_policies();

    AppState {
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
        config,
        policy_store: PolicyStore::new(PolicySet::from_rules(rules)),
        usage_tracker: std::sync::Arc::new(UsageTracker::new(pool, 100)),
        security_profiles: load_security_profiles(),
        secret_policies,
        secret_default_policy,
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn oidc_rejects_disabled_user() {
    let pool = support::setup_db().await;
    let config = ServerConfig::default();
    let state = build_state(pool.clone(), config).await;

    let now = Utc::now();
    let user = User {
        id: uuid::Uuid::now_v7(),
        email: "oidc-disabled@example.com".to_string(),
        full_name: None,
        password_hash: None,
        kdf_salt: random_kdf_salt(),
        kdf_algorithm: state.config.auth.kdf.algorithm.clone(),
        kdf_iterations: i64::from(state.config.auth.kdf.iterations),
        kdf_memory_kb: i64::from(state.config.auth.kdf.memory_kb),
        kdf_parallelism: i64::from(state.config.auth.kdf.parallelism),
        recovery_key_hash: None,
        status: UserStatus::Disabled,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        row_version: 1,
        created_at: now,
        updated_at: now,
        last_login_at: None,
    };
    UserRepo::new(&state.db)
        .create(&user)
        .await
        .expect("create user");

    let oidc_identity = OidcIdentity {
        id: uuid::Uuid::now_v7(),
        user_id: user.id,
        issuer: "https://issuer.example.com".to_string(),
        subject: "subject-123".to_string(),
        created_at: now,
    };
    OidcIdentityRepo::new(&state.db)
        .create(&oidc_identity)
        .await
        .expect("create oidc identity");

    let token = OidcToken {
        issuer: oidc_identity.issuer.clone(),
        subject: oidc_identity.subject.clone(),
        email: None,
        claims: Map::new(),
    };

    let error = identity_from_oidc(&state, token)
        .await
        .expect_err("oidc should reject disabled users");
    assert_eq!(error, "user_disabled");
}
