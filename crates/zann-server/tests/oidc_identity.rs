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
    let rules: Vec<PolicyRule> = support::load_policy_rules();
    config.auth.oidc.enabled = true;
    let (secret_policies, secret_default_policy) = support::default_secret_policies();

    AppState {
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
        usage_tracker: std::sync::Arc::new(UsageTracker::new(pool, 100)),
        security_profiles: load_security_profiles(),
        secret_policies,
        secret_default_policy,
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn oidc_rejects_disabled_user() {
    let _guard = support::test_guard().await;
    let pool = support::setup_shared_db().await;
    support::reset_db(&pool).await;
    let mut config = ServerConfig::default();
    support::tune_test_kdf(&mut config);
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
        email_verified: None,
        claims: Map::new(),
    };

    let error = identity_from_oidc(&state, token)
        .await
        .expect_err("oidc should reject disabled users");
    assert_eq!(error, "user_disabled");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn oidc_links_existing_user_by_email() {
    let _guard = support::test_guard().await;
    let pool = support::setup_shared_db().await;
    support::reset_db(&pool).await;
    let mut config = ServerConfig::default();
    support::tune_test_kdf(&mut config);
    let state = build_state(pool.clone(), config).await;

    let now = Utc::now();
    let user = User {
        id: uuid::Uuid::now_v7(),
        email: "oidc-existing@example.com".to_string(),
        full_name: None,
        password_hash: Some("password-hash".to_string()),
        kdf_salt: random_kdf_salt(),
        kdf_algorithm: state.config.auth.kdf.algorithm.clone(),
        kdf_iterations: i64::from(state.config.auth.kdf.iterations),
        kdf_memory_kb: i64::from(state.config.auth.kdf.memory_kb),
        kdf_parallelism: i64::from(state.config.auth.kdf.parallelism),
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
    UserRepo::new(&state.db)
        .create(&user)
        .await
        .expect("create existing user");

    let token = OidcToken {
        issuer: "https://issuer.example.com".to_string(),
        subject: "subject-existing-user".to_string(),
        email: Some(user.email.clone()),
        email_verified: Some(true),
        claims: Map::new(),
    };

    let identity = identity_from_oidc(&state, token)
        .await
        .expect("oidc should link existing user");
    assert_eq!(identity.user_id, user.id);

    let oidc_identity = OidcIdentityRepo::new(&state.db)
        .get_by_issuer_subject("https://issuer.example.com", "subject-existing-user")
        .await
        .expect("load oidc identity")
        .expect("oidc identity created");
    assert_eq!(oidc_identity.user_id, user.id);
}

async fn fresh_oidc_state() -> AppState {
    let _guard = support::test_guard().await;
    let pool = support::setup_shared_db().await;
    support::reset_db(&pool).await;
    let mut config = ServerConfig::default();
    support::tune_test_kdf(&mut config);
    build_state(pool.clone(), config).await
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn unverified_email_cannot_adopt_an_existing_account() {
    let state = fresh_oidc_state().await;

    let now = Utc::now();
    let victim = User {
        id: uuid::Uuid::now_v7(),
        email: "victim@example.com".to_string(),
        full_name: None,
        password_hash: Some("password-hash".to_string()),
        kdf_salt: random_kdf_salt(),
        kdf_algorithm: state.config.auth.kdf.algorithm.clone(),
        kdf_iterations: i64::from(state.config.auth.kdf.iterations),
        kdf_memory_kb: i64::from(state.config.auth.kdf.memory_kb),
        kdf_parallelism: i64::from(state.config.auth.kdf.parallelism),
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
    UserRepo::new(&state.db)
        .create(&victim)
        .await
        .expect("create victim");

    let token = OidcToken {
        issuer: "https://attacker-issuer.example.com".to_string(),
        subject: "attacker-subject".to_string(),
        email: Some("victim@example.com".to_string()),
        email_verified: Some(false),
        claims: Map::new(),
    };

    let error = identity_from_oidc(&state, token)
        .await
        .expect_err("unverified email must not adopt an account");
    assert_eq!(error, "email_not_verified");

    let binding = OidcIdentityRepo::new(&state.db)
        .get_by_issuer_subject("https://attacker-issuer.example.com", "attacker-subject")
        .await
        .expect("load oidc identity");
    assert!(binding.is_none(), "no binding must be created");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn unverified_email_cannot_create_an_account() {
    let state = fresh_oidc_state().await;

    let token = OidcToken {
        issuer: "https://issuer.example.com".to_string(),
        subject: "subject-unverified-jit".to_string(),
        email: Some("unverified-jit@example.com".to_string()),
        email_verified: None,
        claims: Map::new(),
    };

    let error = identity_from_oidc(&state, token)
        .await
        .expect_err("unverified email must not create an account");
    assert_eq!(error, "email_not_verified");

    let user = UserRepo::new(&state.db)
        .get_by_email("unverified-jit@example.com")
        .await
        .expect("user lookup");
    assert!(user.is_none(), "no user must be provisioned");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn verified_email_provisions_a_new_user() {
    let state = fresh_oidc_state().await;

    let token = OidcToken {
        issuer: "https://issuer.example.com".to_string(),
        subject: "subject-verified-jit".to_string(),
        email: Some("verified-jit@example.com".to_string()),
        email_verified: Some(true),
        claims: Map::new(),
    };

    let identity = identity_from_oidc(&state, token)
        .await
        .expect("verified email provisions an account");
    let user = UserRepo::new(&state.db)
        .get_by_email("verified-jit@example.com")
        .await
        .expect("user lookup")
        .expect("user created");
    assert_eq!(identity.user_id, user.id);
}
