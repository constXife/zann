#![allow(dead_code)]

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sqlx_core::pool::PoolOptions;
use sqlx_core::row::Row;
use sqlx_postgres::{PgConnectOptions, Postgres};
use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Mutex;
use uuid::Uuid;
use zann_db::{migrate, PgPool};
use zann_server::config::ServerConfig;
use zann_server::domains::access_control::policies::PolicyRule;
use zann_server::domains::secrets::policies::{
    default_policy, default_policy_name, PasswordPolicy,
};

struct SharedDb {
    schema: String,
    db_url: String,
}

fn shared_db_lock() -> &'static Mutex<Option<SharedDb>> {
    static SHARED_DB: OnceLock<Mutex<Option<SharedDb>>> = OnceLock::new();
    SHARED_DB.get_or_init(|| Mutex::new(None))
}

fn reset_lock() -> &'static Mutex<()> {
    static RESET: OnceLock<Mutex<()>> = OnceLock::new();
    RESET.get_or_init(|| Mutex::new(()))
}

fn test_lock() -> &'static Mutex<()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK.get_or_init(|| Mutex::new(()))
}

pub struct TestGuard(tokio::sync::MutexGuard<'static, ()>);

pub async fn test_guard() -> TestGuard {
    TestGuard(test_lock().lock().await)
}

pub fn load_policy_rules() -> Vec<PolicyRule> {
    static RULES: OnceLock<Vec<PolicyRule>> = OnceLock::new();
    RULES
        .get_or_init(|| {
            let policies_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../config/policies.default.yaml");
            serde_yaml::from_str(&std::fs::read_to_string(policies_path).expect("policy file"))
                .expect("parse policies")
        })
        .clone()
}

pub fn tune_test_kdf(config: &mut ServerConfig) {
    config.auth.kdf.iterations = 1;
    config.auth.kdf.memory_kb = 8;
    config.auth.kdf.parallelism = 1;
}

pub async fn setup_shared_db() -> PgPool {
    let lock = shared_db_lock();
    let mut guard = lock.lock().await;
    if let Some(shared) = guard.as_ref() {
        let options = PgConnectOptions::from_str(&shared.db_url)
            .expect("failed to parse TEST_DATABASE_URL")
            .options([("search_path", shared.schema.as_str())]);
        let pool = PoolOptions::new()
            .max_connections(10)
            .min_connections(2)
            .acquire_timeout(Duration::from_secs(60))
            .connect_with(options)
            .await
            .expect("connect test pool");
        return pool;
    }

    let db_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set for Postgres tests");
    let schema = format!("zann_test_{}", Uuid::now_v7().simple());
    let admin_options =
        PgConnectOptions::from_str(&db_url).expect("failed to parse TEST_DATABASE_URL");
    let admin_pool = PoolOptions::new()
        .max_connections(1)
        .connect_with(admin_options.clone())
        .await
        .expect("connect admin pool");

    sqlx_core::query::query::<Postgres>(&format!("CREATE SCHEMA \"{}\"", schema))
        .execute(&admin_pool)
        .await
        .expect("create schema");

    let options = admin_options.options([("search_path", schema.as_str())]);
    let pool = PoolOptions::new()
        .max_connections(10)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(60))
        .connect_with(options)
        .await
        .expect("connect test pool");

    migrate(&pool).await.expect("migrate");

    let shared = SharedDb {
        schema,
        db_url,
    };
    *guard = Some(shared);
    pool
}

pub async fn reset_db(pool: &PgPool) {
    let _guard = reset_lock().lock().await;
    let rows = sqlx_core::query::query::<Postgres>(
        "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()",
    )
    .fetch_all(pool)
    .await
    .expect("list tables");
    if rows.is_empty() {
        return;
    }
    let tables: Vec<String> = rows
        .iter()
        .map(|row| row.get::<String, _>("tablename"))
        .collect();
    let joined = tables
        .iter()
        .map(|name| format!("\"{}\"", name.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(", ");
    let statement = format!("TRUNCATE {} RESTART IDENTITY CASCADE", joined);
    sqlx_core::query::query::<Postgres>(&statement)
        .execute(pool)
        .await
        .expect("truncate tables");
}

pub async fn setup_db() -> PgPool {
    let db_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set for Postgres tests");
    let schema = format!("zann_test_{}", Uuid::now_v7().simple());
    let admin_options =
        PgConnectOptions::from_str(&db_url).expect("failed to parse TEST_DATABASE_URL");
    let admin_pool = PoolOptions::new()
        .max_connections(1)
        .connect_with(admin_options.clone())
        .await
        .expect("connect admin pool");

    sqlx_core::query::query::<Postgres>(&format!("CREATE SCHEMA \"{}\"", schema))
        .execute(&admin_pool)
        .await
        .expect("create schema");

    let options = admin_options.options([("search_path", schema.as_str())]);
    let pool = PoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .expect("connect test pool");

    migrate(&pool).await.expect("migrate");
    pool
}

pub fn default_secret_policies() -> (HashMap<String, PasswordPolicy>, String) {
    let mut policies = HashMap::new();
    let default_name = default_policy_name().to_string();
    policies.insert(default_name.clone(), default_policy());
    (policies, default_name)
}

pub fn test_identity_key() -> Arc<SigningKey> {
    Arc::new(SigningKey::generate(&mut OsRng))
}
