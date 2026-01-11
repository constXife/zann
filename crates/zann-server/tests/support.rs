#![allow(dead_code)]

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sqlx_core::pool::PoolOptions;
use sqlx_postgres::{PgConnectOptions, Postgres};
use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;
use zann_db::{migrate, PgPool};
use zann_server::domains::secrets::policies::{
    default_policy, default_policy_name, PasswordPolicy,
};

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
