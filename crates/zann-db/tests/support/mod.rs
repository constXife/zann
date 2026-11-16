use chrono::Utc;
use sqlx_core::pool::PoolOptions;
use sqlx_postgres::{PgConnectOptions, Postgres};
use std::{env, str::FromStr};
use uuid::Uuid;
use zann_core::{User, UserStatus};
use zann_db::{migrate, PgPool};

pub async fn setup_empty_db() -> PgPool {
    let db_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set for Postgres tests");
    let schema = format!("zann_db_test_{}", Uuid::now_v7().simple());
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
        .max_connections(4)
        .connect_with(options)
        .await
        .expect("connect test pool");
    pool
}

pub async fn setup_db() -> PgPool {
    let pool = setup_empty_db().await;
    migrate(&pool).await.expect("migrate");
    pool
}

pub fn test_user(now: chrono::DateTime<Utc>, email: &str, full_name: Option<&str>) -> User {
    User {
        id: Uuid::now_v7(),
        email: email.to_string(),
        full_name: full_name.map(|value| value.to_string()),
        password_hash: None,
        kdf_salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        kdf_algorithm: "argon2id".to_string(),
        kdf_iterations: 3,
        kdf_memory_kb: 65536,
        kdf_parallelism: 4,
        recovery_key_hash: None,
        auth_epoch: 1,
        active_recovery_id: None,
        status: UserStatus::Active,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        row_version: 1,
        created_at: now,
        updated_at: now,
        last_login_at: None,
    }
}
