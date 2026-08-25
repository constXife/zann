use std::env;
use std::str::FromStr;

use chrono::Utc;
use sqlx_core::pool::PoolOptions;
use sqlx_core::raw_sql::raw_sql;
use sqlx_postgres::{PgConnectOptions, Postgres};
use uuid::Uuid;
use zann_db::PgPool;

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn vault_catalog_migration_preflights_and_installs_metadata_bounds() {
    let pool = setup_legacy_schema().await;
    let vault_id = Uuid::now_v7();
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO vaults (
            id, slug, name, kind, encryption_type, vault_key_enc,
            cache_policy, tags, row_version, created_at
        )
        VALUES ($1, $2, 'Legacy', 2, 2, $3, 1, $4, 1, $5)
        "#,
    )
    .bind(vault_id)
    .bind("s".repeat(129))
    .bind(vec![1_u8])
    .bind(sqlx_core::types::Json(Vec::<String>::new()))
    .bind(Utc::now())
    .execute(&pool)
    .await
    .expect("insert oversized legacy slug");

    assert_eq!(
        rejected_migration_constraint(&pool).await,
        "vaults_slug_canonical"
    );
    sqlx_core::query::query::<Postgres>(
        "UPDATE vaults SET slug = 'legacy', name = $2 WHERE id = $1",
    )
    .bind(vault_id)
    .bind("n".repeat(201))
    .execute(&pool)
    .await
    .expect("replace dirty slug with dirty name");
    assert_eq!(
        rejected_migration_constraint(&pool).await,
        "vaults_name_canonical"
    );

    sqlx_core::query::query::<Postgres>("UPDATE vaults SET name = 'Legacy' WHERE id = $1")
        .bind(vault_id)
        .execute(&pool)
        .await
        .expect("repair legacy metadata");
    raw_sql(include_str!(
        "../migrations/0002_changes_current_generation.sql"
    ))
    .execute(&pool)
    .await
    .expect("install bounded catalog contract");

    let error = sqlx_core::query::query::<Postgres>("UPDATE vaults SET name = $2 WHERE id = $1")
        .bind(vault_id)
        .bind("n".repeat(201))
        .execute(&pool)
        .await
        .expect_err("installed constraint must reject oversized name");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database| database.constraint()),
        Some("vaults_name_canonical")
    );
}

async fn rejected_migration_constraint(pool: &PgPool) -> String {
    let mut transaction = pool.begin().await.expect("begin migration");
    let error = raw_sql(include_str!(
        "../migrations/0002_changes_current_generation.sql"
    ))
    .execute(&mut *transaction)
    .await
    .expect_err("dirty legacy catalog must fail migration");
    transaction.rollback().await.expect("rollback migration");
    error
        .as_database_error()
        .and_then(|database| database.constraint())
        .expect("migration constraint")
        .to_string()
}

async fn setup_legacy_schema() -> PgPool {
    let database_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set for Postgres tests");
    let schema = format!("zann_vault_catalog_{}", Uuid::now_v7().simple());
    let admin_options = PgConnectOptions::from_str(&database_url).expect("parse TEST_DATABASE_URL");
    let admin_pool = PoolOptions::new()
        .max_connections(1)
        .connect_with(admin_options.clone())
        .await
        .expect("connect admin pool");
    sqlx_core::query::query::<Postgres>(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&admin_pool)
        .await
        .expect("create test schema");

    let pool = PoolOptions::new()
        .max_connections(2)
        .connect_with(admin_options.options([("search_path", schema.as_str())]))
        .await
        .expect("connect legacy schema");
    raw_sql(include_str!("../migrations/0001_init.sql"))
        .execute(&pool)
        .await
        .expect("install legacy schema");
    pool
}
