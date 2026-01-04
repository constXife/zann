#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_raw_string_hashes)]
#![allow(clippy::uninlined_format_args)]

extern crate sqlx_core as sqlx;

use sqlx_core::pool::{Pool, PoolOptions};
#[cfg(feature = "postgres")]
use sqlx_postgres::{PgConnectOptions, Postgres};
#[cfg(feature = "sqlite")]
use sqlx_sqlite::{Sqlite, SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use std::str::FromStr;
#[cfg(feature = "sqlite")]
use std::time::Duration;

#[cfg(feature = "sqlite")]
pub mod local;
#[cfg(feature = "postgres")]
pub mod repo;
#[cfg(feature = "sqlite")]
pub mod services;

#[cfg(feature = "sqlite")]
pub type SqlitePool = Pool<Sqlite>;
#[cfg(feature = "postgres")]
pub type PgPool = Pool<Postgres>;

#[cfg(feature = "postgres")]
pub async fn connect_postgres(path: &str) -> Result<PgPool, sqlx_core::Error> {
    connect_postgres_with_max(path, 10).await
}

#[cfg(feature = "postgres")]
pub async fn connect_postgres_with_max(
    path: &str,
    max_connections: u32,
) -> Result<PgPool, sqlx_core::Error> {
    let options = PgConnectOptions::from_str(path)?;
    PoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await
}

#[cfg(feature = "sqlite")]
pub async fn connect_sqlite(path: &str) -> Result<SqlitePool, sqlx_core::Error> {
    connect_sqlite_with_max(path, 10).await
}

#[cfg(feature = "sqlite")]
pub async fn connect_sqlite_with_max(
    path: &str,
    max_connections: u32,
) -> Result<SqlitePool, sqlx_core::Error> {
    let mut options = SqliteConnectOptions::from_str(path)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5));
    options = options.foreign_keys(true);

    PoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await
}

#[cfg(feature = "postgres")]
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx_core::migrate::MigrateError> {
    sqlx_macros::migrate!("../zann-server/migrations")
        .run(pool)
        .await
}

#[cfg(feature = "sqlite")]
pub async fn migrate_local(pool: &SqlitePool) -> Result<(), sqlx_core::migrate::MigrateError> {
    sqlx_macros::migrate!("../zann-db/migrations")
        .run(pool)
        .await
}
