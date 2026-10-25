//! SQLite maintenance operations used by native vault services.

use std::path::Path;

use sqlx_core::query::query;
use sqlx_core::query_scalar::query_scalar;

use crate::SqlitePool;

pub async fn integrity_faults(pool: &SqlitePool) -> Result<Vec<String>, sqlx_core::Error> {
    let verdicts: Vec<String> = query_scalar("PRAGMA integrity_check")
        .fetch_all(pool)
        .await?;
    Ok(verdicts.into_iter().filter(|value| value != "ok").collect())
}

pub async fn snapshot_into(pool: &SqlitePool, path: &Path) -> Result<(), sqlx_core::Error> {
    let mut connection = pool.acquire().await?;
    query("VACUUM INTO ?")
        .bind(path.to_string_lossy().to_string())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub async fn inspect_snapshot(pool: &SqlitePool) -> Result<(String, i64), sqlx_core::Error> {
    let mut connection = pool.acquire().await?;
    let verdict = query_scalar("PRAGMA integrity_check")
        .fetch_one(&mut *connection)
        .await?;
    let tables = query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('storages', 'local_vaults', 'items_cache')",
    ).fetch_one(&mut *connection).await?;
    Ok((verdict, tables))
}
