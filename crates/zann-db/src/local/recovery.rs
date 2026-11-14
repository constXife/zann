//! One pinned preview connection detects every intervening commit, including
//! same-cardinality edits, before a scoped terminal recovery transaction.
use crate::{Sqlite, SqlitePool};
use sqlx_core::{pool::PoolConnection, query::query, query_scalar::query_scalar};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Census {
    pub accounts: i64,
    pub items: i64,
    pub pending: i64,
    pub dirty: i64,
    pub local_history: i64,
}
pub struct RecoverySource {
    connection: PoolConnection<Sqlite>,
    version: i64,
    storage: Option<Uuid>,
    pub census: Census,
    pub keyring: Option<String>,
}
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("local recovery preview changed; review it again")]
    Changed,
    #[error("local recovery storage failed")]
    Database(#[from] sqlx_core::Error),
}
fn changed() -> RecoveryError {
    RecoveryError::Changed
}
impl RecoverySource {
    pub async fn prepare(pool: &SqlitePool, storage: Option<Uuid>) -> Result<Self, RecoveryError> {
        let mut connection = pool.acquire().await?;
        let version = query_scalar("PRAGMA data_version")
            .fetch_one(&mut *connection)
            .await?;
        let mut count = async |sql: &str| -> Result<i64, sqlx_core::Error> {
            query_scalar(sql)
                .bind(storage)
                .fetch_one(&mut *connection)
                .await
        };
        let accounts = count("SELECT COUNT(*) FROM storages WHERE (? IS NULL OR id = ?1)").await?;
        let items =
            count("SELECT COUNT(*) FROM items_cache WHERE (? IS NULL OR storage_id = ?1)").await?;
        let pending =
            count("SELECT COUNT(*) FROM pending_changes WHERE (? IS NULL OR storage_id = ?1)")
                .await?;
        let dirty = count("SELECT COUNT(*) FROM items_cache WHERE (? IS NULL OR storage_id = ?1) AND sync_status != 6").await?;
        let local_history = count("SELECT COUNT(*) FROM item_history WHERE (? IS NULL OR storage_id = ?1) AND sync_status != 2").await?;
        let keyring =
            super::metadata_repo::read_bounded(&mut *connection, "device_keyring", 1048576).await?;
        let after: i64 = query_scalar("PRAGMA data_version")
            .fetch_one(&mut *connection)
            .await?;
        if version != after {
            return Err(changed());
        }
        Ok(Self {
            connection,
            version,
            storage,
            keyring,
            census: Census {
                accounts,
                items,
                pending,
                dirty,
                local_history,
            },
        })
    }
    /// Reserve the writer and prove the exact preview before external side effects.
    pub async fn begin(mut self, pool: &SqlitePool) -> Result<ValidatedRecovery, RecoveryError> {
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        let version: i64 = query_scalar("PRAGMA data_version")
            .fetch_one(&mut *self.connection)
            .await?;
        if version != self.version {
            return Err(changed());
        }
        let keyring =
            super::metadata_repo::read_bounded(&mut *tx, "device_keyring", 1048576).await?;
        if keyring != self.keyring {
            return Err(changed());
        }
        Ok(ValidatedRecovery {
            tx,
            storage: self.storage,
        })
    }
}

/// A validated source with its SQLite writer reservation held until commit/drop.
pub struct ValidatedRecovery {
    tx: sqlx_core::transaction::Transaction<'static, Sqlite>,
    storage: Option<Uuid>,
}
impl ValidatedRecovery {
    pub async fn commit(self, replacement_keyring: Option<&str>) -> Result<(), RecoveryError> {
        let mut tx = self.tx;
        for table in [
            "pending_changes",
            "sync_cursors",
            "item_history",
            "items_cache",
            "local_vaults",
        ] {
            query(&format!(
                "DELETE FROM {table} WHERE (? IS NULL OR storage_id = ?1)"
            ))
            .bind(self.storage)
            .execute(&mut *tx)
            .await?;
        }
        query("DELETE FROM storages WHERE (? IS NULL OR id = ?1)")
            .bind(self.storage)
            .execute(&mut *tx)
            .await?;
        match replacement_keyring {
            Some(value) => {
                query("UPDATE metadata SET value = ? WHERE key = 'device_keyring'")
                    .bind(value)
                    .execute(&mut *tx)
                    .await?;
            }
            None => {
                query("DELETE FROM metadata WHERE key = 'device_keyring'")
                    .execute(&mut *tx)
                    .await?;
            }
        }
        let id = Uuid::now_v7();
        let result =
            query("UPDATE local_database_identity SET instance_uuid = ? WHERE singleton = 1")
                .bind(id.as_bytes().as_slice())
                .execute(&mut *tx)
                .await?;
        if result.rows_affected() != 1 {
            return Err(changed());
        }
        tx.commit().await.map_err(Into::into)
    }
}
