use crate::local::{LocalSyncCheckpoint, LocalSyncCursor};
use crate::SqlitePool;

pub struct SyncCursorRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> SyncCursorRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn get(
        &self,
        storage_id: uuid::Uuid,
        vault_id: uuid::Uuid,
    ) -> Result<Option<LocalSyncCursor>, sqlx_core::Error> {
        query_as!(
            LocalSyncCursor,
            r#"
            SELECT
                storage_id,
                vault_id,
                cursor,
                last_sync_at as "last_sync_at"
            FROM sync_cursors
            WHERE storage_id = ?1 AND vault_id = ?2
            "#,
            storage_id,
            vault_id
        )
        .fetch_optional(self.pool)
        .await
    }

    /// Legacy cursor-only write. Updating a row deliberately clears `last_seq`
    /// so it cannot leave a cursor paired with a stale server sequence.
    pub async fn upsert(&self, cursor: &LocalSyncCursor) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO sync_cursors (
                storage_id, vault_id, cursor, last_sync_at
            )
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(storage_id, vault_id) DO UPDATE SET
                cursor = excluded.cursor,
                last_sync_at = excluded.last_sync_at,
                last_seq = NULL
            "#,
            cursor.storage_id,
            cursor.vault_id,
            cursor.cursor.as_deref(),
            cursor.last_sync_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    /// Loads the cursor and server sequence from one durable SQLite snapshot.
    pub async fn get_checkpoint(
        &self,
        storage_id: uuid::Uuid,
        vault_id: uuid::Uuid,
    ) -> Result<Option<LocalSyncCheckpoint>, sqlx_core::Error> {
        query_as!(
            LocalSyncCheckpoint,
            r#"
            SELECT
                storage_id,
                vault_id,
                cursor,
                last_seq,
                last_sync_at as "last_sync_at"
            FROM sync_cursors
            WHERE storage_id = ?1 AND vault_id = ?2
            "#,
            storage_id,
            vault_id
        )
        .fetch_optional(self.pool)
        .await
    }

    /// Seeds or deliberately replaces a complete checkpoint. Sync page commits
    /// should use `LocalSyncRepo`, whose compare-and-swap is transactional.
    pub async fn upsert_checkpoint(
        &self,
        checkpoint: &LocalSyncCheckpoint,
    ) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO sync_cursors (
                storage_id, vault_id, cursor, last_seq, last_sync_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(storage_id, vault_id) DO UPDATE SET
                cursor = excluded.cursor,
                last_seq = excluded.last_seq,
                last_sync_at = excluded.last_sync_at
            "#,
            checkpoint.storage_id,
            checkpoint.vault_id,
            checkpoint.cursor.as_deref(),
            checkpoint.last_seq,
            checkpoint.last_sync_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn delete_by_storage(&self, storage_id: uuid::Uuid) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"DELETE FROM sync_cursors WHERE storage_id = ?1"#,
            storage_id
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn delete_by_storage_vault(
        &self,
        storage_id: uuid::Uuid,
        vault_id: uuid::Uuid,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"DELETE FROM sync_cursors WHERE storage_id = ?1 AND vault_id = ?2"#,
            storage_id,
            vault_id
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}
