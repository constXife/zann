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

    /// MIG-009: a cursor a legacy client wrote before migration 0002 added
    /// `last_seq` keeps its sequence only inside its opaque value. The caller,
    /// which owns the cursor format, records that sequence once; a cursor that
    /// changed or already has one is left as it is. Returns whether it wrote.
    pub async fn adopt_legacy_last_seq(
        &self,
        storage_id: uuid::Uuid,
        vault_id: uuid::Uuid,
        cursor: &str,
        last_seq: i64,
    ) -> Result<bool, sqlx_core::Error> {
        query!(
            r#"
            UPDATE sync_cursors
            SET last_seq = ?4
            WHERE storage_id = ?1 AND vault_id = ?2 AND cursor = ?3 AND last_seq IS NULL
            "#,
            storage_id,
            vault_id,
            cursor,
            last_seq
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected() == 1)
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
