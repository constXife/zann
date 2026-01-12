use crate::local::LocalSyncCursor;
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

    pub async fn upsert(&self, cursor: &LocalSyncCursor) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO sync_cursors (
                storage_id, vault_id, cursor, last_sync_at
            )
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(storage_id, vault_id) DO UPDATE SET
                cursor = excluded.cursor,
                last_sync_at = excluded.last_sync_at
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

    pub async fn delete_by_storage(
        &self,
        storage_id: uuid::Uuid,
    ) -> Result<u64, sqlx_core::Error> {
        query!(r#"DELETE FROM sync_cursors WHERE storage_id = ?1"#, storage_id)
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
