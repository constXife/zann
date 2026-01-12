use uuid::Uuid;

use crate::local::LocalPendingChange;
use crate::SqlitePool;

pub struct PendingChangeRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> PendingChangeRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, change: &LocalPendingChange) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO pending_changes (
                id, storage_id, vault_id, item_id, operation, payload_enc, checksum,
                path, name, type_id, base_seq, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            change.id,
            change.storage_id,
            change.vault_id,
            change.item_id,
            change.operation.as_i32(),
            change.payload_enc.as_deref(),
            change.checksum.as_deref(),
            change.path.as_deref(),
            change.name.as_deref(),
            change.type_id.as_deref(),
            change.base_seq,
            change.created_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn list_by_storage_vault(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
    ) -> Result<Vec<LocalPendingChange>, sqlx_core::Error> {
        query_as!(
            LocalPendingChange,
            r#"
            SELECT
                id,
                storage_id,
                vault_id,
                item_id,
                operation,
                payload_enc,
                checksum,
                path,
                name,
                type_id,
                base_seq as "base_seq",
                created_at as "created_at"
            FROM pending_changes
            WHERE storage_id = ?1 AND vault_id = ?2
            ORDER BY created_at
            "#,
            storage_id,
            vault_id
        )
        .fetch_all(self.pool)
        .await
    }

    pub async fn list_by_storage(
        &self,
        storage_id: Uuid,
    ) -> Result<Vec<LocalPendingChange>, sqlx_core::Error> {
        query_as!(
            LocalPendingChange,
            r#"
            SELECT
                id,
                storage_id,
                vault_id,
                item_id,
                operation,
                payload_enc,
                checksum,
                path,
                name,
                type_id,
                base_seq as "base_seq",
                created_at as "created_at"
            FROM pending_changes
            WHERE storage_id = ?1
            ORDER BY created_at
            "#,
            storage_id
        )
        .fetch_all(self.pool)
        .await
    }

    pub async fn list_by_item(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
    ) -> Result<Vec<LocalPendingChange>, sqlx_core::Error> {
        query_as!(
            LocalPendingChange,
            r#"
            SELECT
                id,
                storage_id,
                vault_id,
                item_id,
                operation,
                payload_enc,
                checksum,
                path,
                name,
                type_id,
                base_seq as "base_seq",
                created_at as "created_at"
            FROM pending_changes
            WHERE storage_id = ?1 AND item_id = ?2
            ORDER BY created_at
            "#,
            storage_id,
            item_id
        )
        .fetch_all(self.pool)
        .await
    }

    pub async fn delete_by_item(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"DELETE FROM pending_changes WHERE storage_id = ?1 AND item_id = ?2"#,
            storage_id,
            item_id
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn delete_by_ids(&self, ids: &[Uuid]) -> Result<u64, sqlx_core::Error> {
        if ids.is_empty() {
            return Ok(0);
        }
        let placeholders = vec!["?"; ids.len()].join(", ");
        let sql = format!("DELETE FROM pending_changes WHERE id IN ({placeholders})");
        let mut query = sqlx_core::query::query::<sqlx_sqlite::Sqlite>(&sql);
        for id in ids {
            query = query.bind(id);
        }
        let result = query.execute(self.pool).await?;
        Ok(result.rows_affected())
    }

    pub async fn delete_by_storage(&self, storage_id: Uuid) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"DELETE FROM pending_changes WHERE storage_id = ?1"#,
            storage_id
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn delete_by_storage_vault(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"DELETE FROM pending_changes WHERE storage_id = ?1 AND vault_id = ?2"#,
            storage_id,
            vault_id
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}
