use sqlx_core::row::Row;
use sqlx_core::transaction::Transaction;
use sqlx_sqlite::Sqlite;
use uuid::Uuid;

use crate::local::{LocalPendingChange, LocalProjectionReadError, LocalSyncCheckpoint};
use crate::services::{MAX_ITEM_NAME_LEN, MAX_ITEM_PATH_LEN, MAX_ITEM_PAYLOAD_BYTES};
use crate::SqlitePool;

const MAX_BOUNDED_PENDING: u32 = 64;
const MAX_PENDING_CIPHERTEXT_BYTES: i64 = (MAX_ITEM_PAYLOAD_BYTES + 256) as i64;
const MAX_PENDING_PATH_BYTES: i64 = MAX_ITEM_PATH_LEN as i64;
const MAX_PENDING_NAME_BYTES: i64 = MAX_ITEM_NAME_LEN as i64;
const MAX_PENDING_TYPE_BYTES: i64 = 128;
const MAX_PENDING_CHECKSUM_BYTES: i64 = 256;
const MAX_CURSOR_BYTES: i64 = 4_096;
const MAX_TIMESTAMP_BYTES: i64 = 64;

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

    /// Loads a checkpoint and a strictly bounded pending projection from the
    /// same SQLite read transaction. Callers conventionally request one more
    /// row than their domain limit so overflow is detected without an
    /// unbounded `fetch_all`.
    pub async fn load_checkpoint_with_pending_limit(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        limit: u32,
    ) -> Result<(Option<LocalSyncCheckpoint>, Vec<LocalPendingChange>), sqlx_core::Error> {
        if limit == 0 || limit > 1_024 {
            return Err(sqlx_core::Error::Protocol(
                "pending checkpoint limit is outside the supported range".to_string(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        let checkpoint = query_as!(
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
        .fetch_optional(&mut *tx)
        .await?;
        let pending = query_as!(
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
            ORDER BY created_at, id
            LIMIT ?3
            "#,
            storage_id,
            vault_id,
            i64::from(limit)
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((checkpoint, pending))
    }

    /// Loads one checkpoint and at most `max_pending` complete pending rows.
    ///
    /// The transaction first counts `max + 1` identifiers and validates only
    /// scalar `typeof`/byte-length expressions. Oversized TEXT/BLOB values are
    /// therefore rejected before SQLx allocates or decodes their bodies.
    pub async fn load_checkpoint_with_pending_max(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        max_pending: u32,
    ) -> Result<(Option<LocalSyncCheckpoint>, Vec<LocalPendingChange>), LocalProjectionReadError>
    {
        if storage_id.is_nil()
            || vault_id.is_nil()
            || max_pending == 0
            || max_pending > MAX_BOUNDED_PENDING
        {
            return Err(LocalProjectionReadError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        if cursor_identifiers_corrupt(&mut tx).await? {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::CorruptProjection);
        }
        let checkpoint_preflight = query!(
            r#"
            SELECT CASE WHEN
                CASE WHEN typeof(storage_id) IN ('blob', 'text')
                    THEN octet_length(storage_id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(vault_id) IN ('blob', 'text')
                    THEN octet_length(vault_id) IN (16, 36) ELSE 0 END
                AND (cursor IS NULL OR CASE WHEN typeof(cursor) = 'text'
                    THEN octet_length(cursor) BETWEEN 1 AND ?3 ELSE 0 END)
                AND CASE
                    WHEN last_seq IS NULL THEN 1
                    WHEN typeof(last_seq) = 'integer' THEN last_seq >= 1
                    ELSE 0
                END
                AND (last_sync_at IS NULL OR CASE WHEN typeof(last_sync_at) = 'text'
                    THEN octet_length(last_sync_at) BETWEEN 1 AND ?4 ELSE 0 END)
            THEN 1 ELSE 0 END AS valid
            FROM sync_cursors
            WHERE storage_id = ?1 AND vault_id = ?2
            "#,
            storage_id,
            vault_id,
            MAX_CURSOR_BYTES,
            MAX_TIMESTAMP_BYTES
        )
        .fetch_optional(&mut *tx)
        .await?;
        if checkpoint_preflight
            .as_ref()
            .is_some_and(|row| row.try_get::<i64, _>("valid").ok() != Some(1))
        {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::CorruptProjection);
        }

        if pending_identifiers_corrupt(&mut tx).await? {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::CorruptProjection);
        }

        let overflow_limit = i64::from(max_pending) + 1;
        let count_row = query!(
            r#"
            SELECT COUNT(*) AS count
            FROM (
                SELECT 1
                FROM pending_changes
                WHERE storage_id = ?1 AND vault_id = ?2
                LIMIT ?3
            )
            "#,
            storage_id,
            vault_id,
            overflow_limit
        )
        .fetch_one(&mut *tx)
        .await?;
        let pending_count: i64 = count_row.try_get("count")?;
        if pending_count > i64::from(max_pending) {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::TooManyRows);
        }

        let corrupt_pending = query!(
            r#"
            SELECT 1
            FROM pending_changes
            WHERE storage_id = ?1 AND vault_id = ?2
              AND CASE WHEN
                CASE WHEN typeof(id) IN ('blob', 'text')
                    THEN octet_length(id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(storage_id) IN ('blob', 'text')
                    THEN octet_length(storage_id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(vault_id) IN ('blob', 'text')
                    THEN octet_length(vault_id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(item_id) IN ('blob', 'text')
                    THEN octet_length(item_id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(operation) = 'integer'
                    THEN operation IN (1, 2, 3, 4) ELSE 0 END
                AND (payload_enc IS NULL OR CASE WHEN typeof(payload_enc) = 'blob'
                    THEN length(payload_enc) <= ?3 ELSE 0 END)
                AND (checksum IS NULL OR CASE WHEN typeof(checksum) = 'text'
                    THEN octet_length(checksum) BETWEEN 1 AND ?4 ELSE 0 END)
                AND (path IS NULL OR CASE WHEN typeof(path) = 'text'
                    THEN octet_length(path) BETWEEN 1 AND ?5 ELSE 0 END)
                AND (name IS NULL OR CASE WHEN typeof(name) = 'text'
                    THEN octet_length(name) BETWEEN 1 AND ?6 ELSE 0 END)
                AND (type_id IS NULL OR CASE WHEN typeof(type_id) = 'text'
                    THEN octet_length(type_id) BETWEEN 1 AND ?7 ELSE 0 END)
                AND CASE
                    WHEN base_seq IS NULL THEN 1
                    WHEN typeof(base_seq) = 'integer' THEN base_seq >= 1
                    ELSE 0
                END
                AND CASE WHEN typeof(created_at) = 'text'
                    THEN octet_length(created_at) BETWEEN 1 AND ?8 ELSE 0 END
              THEN 1 ELSE 0 END = 0
            LIMIT 1
            "#,
            storage_id,
            vault_id,
            MAX_PENDING_CIPHERTEXT_BYTES,
            MAX_PENDING_CHECKSUM_BYTES,
            MAX_PENDING_PATH_BYTES,
            MAX_PENDING_NAME_BYTES,
            MAX_PENDING_TYPE_BYTES,
            MAX_TIMESTAMP_BYTES
        )
        .fetch_optional(&mut *tx)
        .await?;
        if corrupt_pending.is_some() {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::CorruptProjection);
        }

        let checkpoint = query_as!(
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
        .fetch_optional(&mut *tx)
        .await?;
        let pending = query_as!(
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
            ORDER BY created_at, id
            LIMIT ?3
            "#,
            storage_id,
            vault_id,
            i64::from(max_pending)
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((checkpoint, pending))
    }

    /// Reads the unique storage/item pending row without an unbounded vector.
    pub async fn get_by_item(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
    ) -> Result<Option<LocalPendingChange>, sqlx_core::Error> {
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
            LIMIT 1
            "#,
            storage_id,
            item_id
        )
        .fetch_optional(self.pool)
        .await
    }

    /// Reads the unique storage/item row after a scalar body-bound preflight
    /// in the same SQLite snapshot.
    pub async fn get_by_item_bounded(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
    ) -> Result<Option<LocalPendingChange>, LocalProjectionReadError> {
        if storage_id.is_nil() || item_id.is_nil() {
            return Err(LocalProjectionReadError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        if pending_identifiers_corrupt(&mut tx).await? {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::CorruptProjection);
        }
        let corrupt = query!(
            r#"
            SELECT CASE WHEN
                CASE WHEN typeof(id) IN ('blob', 'text')
                    THEN octet_length(id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(storage_id) IN ('blob', 'text')
                    THEN octet_length(storage_id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(vault_id) IN ('blob', 'text')
                    THEN octet_length(vault_id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(item_id) IN ('blob', 'text')
                    THEN octet_length(item_id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(operation) = 'integer'
                    THEN operation IN (1, 2, 3, 4) ELSE 0 END
                AND (payload_enc IS NULL OR CASE WHEN typeof(payload_enc) = 'blob'
                    THEN length(payload_enc) <= ?3 ELSE 0 END)
                AND (checksum IS NULL OR CASE WHEN typeof(checksum) = 'text'
                    THEN octet_length(checksum) BETWEEN 1 AND ?4 ELSE 0 END)
                AND (path IS NULL OR CASE WHEN typeof(path) = 'text'
                    THEN octet_length(path) BETWEEN 1 AND ?5 ELSE 0 END)
                AND (name IS NULL OR CASE WHEN typeof(name) = 'text'
                    THEN octet_length(name) BETWEEN 1 AND ?6 ELSE 0 END)
                AND (type_id IS NULL OR CASE WHEN typeof(type_id) = 'text'
                    THEN octet_length(type_id) BETWEEN 1 AND ?7 ELSE 0 END)
                AND CASE
                    WHEN base_seq IS NULL THEN 1
                    WHEN typeof(base_seq) = 'integer' THEN base_seq >= 1
                    ELSE 0
                END
                AND CASE WHEN typeof(created_at) = 'text'
                    THEN octet_length(created_at) BETWEEN 1 AND ?8 ELSE 0 END
            THEN 0 ELSE 1 END AS corrupt
            FROM pending_changes
            WHERE storage_id = ?1 AND item_id = ?2
            LIMIT 1
            "#,
            storage_id,
            item_id,
            MAX_PENDING_CIPHERTEXT_BYTES,
            MAX_PENDING_CHECKSUM_BYTES,
            MAX_PENDING_PATH_BYTES,
            MAX_PENDING_NAME_BYTES,
            MAX_PENDING_TYPE_BYTES,
            MAX_TIMESTAMP_BYTES
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(corrupt) = corrupt else {
            tx.commit().await?;
            return Ok(None);
        };
        if corrupt.try_get::<i64, _>("corrupt")? != 0 {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::CorruptProjection);
        }
        let pending = query_as!(
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
            LIMIT 1
            "#,
            storage_id,
            item_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(pending)
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

async fn cursor_identifiers_corrupt(
    tx: &mut Transaction<'_, Sqlite>,
) -> Result<bool, sqlx_core::Error> {
    query!(
        r#"
        SELECT 1
        FROM sync_cursors
        WHERE CASE WHEN
            typeof(storage_id) IN ('blob', 'text')
            AND octet_length(storage_id) IN (16, 36)
            AND typeof(vault_id) IN ('blob', 'text')
            AND octet_length(vault_id) IN (16, 36)
        THEN 0 ELSE 1 END
        LIMIT 1
        "#
    )
    .fetch_optional(&mut **tx)
    .await
    .map(|row| row.is_some())
}

async fn pending_identifiers_corrupt(
    tx: &mut Transaction<'_, Sqlite>,
) -> Result<bool, sqlx_core::Error> {
    query!(
        r#"
        SELECT 1
        FROM pending_changes
        WHERE CASE WHEN
            typeof(id) IN ('blob', 'text')
            AND octet_length(id) IN (16, 36)
            AND typeof(storage_id) IN ('blob', 'text')
            AND octet_length(storage_id) IN (16, 36)
            AND typeof(vault_id) IN ('blob', 'text')
            AND octet_length(vault_id) IN (16, 36)
            AND typeof(item_id) IN ('blob', 'text')
            AND octet_length(item_id) IN (16, 36)
        THEN 0 ELSE 1 END
        LIMIT 1
        "#
    )
    .fetch_optional(&mut **tx)
    .await
    .map(|row| row.is_some())
}
