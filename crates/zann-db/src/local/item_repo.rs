use chrono::{DateTime, Utc};
use sqlx_core::row::Row;
use uuid::Uuid;

use crate::local::{LocalItem, LocalProjectionReadError};
use crate::services::{MAX_ITEM_NAME_LEN, MAX_ITEM_PATH_LEN, MAX_ITEM_PAYLOAD_BYTES};
use crate::SqlitePool;

const MAX_ITEM_CIPHERTEXT_BYTES: i64 = (MAX_ITEM_PAYLOAD_BYTES + 256) as i64;
const MAX_ITEM_PATH_BYTES: i64 = MAX_ITEM_PATH_LEN as i64;
const MAX_ITEM_NAME_BYTES: i64 = MAX_ITEM_NAME_LEN as i64;
const MAX_ITEM_TYPE_BYTES: i64 = 128;
const MAX_ITEM_CHECKSUM_BYTES: i64 = 256;
const CACHE_KEY_FINGERPRINT_BYTES: i64 = 12;
const MAX_TIMESTAMP_BYTES: i64 = 64;

pub struct LocalItemRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> LocalItemRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, item: &LocalItem) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO items_cache (
                id, storage_id, vault_id, path, name, type_id, payload_enc, checksum, cache_key_fp,
                version, deleted_at, updated_at, sync_status
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            item.id,
            item.storage_id,
            item.vault_id,
            item.path.as_str(),
            item.name.as_str(),
            item.type_id.as_str(),
            &item.payload_enc,
            item.checksum.as_str(),
            item.cache_key_fp.as_deref(),
            item.version,
            item.deleted_at,
            item.updated_at,
            item.sync_status.as_i32()
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn update(&self, item: &LocalItem) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE items_cache
            SET storage_id = ?2,
                vault_id = ?3,
                path = ?4,
                name = ?5,
                type_id = ?6,
                payload_enc = ?7,
                checksum = ?8,
                cache_key_fp = ?9,
                version = ?10,
                deleted_at = ?11,
                updated_at = ?12,
                sync_status = ?13
            WHERE id = ?1
            "#,
            item.id,
            item.storage_id,
            item.vault_id,
            item.path.as_str(),
            item.name.as_str(),
            item.type_id.as_str(),
            &item.payload_enc,
            item.checksum.as_str(),
            item.cache_key_fp.as_deref(),
            item.version,
            item.deleted_at,
            item.updated_at,
            item.sync_status.as_i32()
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn delete_by_id(&self, item_id: Uuid) -> Result<u64, sqlx_core::Error> {
        query!(r#"DELETE FROM items_cache WHERE id = ?1"#, item_id)
            .execute(self.pool)
            .await
            .map(|result| result.rows_affected())
    }

    pub async fn list_deleted_before(
        &self,
        storage_id: Uuid,
        cutoff: Option<DateTime<Utc>>,
    ) -> Result<Vec<LocalItem>, sqlx_core::Error> {
        if let Some(cutoff) = cutoff {
            query_as!(
                LocalItem,
                r#"
                SELECT
                    id as "id",
                    storage_id as "storage_id",
                    vault_id as "vault_id",
                    path,
                    name,
                    type_id,
                    payload_enc,
                    checksum,
                    cache_key_fp,
                    version as "version",
                    deleted_at as "deleted_at",
                    updated_at as "updated_at",
                    sync_status
                FROM items_cache
                WHERE storage_id = ?1 AND deleted_at IS NOT NULL AND deleted_at <= ?2
                "#,
                storage_id,
                cutoff
            )
            .fetch_all(self.pool)
            .await
        } else {
            query_as!(
                LocalItem,
                r#"
                SELECT
                    id as "id",
                    storage_id as "storage_id",
                    vault_id as "vault_id",
                    path,
                    name,
                    type_id,
                    payload_enc,
                    checksum,
                    cache_key_fp,
                    version as "version",
                    deleted_at as "deleted_at",
                    updated_at as "updated_at",
                    sync_status
                FROM items_cache
                WHERE storage_id = ?1 AND deleted_at IS NOT NULL
                "#,
                storage_id
            )
            .fetch_all(self.pool)
            .await
        }
    }

    pub async fn get_by_vault_path(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        path: &str,
    ) -> Result<Option<LocalItem>, sqlx_core::Error> {
        query_as!(
            LocalItem,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                vault_id as "vault_id",
                path,
                name,
                type_id,
                payload_enc,
                checksum,
                cache_key_fp,
                version as "version",
                deleted_at as "deleted_at",
                updated_at as "updated_at",
                sync_status
            FROM items_cache
            WHERE storage_id = ?1 AND vault_id = ?2 AND path = ?3
            "#,
            storage_id,
            vault_id,
            path
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn get_active_by_vault_path(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        path: &str,
    ) -> Result<Option<LocalItem>, sqlx_core::Error> {
        query_as!(
            LocalItem,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                vault_id as "vault_id",
                path,
                name,
                type_id,
                payload_enc,
                checksum,
                cache_key_fp,
                version as "version",
                deleted_at as "deleted_at",
                updated_at as "updated_at",
                sync_status
            FROM items_cache
            WHERE storage_id = ?1 AND vault_id = ?2 AND path = ?3 AND deleted_at IS NULL
            "#,
            storage_id,
            vault_id,
            path
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn get_by_id(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
    ) -> Result<Option<LocalItem>, sqlx_core::Error> {
        query_as!(
            LocalItem,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                vault_id as "vault_id",
                path,
                name,
                type_id,
                payload_enc,
                checksum,
                cache_key_fp,
                version as "version",
                deleted_at as "deleted_at",
                updated_at as "updated_at",
                sync_status
            FROM items_cache
            WHERE storage_id = ?1 AND id = ?2
            "#,
            storage_id,
            item_id
        )
        .fetch_optional(self.pool)
        .await
    }

    /// Reads one item only after a same-snapshot scalar preflight bounds every
    /// dynamically typed body column before SQLx materializes it.
    pub async fn get_by_id_bounded(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
    ) -> Result<Option<LocalItem>, LocalProjectionReadError> {
        if storage_id.is_nil() || item_id.is_nil() {
            return Err(LocalProjectionReadError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let preflight = query!(
            r#"
        SELECT CASE WHEN
                CASE WHEN typeof(id) IN ('blob', 'text')
                    THEN octet_length(id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(storage_id) IN ('blob', 'text')
                    THEN octet_length(storage_id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(vault_id) IN ('blob', 'text')
                    THEN octet_length(vault_id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(path) = 'text'
                    THEN octet_length(path) BETWEEN 1 AND ?2 ELSE 0 END
                AND CASE WHEN typeof(name) = 'text'
                    THEN octet_length(name) BETWEEN 1 AND ?3 ELSE 0 END
                AND CASE WHEN typeof(type_id) = 'text'
                    THEN octet_length(type_id) BETWEEN 1 AND ?4 ELSE 0 END
                AND CASE WHEN typeof(payload_enc) = 'blob'
                    THEN length(payload_enc) <= ?5 ELSE 0 END
                AND CASE WHEN typeof(checksum) = 'text'
                    THEN octet_length(checksum) BETWEEN 1 AND ?6 ELSE 0 END
                AND (cache_key_fp IS NULL OR CASE WHEN typeof(cache_key_fp) = 'text'
                    THEN octet_length(cache_key_fp) = ?7 ELSE 0 END)
                AND CASE WHEN typeof(version) = 'integer'
                    THEN version >= 1 ELSE 0 END
                AND (deleted_at IS NULL OR CASE WHEN typeof(deleted_at) = 'text'
                    THEN octet_length(deleted_at) BETWEEN 1 AND ?8 ELSE 0 END)
                AND CASE WHEN typeof(updated_at) = 'text'
                    THEN octet_length(updated_at) BETWEEN 1 AND ?8 ELSE 0 END
                AND CASE WHEN typeof(sync_status) = 'integer'
                    THEN sync_status IN (1, 2, 3, 4, 5, 6) ELSE 0 END
            THEN 1 ELSE 0 END AS valid
            FROM items_cache
            WHERE id = ?1
            "#,
            item_id,
            MAX_ITEM_PATH_BYTES,
            MAX_ITEM_NAME_BYTES,
            MAX_ITEM_TYPE_BYTES,
            MAX_ITEM_CIPHERTEXT_BYTES,
            MAX_ITEM_CHECKSUM_BYTES,
            CACHE_KEY_FINGERPRINT_BYTES,
            MAX_TIMESTAMP_BYTES
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(preflight) = preflight else {
            tx.commit().await?;
            return Ok(None);
        };
        if preflight.try_get::<i64, _>("valid")? != 1 {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::CorruptProjection);
        }
        let item = query_as!(
            LocalItem,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                vault_id as "vault_id",
                path,
                name,
                type_id,
                payload_enc,
                checksum,
                cache_key_fp,
                version as "version",
                deleted_at as "deleted_at",
                updated_at as "updated_at",
                sync_status
            FROM items_cache
            WHERE id = ?1
            "#,
            item_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        if item
            .as_ref()
            .is_some_and(|stored| stored.storage_id != storage_id)
        {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::CorruptProjection);
        }
        tx.commit().await?;
        Ok(item)
    }

    pub async fn list_by_vault(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        include_deleted: bool,
    ) -> Result<Vec<LocalItem>, sqlx_core::Error> {
        if include_deleted {
            query_as!(
                LocalItem,
                r#"
                SELECT
                    id as "id",
                    storage_id as "storage_id",
                    vault_id as "vault_id",
                    path,
                    name,
                    type_id,
                    payload_enc,
                    checksum,
                    cache_key_fp,
                    version as "version",
                    deleted_at as "deleted_at",
                    updated_at as "updated_at",
                    sync_status
                FROM items_cache
                WHERE storage_id = ?1 AND vault_id = ?2
                "#,
                storage_id,
                vault_id
            )
            .fetch_all(self.pool)
            .await
        } else {
            query_as!(
                LocalItem,
                r#"
                SELECT
                    id as "id",
                    storage_id as "storage_id",
                    vault_id as "vault_id",
                    path,
                    name,
                    type_id,
                    payload_enc,
                    checksum,
                    cache_key_fp,
                    version as "version",
                    deleted_at as "deleted_at",
                    updated_at as "updated_at",
                    sync_status
                FROM items_cache
                WHERE storage_id = ?1 AND vault_id = ?2 AND deleted_at IS NULL
                "#,
                storage_id,
                vault_id
            )
            .fetch_all(self.pool)
            .await
        }
    }

    pub async fn list_by_vault_paged(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        include_deleted: bool,
        limit: i64,
        cursor: Option<(DateTime<Utc>, Uuid)>,
    ) -> Result<Vec<LocalItem>, sqlx_core::Error> {
        match (include_deleted, cursor) {
            (true, Some((cursor_ts, cursor_id))) => {
                query_as!(
                    LocalItem,
                    r#"
                    SELECT
                        id as "id",
                        storage_id as "storage_id",
                        vault_id as "vault_id",
                        path,
                        name,
                        type_id,
                        payload_enc,
                        checksum,
                        cache_key_fp,
                        version as "version",
                        deleted_at as "deleted_at",
                        updated_at as "updated_at",
                        sync_status
                    FROM items_cache
                    WHERE storage_id = ?1
                        AND vault_id = ?2
                        AND (
                            updated_at < ?3
                            OR (updated_at = ?3 AND id < ?4)
                        )
                    ORDER BY updated_at DESC, id DESC
                    LIMIT ?5
                    "#,
                    storage_id,
                    vault_id,
                    cursor_ts,
                    cursor_id,
                    limit
                )
                .fetch_all(self.pool)
                .await
            }
            (true, None) => {
                query_as!(
                    LocalItem,
                    r#"
                    SELECT
                        id as "id",
                        storage_id as "storage_id",
                        vault_id as "vault_id",
                        path,
                        name,
                        type_id,
                        payload_enc,
                        checksum,
                        cache_key_fp,
                        version as "version",
                        deleted_at as "deleted_at",
                        updated_at as "updated_at",
                        sync_status
                    FROM items_cache
                    WHERE storage_id = ?1 AND vault_id = ?2
                    ORDER BY updated_at DESC, id DESC
                    LIMIT ?3
                    "#,
                    storage_id,
                    vault_id,
                    limit
                )
                .fetch_all(self.pool)
                .await
            }
            (false, Some((cursor_ts, cursor_id))) => {
                query_as!(
                    LocalItem,
                    r#"
                    SELECT
                        id as "id",
                        storage_id as "storage_id",
                        vault_id as "vault_id",
                        path,
                        name,
                        type_id,
                        payload_enc,
                        checksum,
                        cache_key_fp,
                        version as "version",
                        deleted_at as "deleted_at",
                        updated_at as "updated_at",
                        sync_status
                    FROM items_cache
                    WHERE storage_id = ?1
                        AND vault_id = ?2
                        AND deleted_at IS NULL
                        AND (
                            updated_at < ?3
                            OR (updated_at = ?3 AND id < ?4)
                        )
                    ORDER BY updated_at DESC, id DESC
                    LIMIT ?5
                    "#,
                    storage_id,
                    vault_id,
                    cursor_ts,
                    cursor_id,
                    limit
                )
                .fetch_all(self.pool)
                .await
            }
            (false, None) => {
                query_as!(
                    LocalItem,
                    r#"
                    SELECT
                        id as "id",
                        storage_id as "storage_id",
                        vault_id as "vault_id",
                        path,
                        name,
                        type_id,
                        payload_enc,
                        checksum,
                        cache_key_fp,
                        version as "version",
                        deleted_at as "deleted_at",
                        updated_at as "updated_at",
                        sync_status
                    FROM items_cache
                    WHERE storage_id = ?1 AND vault_id = ?2 AND deleted_at IS NULL
                    ORDER BY updated_at DESC, id DESC
                    LIMIT ?3
                    "#,
                    storage_id,
                    vault_id,
                    limit
                )
                .fetch_all(self.pool)
                .await
            }
        }
    }

    pub async fn list_by_vault_paged_with_query(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        include_deleted: bool,
        query: &str,
        limit: i64,
        cursor: Option<(DateTime<Utc>, Uuid)>,
    ) -> Result<Vec<LocalItem>, sqlx_core::Error> {
        match (include_deleted, cursor) {
            (true, Some((cursor_ts, cursor_id))) => {
                query_as!(
                    LocalItem,
                    r#"
                    SELECT
                        items_cache.id as "id",
                        items_cache.storage_id as "storage_id",
                        items_cache.vault_id as "vault_id",
                        items_cache.path,
                        items_cache.name,
                        items_cache.type_id,
                        items_cache.payload_enc,
                        items_cache.checksum,
                        items_cache.cache_key_fp,
                        items_cache.version as "version",
                        items_cache.deleted_at as "deleted_at",
                        items_cache.updated_at as "updated_at",
                        items_cache.sync_status
                    FROM items_cache
                    JOIN items_cache_fts ON items_cache_fts.rowid = items_cache.rowid
                    WHERE items_cache.storage_id = ?1
                        AND items_cache.vault_id = ?2
                        AND items_cache_fts MATCH ?3
                        AND (
                            items_cache.updated_at < ?4
                            OR (items_cache.updated_at = ?4 AND items_cache.id < ?5)
                        )
                    ORDER BY items_cache.updated_at DESC, items_cache.id DESC
                    LIMIT ?6
                    "#,
                    storage_id,
                    vault_id,
                    query,
                    cursor_ts,
                    cursor_id,
                    limit
                )
                .fetch_all(self.pool)
                .await
            }
            (true, None) => {
                query_as!(
                    LocalItem,
                    r#"
                    SELECT
                        items_cache.id as "id",
                        items_cache.storage_id as "storage_id",
                        items_cache.vault_id as "vault_id",
                        items_cache.path,
                        items_cache.name,
                        items_cache.type_id,
                        items_cache.payload_enc,
                        items_cache.checksum,
                        items_cache.cache_key_fp,
                        items_cache.version as "version",
                        items_cache.deleted_at as "deleted_at",
                        items_cache.updated_at as "updated_at",
                        items_cache.sync_status
                    FROM items_cache
                    JOIN items_cache_fts ON items_cache_fts.rowid = items_cache.rowid
                    WHERE items_cache.storage_id = ?1
                        AND items_cache.vault_id = ?2
                        AND items_cache_fts MATCH ?3
                    ORDER BY items_cache.updated_at DESC, items_cache.id DESC
                    LIMIT ?4
                    "#,
                    storage_id,
                    vault_id,
                    query,
                    limit
                )
                .fetch_all(self.pool)
                .await
            }
            (false, Some((cursor_ts, cursor_id))) => {
                query_as!(
                    LocalItem,
                    r#"
                    SELECT
                        items_cache.id as "id",
                        items_cache.storage_id as "storage_id",
                        items_cache.vault_id as "vault_id",
                        items_cache.path,
                        items_cache.name,
                        items_cache.type_id,
                        items_cache.payload_enc,
                        items_cache.checksum,
                        items_cache.cache_key_fp,
                        items_cache.version as "version",
                        items_cache.deleted_at as "deleted_at",
                        items_cache.updated_at as "updated_at",
                        items_cache.sync_status
                    FROM items_cache
                    JOIN items_cache_fts ON items_cache_fts.rowid = items_cache.rowid
                    WHERE items_cache.storage_id = ?1
                        AND items_cache.vault_id = ?2
                        AND items_cache.deleted_at IS NULL
                        AND items_cache_fts MATCH ?3
                        AND (
                            items_cache.updated_at < ?4
                            OR (items_cache.updated_at = ?4 AND items_cache.id < ?5)
                        )
                    ORDER BY items_cache.updated_at DESC, items_cache.id DESC
                    LIMIT ?6
                    "#,
                    storage_id,
                    vault_id,
                    query,
                    cursor_ts,
                    cursor_id,
                    limit
                )
                .fetch_all(self.pool)
                .await
            }
            (false, None) => {
                query_as!(
                    LocalItem,
                    r#"
                    SELECT
                        items_cache.id as "id",
                        items_cache.storage_id as "storage_id",
                        items_cache.vault_id as "vault_id",
                        items_cache.path,
                        items_cache.name,
                        items_cache.type_id,
                        items_cache.payload_enc,
                        items_cache.checksum,
                        items_cache.cache_key_fp,
                        items_cache.version as "version",
                        items_cache.deleted_at as "deleted_at",
                        items_cache.updated_at as "updated_at",
                        items_cache.sync_status
                    FROM items_cache
                    JOIN items_cache_fts ON items_cache_fts.rowid = items_cache.rowid
                    WHERE items_cache.storage_id = ?1
                        AND items_cache.vault_id = ?2
                        AND items_cache.deleted_at IS NULL
                        AND items_cache_fts MATCH ?3
                    ORDER BY items_cache.updated_at DESC, items_cache.id DESC
                    LIMIT ?4
                    "#,
                    storage_id,
                    vault_id,
                    query,
                    limit
                )
                .fetch_all(self.pool)
                .await
            }
        }
    }

    pub async fn count_by_vault(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
    ) -> Result<i64, sqlx_core::Error> {
        let row = query!(
            r#"
            SELECT COUNT(*) as "count"
            FROM items_cache
            WHERE storage_id = ?1 AND vault_id = ?2 AND deleted_at IS NULL
            "#,
            storage_id,
            vault_id
        )
        .fetch_one(self.pool)
        .await?;
        row.try_get("count")
    }

    pub async fn count_by_vault_all(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        include_deleted: bool,
    ) -> Result<i64, sqlx_core::Error> {
        let row = if include_deleted {
            query!(
                r#"
                SELECT COUNT(*) as "count"
                FROM items_cache
                WHERE storage_id = ?1 AND vault_id = ?2
                "#,
                storage_id,
                vault_id
            )
            .fetch_one(self.pool)
            .await?
        } else {
            query!(
                r#"
                SELECT COUNT(*) as "count"
                FROM items_cache
                WHERE storage_id = ?1 AND vault_id = ?2 AND deleted_at IS NULL
                "#,
                storage_id,
                vault_id
            )
            .fetch_one(self.pool)
            .await?
        };
        row.try_get("count")
    }

    pub async fn count_by_vault_grouped(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
    ) -> Result<Vec<(String, i64)>, sqlx_core::Error> {
        let rows = query!(
            r#"
            SELECT type_id as "type_id", COUNT(*) as "count"
            FROM items_cache
            WHERE storage_id = ?1 AND vault_id = ?2 AND deleted_at IS NULL
            GROUP BY type_id
            "#,
            storage_id,
            vault_id
        )
        .fetch_all(self.pool)
        .await?;
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let type_id: String = row.try_get("type_id")?;
            let count: i64 = row.try_get("count")?;
            result.push((type_id, count));
        }
        Ok(result)
    }

    pub async fn count_deleted_by_vault(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
    ) -> Result<i64, sqlx_core::Error> {
        let row = query!(
            r#"
            SELECT COUNT(*) as "count"
            FROM items_cache
            WHERE storage_id = ?1 AND vault_id = ?2 AND deleted_at IS NOT NULL
            "#,
            storage_id,
            vault_id
        )
        .fetch_one(self.pool)
        .await?;
        row.try_get("count")
    }

    pub async fn count_by_vault_with_query(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        include_deleted: bool,
        query: &str,
    ) -> Result<i64, sqlx_core::Error> {
        let row = if include_deleted {
            query!(
                r#"
                SELECT COUNT(*) as "count"
                FROM items_cache
                JOIN items_cache_fts ON items_cache_fts.rowid = items_cache.rowid
                WHERE items_cache.storage_id = ?1
                    AND items_cache.vault_id = ?2
                    AND items_cache_fts MATCH ?3
                "#,
                storage_id,
                vault_id,
                query
            )
            .fetch_one(self.pool)
            .await?
        } else {
            query!(
                r#"
                SELECT COUNT(*) as "count"
                FROM items_cache
                JOIN items_cache_fts ON items_cache_fts.rowid = items_cache.rowid
                WHERE items_cache.storage_id = ?1
                    AND items_cache.vault_id = ?2
                    AND items_cache.deleted_at IS NULL
                    AND items_cache_fts MATCH ?3
                "#,
                storage_id,
                vault_id,
                query
            )
            .fetch_one(self.pool)
            .await?
        };
        row.try_get("count")
    }

    pub async fn count_by_vault_grouped_with_query(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        query: &str,
    ) -> Result<Vec<(String, i64)>, sqlx_core::Error> {
        let rows = query!(
            r#"
            SELECT items_cache.type_id as "type_id", COUNT(*) as "count"
            FROM items_cache
            JOIN items_cache_fts ON items_cache_fts.rowid = items_cache.rowid
            WHERE items_cache.storage_id = ?1
                AND items_cache.vault_id = ?2
                AND items_cache.deleted_at IS NULL
                AND items_cache_fts MATCH ?3
            GROUP BY items_cache.type_id
            "#,
            storage_id,
            vault_id,
            query
        )
        .fetch_all(self.pool)
        .await?;
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let type_id: String = row.try_get("type_id")?;
            let count: i64 = row.try_get("count")?;
            result.push((type_id, count));
        }
        Ok(result)
    }

    pub async fn count_deleted_by_vault_with_query(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        query: &str,
    ) -> Result<i64, sqlx_core::Error> {
        let row = query!(
            r#"
            SELECT COUNT(*) as "count"
            FROM items_cache
            JOIN items_cache_fts ON items_cache_fts.rowid = items_cache.rowid
            WHERE items_cache.storage_id = ?1
                AND items_cache.vault_id = ?2
                AND items_cache.deleted_at IS NOT NULL
                AND items_cache_fts MATCH ?3
            "#,
            storage_id,
            vault_id,
            query
        )
        .fetch_one(self.pool)
        .await?;
        row.try_get("count")
    }

    pub async fn delete_by_storage(&self, storage_id: Uuid) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"DELETE FROM items_cache WHERE storage_id = ?1"#,
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
            r#"DELETE FROM items_cache WHERE storage_id = ?1 AND vault_id = ?2"#,
            storage_id,
            vault_id
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}
