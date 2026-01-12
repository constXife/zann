use chrono::{DateTime, Utc};
use sqlx_core::row::Row;
use uuid::Uuid;

use crate::local::LocalItem;
use crate::SqlitePool;

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
