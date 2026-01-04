use super::prelude::*;

pub struct ItemRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> ItemRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, item: &Item) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO items (
                id, vault_id, path, name, type_id, tags, favorite, payload_enc, checksum,
                version, row_version, device_id, sync_status, deleted_at, deleted_by_user_id,
                deleted_by_device_id, created_at, updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9,
                $10, $11, $12, $13, $14, $15, $16, $17, $18
            )
            "#,
            item.id,
            item.vault_id,
            item.path.as_str(),
            item.name.as_str(),
            item.type_id.as_str(),
            item.tags.as_ref(),
            item.favorite,
            &item.payload_enc,
            item.checksum.as_str(),
            item.version,
            item.row_version,
            item.device_id,
            item.sync_status.as_str(),
            item.deleted_at,
            item.deleted_by_user_id,
            item.deleted_by_device_id,
            item.created_at,
            item.updated_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<Item>, sqlx_core::Error> {
        query_as!(
            Item,
            r#"
            SELECT
                id as "id",
                vault_id as "vault_id",
                path,
                name,
                type_id,
                tags as "tags",
                favorite as "favorite",
                payload_enc,
                checksum,
                version as "version",
                row_version as "row_version",
                device_id as "device_id",
                sync_status as "sync_status",
                deleted_at as "deleted_at",
                deleted_by_user_id as "deleted_by_user_id",
                deleted_by_device_id as "deleted_by_device_id",
                created_at as "created_at",
                updated_at as "updated_at"
            FROM items
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn get_by_vault_path(
        &self,
        vault_id: Uuid,
        path: &str,
    ) -> Result<Option<Item>, sqlx_core::Error> {
        query_as!(
            Item,
            r#"
            SELECT
                id as "id",
                vault_id as "vault_id",
                path,
                name,
                type_id,
                tags as "tags",
                favorite as "favorite",
                payload_enc,
                checksum,
                version as "version",
                row_version as "row_version",
                device_id as "device_id",
                sync_status as "sync_status",
                deleted_at as "deleted_at",
                deleted_by_user_id as "deleted_by_user_id",
                deleted_by_device_id as "deleted_by_device_id",
                created_at as "created_at",
                updated_at as "updated_at"
            FROM items
            WHERE vault_id = $1 AND path = $2
            "#,
            vault_id,
            path
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn list_by_vault(
        &self,
        vault_id: Uuid,
        include_deleted: bool,
    ) -> Result<Vec<Item>, sqlx_core::Error> {
        let where_clause = if include_deleted {
            "WHERE vault_id = $1"
        } else {
            "WHERE vault_id = $1 AND sync_status = 'active'"
        };
        let query = format!(
            r#"
            SELECT
                id as "id",
                vault_id as "vault_id",
                path,
                name,
                type_id,
                tags as "tags",
                favorite as "favorite",
                payload_enc,
                checksum,
                version as "version",
                row_version as "row_version",
                device_id as "device_id",
                sync_status as "sync_status",
                deleted_at as "deleted_at",
                deleted_by_user_id as "deleted_by_user_id",
                deleted_by_device_id as "deleted_by_device_id",
                created_at as "created_at",
                updated_at as "updated_at"
            FROM items
            {where_clause}
            ORDER BY updated_at DESC
            "#,
            where_clause = where_clause
        );
        query_as!(Item, &query, vault_id).fetch_all(self.pool).await
    }

    pub async fn update(&self, item: &Item) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE items
            SET path = $2,
                name = $3,
                type_id = $4,
                tags = $5,
                favorite = $6,
                payload_enc = $7,
                checksum = $8,
                version = $9,
                row_version = row_version + 1,
                device_id = $10,
                sync_status = $11,
                deleted_at = $12,
                deleted_by_user_id = $13,
                deleted_by_device_id = $14,
                updated_at = $15
            WHERE id = $1 AND row_version = $16
            "#,
            item.id,
            item.path.as_str(),
            item.name.as_str(),
            item.type_id.as_str(),
            item.tags.as_ref(),
            item.favorite,
            &item.payload_enc,
            item.checksum.as_str(),
            item.version,
            item.device_id,
            item.sync_status.as_str(),
            item.deleted_at,
            item.deleted_by_user_id,
            item.deleted_by_device_id,
            item.updated_at,
            item.row_version
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}

pub struct ItemUsageRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> ItemUsageRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn upsert_batch(&self, records: Vec<ItemUsage>) -> Result<(), sqlx_core::Error> {
        if records.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for record in records {
            query!(
                r#"
                INSERT INTO item_usage (
                    item_id, last_read_at, last_read_by_user_id, last_read_by_device_id, read_count
                )
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT(item_id) DO UPDATE SET
                    last_read_at = excluded.last_read_at,
                    last_read_by_user_id = excluded.last_read_by_user_id,
                    last_read_by_device_id = excluded.last_read_by_device_id,
                    read_count = item_usage.read_count + excluded.read_count
                "#,
                record.item_id,
                record.last_read_at,
                record.last_read_by_user_id,
                record.last_read_by_device_id,
                record.read_count
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await
    }
}

pub struct ItemHistoryRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> ItemHistoryRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, history: &ItemHistory) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO item_history (
                id, item_id, payload_enc, checksum, version, change_type, fields_changed,
                changed_by_user_id, changed_by_email, changed_by_name, changed_by_device_id,
                changed_by_device_name, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
            history.id,
            history.item_id,
            &history.payload_enc,
            history.checksum.as_str(),
            history.version,
            history.change_type.as_str(),
            history.fields_changed.as_ref(),
            history.changed_by_user_id,
            history.changed_by_email.as_str(),
            history.changed_by_name.as_deref(),
            history.changed_by_device_id,
            history.changed_by_device_name.as_deref(),
            history.created_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<ItemHistory>, sqlx_core::Error> {
        query_as!(
            ItemHistory,
            r#"
            SELECT
                id as "id",
                item_id as "item_id",
                payload_enc,
                checksum,
                version as "version",
                change_type as "change_type",
                fields_changed as "fields_changed",
                changed_by_user_id as "changed_by_user_id",
                changed_by_email as "changed_by_email",
                changed_by_name as "changed_by_name",
                changed_by_device_id as "changed_by_device_id",
                changed_by_device_name as "changed_by_device_name",
                created_at as "created_at"
            FROM item_history
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn list_by_item(&self, item_id: Uuid) -> Result<Vec<ItemHistory>, sqlx_core::Error> {
        query_as!(
            ItemHistory,
            r#"
            SELECT
                id as "id",
                item_id as "item_id",
                payload_enc,
                checksum,
                version as "version",
                change_type as "change_type",
                fields_changed as "fields_changed",
                changed_by_user_id as "changed_by_user_id",
                changed_by_email as "changed_by_email",
                changed_by_name as "changed_by_name",
                changed_by_device_id as "changed_by_device_id",
                changed_by_device_name as "changed_by_device_name",
                created_at as "created_at"
            FROM item_history
            WHERE item_id = $1
            ORDER BY version DESC
            "#,
            item_id
        )
        .fetch_all(self.pool)
        .await
    }

    pub async fn list_by_item_limit(
        &self,
        item_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ItemHistory>, sqlx_core::Error> {
        query_as!(
            ItemHistory,
            r#"
            SELECT
                id as "id",
                item_id as "item_id",
                payload_enc,
                checksum,
                version as "version",
                change_type as "change_type",
                fields_changed as "fields_changed",
                changed_by_user_id as "changed_by_user_id",
                changed_by_email as "changed_by_email",
                changed_by_name as "changed_by_name",
                changed_by_device_id as "changed_by_device_id",
                changed_by_device_name as "changed_by_device_name",
                created_at as "created_at"
            FROM item_history
            WHERE item_id = $1
            ORDER BY version DESC
            LIMIT $2
            "#,
            item_id,
            limit
        )
        .fetch_all(self.pool)
        .await
    }

    pub async fn get_by_item_version(
        &self,
        item_id: Uuid,
        version: i64,
    ) -> Result<Option<ItemHistory>, sqlx_core::Error> {
        query_as!(
            ItemHistory,
            r#"
            SELECT
                id as "id",
                item_id as "item_id",
                payload_enc,
                checksum,
                version as "version",
                change_type as "change_type",
                fields_changed as "fields_changed",
                changed_by_user_id as "changed_by_user_id",
                changed_by_email as "changed_by_email",
                changed_by_name as "changed_by_name",
                changed_by_device_id as "changed_by_device_id",
                changed_by_device_name as "changed_by_device_name",
                created_at as "created_at"
            FROM item_history
            WHERE item_id = $1 AND version = $2
            "#,
            item_id,
            version
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn prune_by_item(&self, item_id: Uuid, keep: i64) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            DELETE FROM item_history
            WHERE id IN (
                SELECT id
                FROM item_history
                WHERE item_id = $1
                ORDER BY version DESC
                OFFSET $2
            )
            "#,
            item_id,
            keep
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}

pub struct AttachmentRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> AttachmentRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, attachment: &Attachment) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO attachments (
                id, item_id, filename, size, mime_type, content_enc, checksum, storage_url, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            attachment.id,
            attachment.item_id,
            attachment.filename.as_str(),
            attachment.size,
            attachment.mime_type.as_str(),
            &attachment.content_enc,
            attachment.checksum.as_str(),
            attachment.storage_url.as_deref(),
            attachment.created_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<Attachment>, sqlx_core::Error> {
        query_as!(
            Attachment,
            r#"
            SELECT
                id as "id",
                item_id as "item_id",
                filename,
                size as "size",
                mime_type,
                content_enc,
                checksum,
                storage_url,
                created_at as "created_at"
            FROM attachments
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn list_by_item(&self, item_id: Uuid) -> Result<Vec<Attachment>, sqlx_core::Error> {
        query_as!(
            Attachment,
            r#"
            SELECT
                id as "id",
                item_id as "item_id",
                filename,
                size as "size",
                mime_type,
                content_enc,
                checksum,
                storage_url,
                created_at as "created_at"
            FROM attachments
            WHERE item_id = $1
            "#,
            item_id
        )
        .fetch_all(self.pool)
        .await
    }
}

pub struct ItemConflictRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> ItemConflictRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, conflict: &ItemConflict) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO item_conflicts (
                id, item_id, vault_id, losing_version, losing_device_id, losing_payload_enc,
                created_at, resolved_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            conflict.id,
            conflict.item_id,
            conflict.vault_id,
            conflict.losing_version,
            conflict.losing_device_id,
            &conflict.losing_payload_enc,
            conflict.created_at,
            conflict.resolved_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<ItemConflict>, sqlx_core::Error> {
        query_as!(
            ItemConflict,
            r#"
            SELECT
                id as "id",
                item_id as "item_id",
                vault_id as "vault_id",
                losing_version as "losing_version",
                losing_device_id as "losing_device_id",
                losing_payload_enc,
                created_at as "created_at",
                resolved_at as "resolved_at"
            FROM item_conflicts
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn list_by_vault(
        &self,
        vault_id: Uuid,
    ) -> Result<Vec<ItemConflict>, sqlx_core::Error> {
        query_as!(
            ItemConflict,
            r#"
            SELECT
                id as "id",
                item_id as "item_id",
                vault_id as "vault_id",
                losing_version as "losing_version",
                losing_device_id as "losing_device_id",
                losing_payload_enc,
                created_at as "created_at",
                resolved_at as "resolved_at"
            FROM item_conflicts
            WHERE vault_id = $1
            "#,
            vault_id
        )
        .fetch_all(self.pool)
        .await
    }
}
