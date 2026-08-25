use super::prelude::*;
use sqlx_core::transaction::Transaction;
use sqlx_postgres::Postgres;
use tracing::{instrument, Span};

const MAX_EAGER_ROWS: i64 = 120;
const MAX_EAGER_PAYLOAD_BYTES: i32 = 256 * 1024 + 256;

fn bounded_eager_limit(limit: i64) -> i64 {
    limit.clamp(1, MAX_EAGER_ROWS)
}

pub struct ItemRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> ItemRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    #[instrument(
        level = "debug",
        skip(self, item),
        fields(
            item_id = %item.id,
            vault_id = %item.vault_id,
            db.system = "postgresql",
            db.operation = "INSERT",
            db.query = "items.create"
        )
    )]
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
            item.sync_status.as_i32(),
            item.deleted_at,
            item.deleted_by_user_id,
            item.deleted_by_device_id,
            item.created_at,
            item.updated_at
        )
        .execute(self.pool)
        .await
        .map(|result| {
            Span::current().record("db.rows", result.rows_affected() as i64);
        })
    }

    pub async fn create_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        item: &Item,
    ) -> Result<(), sqlx_core::Error> {
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
            item.sync_status.as_i32(),
            item.deleted_at,
            item.deleted_by_user_id,
            item.deleted_by_device_id,
            item.created_at,
            item.updated_at
        )
        .execute(&mut **tx)
        .await
        .map(|result| {
            Span::current().record("db.rows", result.rows_affected() as i64);
        })
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(item_id = %id, db.system = "postgresql", db.operation = "SELECT", db.query = "items.get_by_id")
    )]
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

    /// Loads and locks the aggregate root until the surrounding transaction
    /// finishes. All server-side item writers must use this before deriving a
    /// new generation from the current row.
    pub async fn get_by_id_for_update_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
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
            WHERE id = $1
            FOR UPDATE
            "#,
            id
        )
        .fetch_optional(&mut **tx)
        .await
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(vault_id = %vault_id, path, db.system = "postgresql", db.operation = "SELECT", db.query = "items.get_by_vault_path")
    )]
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

    #[instrument(
        level = "debug",
        skip(self),
        fields(vault_id = %vault_id, include_deleted, limit, db.system = "postgresql", db.operation = "SELECT", db.query = "items.list_by_vault_bounded")
    )]
    pub async fn list_by_vault_bounded(
        &self,
        vault_id: Uuid,
        include_deleted: bool,
        limit: i64,
    ) -> Result<Vec<Item>, sqlx_core::Error> {
        let limit = bounded_eager_limit(limit);
        let where_clause = if include_deleted {
            "WHERE vault_id = $1 AND octet_length(payload_enc) <= $3"
        } else {
            "WHERE vault_id = $1 AND sync_status = 1 AND octet_length(payload_enc) <= $3"
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
            LIMIT $2
            "#,
            where_clause = where_clause
        );
        let items = query_as!(Item, &query, vault_id, limit, MAX_EAGER_PAYLOAD_BYTES)
            .fetch_all(self.pool)
            .await?;
        Span::current().record("db.rows", items.len() as i64);
        Ok(items)
    }

    /// Returns a bounded eager export page from the caller's stable snapshot.
    /// The hard repository cap prevents an excessive caller-supplied limit.
    pub async fn list_by_vault_bounded_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        vault_id: Uuid,
        include_deleted: bool,
        limit: i64,
    ) -> Result<Vec<Item>, sqlx_core::Error> {
        let limit = bounded_eager_limit(limit);
        let where_clause = if include_deleted {
            "WHERE vault_id = $1 AND octet_length(payload_enc) <= $3"
        } else {
            "WHERE vault_id = $1 AND sync_status = 1 AND octet_length(payload_enc) <= $3"
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
            LIMIT $2
            "#,
            where_clause = where_clause
        );
        let items = query_as!(Item, &query, vault_id, limit, MAX_EAGER_PAYLOAD_BYTES)
            .fetch_all(&mut **tx)
            .await?;
        Span::current().record("db.rows", items.len() as i64);
        Ok(items)
    }

    /// Counts rows and their variable-size source material without fetching
    /// payloads. Export callers pair this with `list_by_vault_bounded_in` in a
    /// repeatable-read transaction, proving the aggregate budget before any
    /// plaintext is decrypted or serialized.
    pub async fn export_budget_by_vault_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        vault_id: Uuid,
        include_deleted: bool,
    ) -> Result<(i64, i64), sqlx_core::Error> {
        let row = query!(
            r#"
            SELECT
                COUNT(*)::bigint AS item_count,
                COALESCE(
                    SUM(
                        octet_length(payload_enc)::bigint
                        + octet_length(path)::bigint
                        + octet_length(name)::bigint
                        + octet_length(type_id)::bigint
                        + octet_length(checksum)::bigint
                        + COALESCE(octet_length(tags::text), 0)::bigint
                    ),
                    0
                )::bigint AS source_bytes
            FROM items
            WHERE vault_id = $1
              AND ($2 OR sync_status = 1)
            "#,
            vault_id,
            include_deleted
        )
        .fetch_one(&mut **tx)
        .await?;
        Ok((row.try_get("item_count")?, row.try_get("source_bytes")?))
    }

    #[instrument(
        level = "debug",
        skip(self, item),
        fields(
            item_id = %item.id,
            vault_id = %item.vault_id,
            db.system = "postgresql",
            db.operation = "UPDATE",
            db.query = "items.update"
        )
    )]
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
            item.sync_status.as_i32(),
            item.deleted_at,
            item.deleted_by_user_id,
            item.deleted_by_device_id,
            item.updated_at,
            item.row_version
        )
        .execute(self.pool)
        .await
        .map(|result| {
            let rows = result.rows_affected();
            Span::current().record("db.rows", rows as i64);
            rows
        })
    }

    pub async fn update_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        item: &Item,
    ) -> Result<u64, sqlx_core::Error> {
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
            item.sync_status.as_i32(),
            item.deleted_at,
            item.deleted_by_user_id,
            item.deleted_by_device_id,
            item.updated_at,
            item.row_version
        )
        .execute(&mut **tx)
        .await
        .map(|result| {
            let rows = result.rows_affected();
            Span::current().record("db.rows", rows as i64);
            rows
        })
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

    #[instrument(
        level = "debug",
        skip(self, history),
        fields(
            history_id = %history.id,
            item_id = %history.item_id,
            db.system = "postgresql",
            db.operation = "INSERT",
            db.query = "item_history.create"
        )
    )]
    pub async fn create(&self, history: &ItemHistory) -> Result<(), sqlx_core::Error> {
        let result = query!(
            r#"
            INSERT INTO item_history AS existing (
                id, item_id, payload_enc, checksum, version, change_type, fields_changed,
                changed_by_user_id, changed_by_email, changed_by_name, changed_by_device_id,
                changed_by_device_name, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (item_id, version) DO UPDATE
            SET item_id = existing.item_id
            WHERE existing.payload_enc IS NOT DISTINCT FROM excluded.payload_enc
              AND existing.checksum IS NOT DISTINCT FROM excluded.checksum
            "#,
            history.id,
            history.item_id,
            &history.payload_enc,
            history.checksum.as_str(),
            history.version,
            history.change_type.as_i32(),
            history.fields_changed.as_ref(),
            history.changed_by_user_id,
            history.changed_by_email.as_str(),
            history.changed_by_name.as_deref(),
            history.changed_by_device_id,
            history.changed_by_device_name.as_deref(),
            history.created_at
        )
        .execute(self.pool)
        .await?;
        Span::current().record("db.rows", result.rows_affected() as i64);
        if result.rows_affected() == 0 {
            return Err(conflicting_history_generation_error());
        }
        Ok(())
    }

    pub async fn create_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        history: &ItemHistory,
    ) -> Result<(), sqlx_core::Error> {
        let result = query!(
            r#"
            INSERT INTO item_history AS existing (
                id, item_id, payload_enc, checksum, version, change_type, fields_changed,
                changed_by_user_id, changed_by_email, changed_by_name, changed_by_device_id,
                changed_by_device_name, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (item_id, version) DO UPDATE
            SET item_id = existing.item_id
            WHERE existing.payload_enc IS NOT DISTINCT FROM excluded.payload_enc
              AND existing.checksum IS NOT DISTINCT FROM excluded.checksum
            "#,
            history.id,
            history.item_id,
            &history.payload_enc,
            history.checksum.as_str(),
            history.version,
            history.change_type.as_i32(),
            history.fields_changed.as_ref(),
            history.changed_by_user_id,
            history.changed_by_email.as_str(),
            history.changed_by_name.as_deref(),
            history.changed_by_device_id,
            history.changed_by_device_name.as_deref(),
            history.created_at
        )
        .execute(&mut **tx)
        .await?;
        Span::current().record("db.rows", result.rows_affected() as i64);
        if result.rows_affected() == 0 {
            return Err(conflicting_history_generation_error());
        }
        Ok(())
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(history_id = %id, db.system = "postgresql", db.operation = "SELECT", db.query = "item_history.get_by_id")
    )]
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

    #[instrument(
        level = "debug",
        skip(self),
        fields(item_id = %item_id, limit, db.system = "postgresql", db.operation = "SELECT", db.query = "item_history.list_by_item_limit")
    )]
    pub async fn list_by_item_limit(
        &self,
        item_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ItemHistory>, sqlx_core::Error> {
        let limit = bounded_eager_limit(limit);
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
              AND octet_length(payload_enc) <= $3
            ORDER BY version DESC
            LIMIT $2
            "#,
            item_id,
            limit,
            MAX_EAGER_PAYLOAD_BYTES
        )
        .fetch_all(self.pool)
        .await
        .inspect(|history| {
            Span::current().record("db.rows", history.len() as i64);
        })
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(item_id = %item_id, version, db.system = "postgresql", db.operation = "SELECT", db.query = "item_history.get_by_item_version")
    )]
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

    pub async fn get_by_item_version_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
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
        .fetch_optional(&mut **tx)
        .await
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(item_id = %item_id, keep, db.system = "postgresql", db.operation = "DELETE", db.query = "item_history.prune_by_item")
    )]
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
        .map(|result| {
            let rows = result.rows_affected();
            Span::current().record("db.rows", rows as i64);
            rows
        })
    }

    pub async fn prune_by_item_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        item_id: Uuid,
        keep: i64,
    ) -> Result<u64, sqlx_core::Error> {
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
        .execute(&mut **tx)
        .await
        .map(|result| {
            let rows = result.rows_affected();
            Span::current().record("db.rows", rows as i64);
            rows
        })
    }
}

pub struct AttachmentRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> AttachmentRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    #[instrument(
        level = "debug",
        skip(self, attachment),
        fields(
            attachment_id = %attachment.id,
            item_id = %attachment.item_id,
            db.system = "postgresql",
            db.operation = "INSERT",
            db.query = "attachments.create"
        )
    )]
    pub async fn create(&self, attachment: &Attachment) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO attachments (
                id, item_id, filename, size, mime_type, enc_mode, content_enc, checksum, storage_url,
                created_at, deleted_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            attachment.id,
            attachment.item_id,
            attachment.filename.as_str(),
            attachment.size,
            attachment.mime_type.as_str(),
            attachment.enc_mode.as_str(),
            &attachment.content_enc,
            attachment.checksum.as_str(),
            attachment.storage_url.as_deref(),
            attachment.created_at,
            attachment.deleted_at
        )
        .execute(self.pool)
        .await
        .map(|result| {
            Span::current().record("db.rows", result.rows_affected() as i64);
        })
    }

    pub async fn create_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        attachment: &Attachment,
    ) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO attachments (
                id, item_id, filename, size, mime_type, enc_mode, content_enc, checksum, storage_url,
                created_at, deleted_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            attachment.id,
            attachment.item_id,
            attachment.filename.as_str(),
            attachment.size,
            attachment.mime_type.as_str(),
            attachment.enc_mode.as_str(),
            &attachment.content_enc,
            attachment.checksum.as_str(),
            attachment.storage_url.as_deref(),
            attachment.created_at,
            attachment.deleted_at
        )
        .execute(&mut **tx)
        .await
        .map(|result| {
            Span::current().record("db.rows", result.rows_affected() as i64);
        })
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(attachment_id = %id, db.system = "postgresql", db.operation = "SELECT", db.query = "attachments.get_by_id")
    )]
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
                enc_mode,
                content_enc,
                checksum,
                storage_url,
                created_at as "created_at",
                deleted_at as "deleted_at"
            FROM attachments
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(item_id = %item_id, db.system = "postgresql", db.operation = "UPDATE", db.query = "attachments.mark_deleted_by_item")
    )]
    pub async fn mark_deleted_by_item(
        &self,
        item_id: Uuid,
        deleted_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE attachments
            SET deleted_at = $2
            WHERE item_id = $1 AND deleted_at IS NULL
            "#,
            item_id,
            deleted_at
        )
        .execute(self.pool)
        .await
        .map(|result| {
            let rows = result.rows_affected();
            Span::current().record("db.rows", rows as i64);
            rows
        })
    }

    pub async fn mark_deleted_by_item_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        item_id: Uuid,
        deleted_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE attachments
            SET deleted_at = $2
            WHERE item_id = $1 AND deleted_at IS NULL
            "#,
            item_id,
            deleted_at
        )
        .execute(&mut **tx)
        .await
        .map(|result| {
            let rows = result.rows_affected();
            Span::current().record("db.rows", rows as i64);
            rows
        })
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(item_id = %item_id, db.system = "postgresql", db.operation = "UPDATE", db.query = "attachments.clear_deleted_by_item")
    )]
    pub async fn clear_deleted_by_item(&self, item_id: Uuid) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE attachments
            SET deleted_at = NULL
            WHERE item_id = $1
            "#,
            item_id
        )
        .execute(self.pool)
        .await
        .map(|result| {
            let rows = result.rows_affected();
            Span::current().record("db.rows", rows as i64);
            rows
        })
    }

    pub async fn clear_deleted_by_item_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        item_id: Uuid,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE attachments
            SET deleted_at = NULL
            WHERE item_id = $1
            "#,
            item_id
        )
        .execute(&mut **tx)
        .await
        .map(|result| {
            let rows = result.rows_affected();
            Span::current().record("db.rows", rows as i64);
            rows
        })
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(db.system = "postgresql", db.operation = "DELETE", db.query = "attachments.purge_deleted_before")
    )]
    pub async fn purge_deleted_before(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            DELETE FROM attachments
            WHERE deleted_at IS NOT NULL AND deleted_at < $1
            "#,
            cutoff
        )
        .execute(self.pool)
        .await
        .map(|result| {
            let rows = result.rows_affected();
            Span::current().record("db.rows", rows as i64);
            rows
        })
    }
}

fn conflicting_history_generation_error() -> sqlx_core::Error {
    sqlx_core::Error::Protocol("conflicting item history generation payload".to_string())
}
