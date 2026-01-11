use uuid::Uuid;

use crate::local::LocalItemHistory;

pub struct LocalItemHistoryRepo<'a> {
    pool: &'a sqlx_sqlite::SqlitePool,
}

impl<'a> LocalItemHistoryRepo<'a> {
    pub fn new(pool: &'a sqlx_sqlite::SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, history: &LocalItemHistory) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO item_history (
                id,
                storage_id,
                vault_id,
                item_id,
                payload_enc,
                checksum,
                version,
                change_type,
                changed_by_email,
                changed_by_name,
                changed_by_device_id,
                changed_by_device_name,
                created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            history.id,
            history.storage_id,
            history.vault_id,
            history.item_id,
            &history.payload_enc,
            history.checksum.clone(),
            history.version,
            history.change_type.clone(),
            history.changed_by_email.clone(),
            history.changed_by_name.clone(),
            history.changed_by_device_id,
            history.changed_by_device_name.clone(),
            history.created_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn list_by_item_limit(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
        limit: i64,
    ) -> Result<Vec<LocalItemHistory>, sqlx_core::Error> {
        query_as!(
            LocalItemHistory,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                vault_id as "vault_id",
                item_id as "item_id",
                payload_enc,
                checksum,
                version as "version",
                change_type as "change_type",
                changed_by_email as "changed_by_email",
                changed_by_name as "changed_by_name",
                changed_by_device_id as "changed_by_device_id",
                changed_by_device_name as "changed_by_device_name",
                created_at as "created_at"
            FROM item_history
            WHERE storage_id = ?1 AND item_id = ?2
            ORDER BY version DESC
            LIMIT ?3
            "#,
            storage_id,
            item_id,
            limit
        )
        .fetch_all(self.pool)
        .await
    }

    pub async fn get_by_item_version(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
        version: i64,
    ) -> Result<Option<LocalItemHistory>, sqlx_core::Error> {
        query_as!(
            LocalItemHistory,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                vault_id as "vault_id",
                item_id as "item_id",
                payload_enc,
                checksum,
                version as "version",
                change_type as "change_type",
                changed_by_email as "changed_by_email",
                changed_by_name as "changed_by_name",
                changed_by_device_id as "changed_by_device_id",
                changed_by_device_name as "changed_by_device_name",
                created_at as "created_at"
            FROM item_history
            WHERE storage_id = ?1 AND item_id = ?2 AND version = ?3
            "#,
            storage_id,
            item_id,
            version
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn delete_by_item(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            DELETE FROM item_history
            WHERE storage_id = ?1 AND item_id = ?2
            "#,
            storage_id,
            item_id
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn replace_by_item(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
        history: &[LocalItemHistory],
    ) -> Result<(), sqlx_core::Error> {
        let mut tx = self.pool.begin().await?;
        query!(
            r#"
            DELETE FROM item_history
            WHERE storage_id = ?1 AND item_id = ?2
            "#,
            storage_id,
            item_id
        )
        .execute(&mut *tx)
        .await?;

        for entry in history {
            query!(
                r#"
                INSERT INTO item_history (
                    id,
                    storage_id,
                    vault_id,
                    item_id,
                    payload_enc,
                    checksum,
                    version,
                    change_type,
                    changed_by_email,
                    changed_by_name,
                    changed_by_device_id,
                    changed_by_device_name,
                    created_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                "#,
                entry.id,
                entry.storage_id,
                entry.vault_id,
                entry.item_id,
                &entry.payload_enc,
                entry.checksum.clone(),
                entry.version,
                entry.change_type.clone(),
                entry.changed_by_email.clone(),
                entry.changed_by_name.clone(),
                entry.changed_by_device_id,
                entry.changed_by_device_name.clone(),
                entry.created_at
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await
    }

    pub async fn prune_by_item(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
        keep: i64,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            DELETE FROM item_history
            WHERE id IN (
                SELECT id
                FROM item_history
                WHERE storage_id = ?1 AND item_id = ?2
                ORDER BY version DESC
                OFFSET ?3
            )
            "#,
            storage_id,
            item_id,
            keep
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}
