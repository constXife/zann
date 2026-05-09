use uuid::Uuid;

use crate::local::{HistorySyncStatus, LocalItemHistory};

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
                source,
                sync_status,
                created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            "#,
            history.id,
            history.storage_id,
            history.vault_id,
            history.item_id,
            &history.payload_enc,
            history.checksum.clone(),
            history.version,
            history.change_type.as_i32(),
            history.changed_by_email.clone(),
            history.changed_by_name.clone(),
            history.changed_by_device_id,
            history.changed_by_device_name.clone(),
            history.source.as_i32(),
            history.sync_status.as_i32(),
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
                source as "source",
                sync_status as "sync_status",
                created_at as "created_at"
            FROM item_history
            WHERE storage_id = ?1 AND item_id = ?2
            ORDER BY sync_status ASC, version DESC, created_at DESC
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
                source as "source",
                sync_status as "sync_status",
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
                    source,
                    sync_status,
                    created_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                "#,
                entry.id,
                entry.storage_id,
                entry.vault_id,
                entry.item_id,
                &entry.payload_enc,
                entry.checksum.clone(),
                entry.version,
                entry.change_type.as_i32(),
                entry.changed_by_email.clone(),
                entry.changed_by_name.clone(),
                entry.changed_by_device_id,
                entry.changed_by_device_name.clone(),
                entry.source.as_i32(),
                entry.sync_status.as_i32(),
                entry.created_at
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await
    }

    pub async fn merge_by_item(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
        history: &[LocalItemHistory],
        keep: i64,
    ) -> Result<(), sqlx_core::Error> {
        let pending = HistorySyncStatus::Pending.as_i32();
        let confirmed = HistorySyncStatus::Confirmed.as_i32();
        let mut tx = self.pool.begin().await?;

        for entry in history {
            let updated = query!(
                r#"
                UPDATE item_history
                SET
                    payload_enc = ?1,
                    checksum = ?2,
                    version = ?3,
                    change_type = ?4,
                    changed_by_email = ?5,
                    changed_by_name = ?6,
                    changed_by_device_id = ?7,
                    changed_by_device_name = ?8,
                    source = ?9,
                    sync_status = ?10,
                    created_at = ?11
                WHERE storage_id = ?12
                  AND item_id = ?13
                  AND version = ?14
                  AND sync_status = ?15
                "#,
                &entry.payload_enc,
                entry.checksum.clone(),
                entry.version,
                entry.change_type.as_i32(),
                entry.changed_by_email.clone(),
                entry.changed_by_name.clone(),
                entry.changed_by_device_id,
                entry.changed_by_device_name.clone(),
                entry.source.as_i32(),
                entry.sync_status.as_i32(),
                entry.created_at,
                storage_id,
                item_id,
                entry.version,
                pending
            )
            .execute(&mut *tx)
            .await?
            .rows_affected();

            if updated == 0 {
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
                        source,
                        sync_status,
                        created_at
                    )
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                    "#,
                    entry.id,
                    entry.storage_id,
                    entry.vault_id,
                    entry.item_id,
                    &entry.payload_enc,
                    entry.checksum.clone(),
                    entry.version,
                    entry.change_type.as_i32(),
                    entry.changed_by_email.clone(),
                    entry.changed_by_name.clone(),
                    entry.changed_by_device_id,
                    entry.changed_by_device_name.clone(),
                    entry.source.as_i32(),
                    entry.sync_status.as_i32(),
                    entry.created_at
                )
                .execute(&mut *tx)
                .await?;
            }
        }

        query!(
            r#"
            DELETE FROM item_history
            WHERE id IN (
                SELECT id
                FROM item_history
                WHERE storage_id = ?1 AND item_id = ?2 AND sync_status = ?3
                ORDER BY version DESC
                LIMIT -1 OFFSET ?4
            )
            "#,
            storage_id,
            item_id,
            confirmed,
            keep
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await
    }

    pub async fn prune_by_item(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
        keep: i64,
    ) -> Result<u64, sqlx_core::Error> {
        let confirmed = HistorySyncStatus::Confirmed.as_i32();
        query!(
            r#"
            DELETE FROM item_history
            WHERE id IN (
                SELECT id
                FROM item_history
                WHERE storage_id = ?1 AND item_id = ?2 AND sync_status = ?3
                ORDER BY version DESC
                LIMIT -1 OFFSET ?4
            )
            "#,
            storage_id,
            item_id,
            confirmed,
            keep
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}
