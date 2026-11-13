use async_trait::async_trait;

use zann_core::{AppService, AppStatus, ServiceError, ServiceResult, StoragesService};

use crate::local::MetadataRepo;

use super::LocalServices;

#[async_trait]
impl<'a> AppService for LocalServices<'a> {
    async fn status(&self, locked: bool) -> ServiceResult<AppStatus> {
        let meta = MetadataRepo::new(self.pool);
        let initialized = meta
            .get_value("initialized")
            .await
            .map_err(|err| ServiceError::new("metadata_read_failed", err.to_string()))?
            .map(|value| value == "true")
            .unwrap_or(false);
        let storages_count = self.list_storages().await?.len();
        Ok(AppStatus {
            initialized,
            locked,
            storages_count,
        })
    }

    async fn initialize_master_password(&self) -> ServiceResult<()> {
        use sqlx_core::row::Row;
        use sqlx_sqlite::Sqlite;

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| ServiceError::new("tx_begin_failed", err.to_string()))?;

        let initialized = sqlx_core::query::query::<Sqlite>(
            r#"
            SELECT value
            FROM metadata
            WHERE key = 'initialized'
            "#,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| ServiceError::new("metadata_read_failed", err.to_string()))?
        .and_then(|row| row.try_get::<String, _>("value").ok())
        .map(|value| value == "true")
        .unwrap_or(false);

        if initialized {
            return Err(ServiceError::new(
                "already_initialized",
                "already initialized",
            ));
        }

        sqlx_core::query::query::<Sqlite>(
            r#"
            INSERT INTO metadata (key, value)
            VALUES ('initialized', 'true')
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            "#,
        )
        .execute(&mut *tx)
        .await
        .map_err(|err| ServiceError::new("metadata_write_failed", err.to_string()))?;

        tx.commit()
            .await
            .map_err(|err| ServiceError::new("tx_commit_failed", err.to_string()))?;
        Ok(())
    }
}
