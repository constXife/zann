use async_trait::async_trait;
use uuid::Uuid;

use zann_crypto::crypto::SecretKey;
use zann_crypto::vault_crypto as core_crypto;
use zann_core::{
    AppService, AppStatus, ServiceError, ServiceResult, StoragesService, VaultsService,
};

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
        let has_local_vault = self
            .list_vaults(Uuid::nil())
            .await
            .map(|vaults| !vaults.is_empty())
            .unwrap_or(false);
        Ok(AppStatus {
            initialized,
            locked,
            storages_count,
            has_local_vault,
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

        let storage_id = Uuid::nil();
        sqlx_core::query::query::<Sqlite>(
            r#"
            INSERT INTO storages (id, kind, name)
            VALUES (?1, 1, 'Local')
            ON CONFLICT(id) DO UPDATE SET kind = 1, name = 'Local'
            "#,
        )
        .bind(storage_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| ServiceError::new("storage_write_failed", err.to_string()))?;

        let existing_vault = sqlx_core::query::query::<Sqlite>(
            r#"
            SELECT id
            FROM local_vaults
            WHERE storage_id = ?1 AND name = 'Personal (Local)'
            "#,
        )
        .bind(storage_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| ServiceError::new("vault_lookup_failed", err.to_string()))?;

        if existing_vault.is_none() {
            let vault_key = SecretKey::generate();
            let vault_id = Uuid::now_v7();
            let payload = core_crypto::encrypt_vault_key(self.master_key, vault_id, &vault_key)
                .map_err(|err| ServiceError::new("vault_key_encrypt_failed", err.to_string()))?;
            sqlx_core::query::query::<Sqlite>(
                r#"
                INSERT INTO local_vaults (
                    id,
                    storage_id,
                    name,
                    kind,
                    is_default,
                    vault_key_enc,
                    key_wrap_type,
                    last_synced_at
                )
                VALUES (?1, ?2, 'Personal (Local)', 1, 1, ?3, 1, NULL)
                "#,
            )
            .bind(vault_id)
            .bind(storage_id)
            .bind(payload)
            .execute(&mut *tx)
            .await
            .map_err(|err| ServiceError::new("vault_create_failed", err.to_string()))?;
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
