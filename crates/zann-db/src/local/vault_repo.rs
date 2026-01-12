use uuid::Uuid;

use crate::local::LocalVault;
use crate::SqlitePool;

pub struct LocalVaultRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> LocalVaultRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn get_by_id(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
    ) -> Result<Option<LocalVault>, sqlx_core::Error> {
        query_as!(
            LocalVault,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                name,
                kind,
                is_default,
                vault_key_enc,
                key_wrap_type,
                last_synced_at as "last_synced_at"
            FROM local_vaults
            WHERE storage_id = ?1 AND id = ?2
            "#,
            storage_id,
            vault_id
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn create(&self, vault: &LocalVault) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO local_vaults (
                id, storage_id, name, kind, is_default, vault_key_enc, key_wrap_type, last_synced_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            vault.id,
            vault.storage_id,
            vault.name.as_str(),
            vault.kind.as_i32(),
            vault.is_default,
            &vault.vault_key_enc,
            vault.key_wrap_type.as_i32(),
            vault.last_synced_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get_by_name(
        &self,
        storage_id: Uuid,
        name: &str,
    ) -> Result<Option<LocalVault>, sqlx_core::Error> {
        query_as!(
            LocalVault,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                name,
                kind,
                is_default,
                vault_key_enc,
                key_wrap_type,
                last_synced_at as "last_synced_at"
            FROM local_vaults
            WHERE storage_id = ?1 AND name = ?2
            "#,
            storage_id,
            name
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn list_by_storage(
        &self,
        storage_id: Uuid,
    ) -> Result<Vec<LocalVault>, sqlx_core::Error> {
        query_as!(
            LocalVault,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                name,
                kind,
                is_default,
                vault_key_enc,
                key_wrap_type,
                last_synced_at as "last_synced_at"
            FROM local_vaults
            WHERE storage_id = ?1
            ORDER BY name
            "#,
            storage_id
        )
        .fetch_all(self.pool)
        .await
    }

    pub async fn update_key(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        vault_key_enc: &[u8],
        key_wrap_type: crate::local::KeyWrapType,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE local_vaults
            SET vault_key_enc = ?3,
                key_wrap_type = ?4
            WHERE storage_id = ?1 AND id = ?2
            "#,
            storage_id,
            vault_id,
            vault_key_enc,
            key_wrap_type.as_i32()
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn delete_by_storage(&self, storage_id: Uuid) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"DELETE FROM local_vaults WHERE storage_id = ?1"#,
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
            r#"DELETE FROM local_vaults WHERE storage_id = ?1 AND id = ?2"#,
            storage_id,
            vault_id
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}
