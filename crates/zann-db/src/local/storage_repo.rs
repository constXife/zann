use uuid::Uuid;

use crate::local::LocalStorage;
use crate::SqlitePool;

pub struct LocalStorageRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> LocalStorageRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn get(&self, storage_id: Uuid) -> Result<Option<LocalStorage>, sqlx_core::Error> {
        query_as!(
            LocalStorage,
            r#"
            SELECT
                id as "id",
                kind,
                name,
                server_url,
                server_name,
                server_fingerprint,
                account_subject,
                personal_vaults_enabled,
                auth_method
            FROM storages
            WHERE id = ?1
            "#,
            storage_id
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn upsert(&self, storage: &LocalStorage) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO storages (
                id, kind, name, server_url, server_name, server_fingerprint, account_subject, personal_vaults_enabled, auth_method
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(id) DO UPDATE SET
                kind = excluded.kind,
                name = excluded.name,
                server_url = excluded.server_url,
                server_name = excluded.server_name,
                server_fingerprint = excluded.server_fingerprint,
                account_subject = excluded.account_subject,
                personal_vaults_enabled = excluded.personal_vaults_enabled,
                auth_method = excluded.auth_method
            "#,
            storage.id,
            storage.kind.as_i32(),
            storage.name.as_str(),
            storage.server_url.as_deref(),
            storage.server_name.as_deref(),
            storage.server_fingerprint.as_deref(),
            storage.account_subject.as_deref(),
            storage.personal_vaults_enabled,
            storage.auth_method.map(|value| value.as_i32())
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn list(&self) -> Result<Vec<LocalStorage>, sqlx_core::Error> {
        query_as!(
            LocalStorage,
            r#"
            SELECT
                id as "id",
                kind,
                name,
                server_url,
                server_name,
                server_fingerprint,
                account_subject,
                personal_vaults_enabled,
                auth_method
            FROM storages
            ORDER BY name
            "#
        )
        .fetch_all(self.pool)
        .await
    }

    pub async fn delete(&self, storage_id: Uuid) -> Result<u64, sqlx_core::Error> {
        query!(r#"DELETE FROM storages WHERE id = ?1"#, storage_id)
            .execute(self.pool)
            .await
            .map(|result| result.rows_affected())
    }

    pub async fn update_account_info(
        &self,
        storage_id: Uuid,
        account_subject: Option<&str>,
    ) -> Result<(), sqlx_core::Error> {
        query!(
            r#"UPDATE storages SET account_subject = ?2 WHERE id = ?1"#,
            storage_id,
            account_subject
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }
}
