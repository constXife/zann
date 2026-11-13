use sqlx_core::row::Row;
use sqlx_core::transaction::Transaction;
use sqlx_sqlite::Sqlite;
use uuid::Uuid;

use zann_core::{AuthMethod, StorageKind};

use crate::local::{LocalProjectionReadError, LocalStorage};
use crate::SqlitePool;

const MAX_STORAGE_NAME_BYTES: i64 = 200;
const MAX_SERVER_URL_BYTES: i64 = 2_048;
const MAX_SERVER_METADATA_BYTES: i64 = 512;
// Config v2 permits at most 256 remote connections. One additional row is
// reserved for the local personal storage projection.
const MAX_LOCAL_STORAGES: i64 = 257;

pub struct LocalStorageRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> LocalStorageRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn get(&self, storage_id: Uuid) -> Result<Option<LocalStorage>, sqlx_core::Error> {
        self.get_bounded(storage_id)
            .await
            .map_err(|error| match error {
                LocalProjectionReadError::Database(error) => error,
                LocalProjectionReadError::InvalidInput
                | LocalProjectionReadError::CorruptProjection
                | LocalProjectionReadError::TooManyRows => sqlx_core::Error::Protocol(
                    "local storage projection is corrupt or unsupported".to_string(),
                ),
            })
    }

    /// Reads one storage only after a same-snapshot scalar preflight proves
    /// every dynamically typed TEXT column is bounded before SQLx decodes it.
    pub async fn get_bounded(
        &self,
        storage_id: Uuid,
    ) -> Result<Option<LocalStorage>, LocalProjectionReadError> {
        let mut tx = self.pool.begin().await?;
        if storage_headers_corrupt(&mut tx).await? {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::CorruptProjection);
        }
        let preflight = query!(
            r#"
            SELECT CASE WHEN
                CASE WHEN typeof(id) IN ('blob', 'text')
                    THEN octet_length(id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(kind) = 'integer'
                    THEN kind IN (1, 2) ELSE 0 END
                AND CASE WHEN typeof(name) = 'text'
                    THEN octet_length(name) BETWEEN 1 AND ?2 ELSE 0 END
                AND (server_url IS NULL OR CASE WHEN typeof(server_url) = 'text'
                    THEN octet_length(server_url) BETWEEN 1 AND ?3 ELSE 0 END)
                AND (server_name IS NULL OR CASE WHEN typeof(server_name) = 'text'
                    THEN octet_length(server_name) BETWEEN 1 AND ?4 ELSE 0 END)
                AND (server_fingerprint IS NULL OR CASE
                    WHEN typeof(server_fingerprint) = 'text'
                    THEN octet_length(server_fingerprint) BETWEEN 1 AND ?4 ELSE 0 END)
                AND (account_subject IS NULL OR CASE WHEN typeof(account_subject) = 'text'
                    THEN octet_length(account_subject) BETWEEN 1 AND ?4 ELSE 0 END)
                AND CASE WHEN typeof(personal_vaults_enabled) = 'integer'
                    THEN personal_vaults_enabled IN (0, 1) ELSE 0 END
                AND CASE
                    WHEN auth_method IS NULL THEN 1
                    WHEN typeof(auth_method) = 'integer'
                        THEN auth_method IN (1, 2, 3)
                    ELSE 0
                END
                AND CASE
                    WHEN sync_config_repository_fp IS NULL THEN
                        sync_stable_target_fp IS NULL
                        AND sync_config_revision IS NULL
                        AND sync_config_content_fp IS NULL
                    WHEN kind != ?5 THEN 0
                    WHEN typeof(sync_config_repository_fp) != 'blob' THEN 0
                    WHEN octet_length(sync_config_repository_fp) != 32 THEN 0
                    WHEN typeof(sync_stable_target_fp) != 'blob' THEN 0
                    WHEN octet_length(sync_stable_target_fp) != 32 THEN 0
                    WHEN typeof(sync_config_revision) != 'blob' THEN 0
                    WHEN octet_length(sync_config_revision) != 8 THEN 0
                    WHEN typeof(sync_config_content_fp) != 'blob' THEN 0
                    WHEN octet_length(sync_config_content_fp) != 32 THEN 0
                    ELSE 1
                END
            THEN 1 ELSE 0 END AS valid
            FROM storages
            WHERE id = ?1
            "#,
            storage_id,
            MAX_STORAGE_NAME_BYTES,
            MAX_SERVER_URL_BYTES,
            MAX_SERVER_METADATA_BYTES,
            zann_core::StorageKind::Remote.as_i32()
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
        let storage = query_as!(
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
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(storage)
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

    /// Inserts one projection without ever replacing an existing binding.
    /// Callers must re-read and compare the row after a false/racing outcome.
    pub async fn insert_if_absent(&self, storage: &LocalStorage) -> Result<bool, sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO storages (
                id, kind, name, server_url, server_name, server_fingerprint,
                account_subject, personal_vaults_enabled, auth_method
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(id) DO NOTHING
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
        .map(|result| result.rows_affected() == 1)
    }

    /// Voids the claim of the connection generation that synced this remote
    /// storage, keeping its projection and unsent changes, so the next
    /// connection to its address can claim it again (see
    /// `LocalVaultRepo::bind_cache_key_fingerprints_leased`). Releasing an
    /// absent or already released storage is a no-op.
    pub async fn release_claim(&self, storage_id: Uuid) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            UPDATE storages
            SET sync_config_repository_fp = NULL,
                sync_stable_target_fp = NULL,
                sync_config_revision = NULL,
                sync_config_content_fp = NULL
            WHERE id = ?1 AND kind = ?2
            "#,
            storage_id,
            StorageKind::Remote.as_i32()
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    /// Rebinds a released remote storage to what its server proves now: its
    /// display name, server fingerprint and auth method. Address, account and
    /// capability stay, so the projection keeps belonging to the same
    /// account. Returns `false`, changing nothing, when the row is claimed or
    /// no longer reads `expected`.
    pub async fn rebind_released(
        &self,
        expected: &LocalStorage,
        name: &str,
        server_fingerprint: &str,
        auth_method: AuthMethod,
        account_subject: &str,
    ) -> Result<bool, sqlx_core::Error> {
        query!(
            r#"
            UPDATE storages
            SET name = ?1,
                server_fingerprint = ?2,
                auth_method = ?3,
                account_subject = ?13
            WHERE id = ?4
              AND kind = ?5
              AND sync_config_repository_fp IS NULL
              AND name = ?6
              AND server_url IS ?7
              AND server_name IS ?8
              AND server_fingerprint IS ?9
              AND account_subject IS ?10
              AND personal_vaults_enabled = ?11
              AND auth_method IS ?12
            "#,
            name,
            server_fingerprint,
            auth_method.as_i32(),
            expected.id,
            StorageKind::Remote.as_i32(),
            expected.name.as_str(),
            expected.server_url.as_deref(),
            expected.server_name.as_deref(),
            expected.server_fingerprint.as_deref(),
            expected.account_subject.as_deref(),
            expected.personal_vaults_enabled,
            expected.auth_method.map(|value| value.as_i32()),
            account_subject
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected() == 1)
    }

    pub async fn list(&self) -> Result<Vec<LocalStorage>, sqlx_core::Error> {
        let mut tx = self.pool.begin().await?;
        let count: i64 = query!(
            r#"
            SELECT COUNT(*) AS count
            FROM (SELECT 1 FROM storages LIMIT ?1)
            "#,
            MAX_LOCAL_STORAGES + 1
        )
        .fetch_one(&mut *tx)
        .await?
        .try_get("count")?;
        if count > MAX_LOCAL_STORAGES {
            tx.rollback().await?;
            return Err(sqlx_core::Error::Protocol(
                "too many local storage rows".to_string(),
            ));
        }
        if storage_rows_corrupt(&mut tx).await? {
            tx.rollback().await?;
            return Err(sqlx_core::Error::Protocol(
                "local storage projection is corrupt".to_string(),
            ));
        }
        let counts = query!(
            r#"
            SELECT
                COALESCE(SUM(CASE WHEN kind = 1 THEN 1 ELSE 0 END), 0) AS local_count,
                COALESCE(SUM(CASE WHEN kind = 2 THEN 1 ELSE 0 END), 0) AS remote_count
            FROM storages
            "#
        )
        .fetch_one(&mut *tx)
        .await?;
        let local_count: i64 = counts.try_get("local_count")?;
        let remote_count: i64 = counts.try_get("remote_count")?;
        if local_count > 1 || remote_count > 256 {
            tx.rollback().await?;
            return Err(sqlx_core::Error::Protocol(
                "unsupported local storage topology".to_string(),
            ));
        }
        let storages = query_as!(
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
            ORDER BY name, id
            LIMIT ?1
            "#,
            MAX_LOCAL_STORAGES
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(storages)
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

/// Validates all dynamically typed storage bodies before any ORDER BY or
/// typed decode can materialize them. CASE ordering is deliberately lazy.
async fn storage_rows_corrupt(tx: &mut Transaction<'_, Sqlite>) -> Result<bool, sqlx_core::Error> {
    query!(
        r#"
        SELECT 1
        FROM storages
        WHERE CASE
            WHEN typeof(id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(id) NOT IN (16, 36) THEN 1
            WHEN typeof(kind) != 'integer' THEN 1
            WHEN kind NOT IN (1, 2) THEN 1
            WHEN typeof(name) != 'text' THEN 1
            WHEN octet_length(name) NOT BETWEEN 1 AND ?1 THEN 1
            WHEN server_url IS NOT NULL AND typeof(server_url) != 'text' THEN 1
            WHEN server_url IS NOT NULL AND octet_length(server_url) NOT BETWEEN 1 AND ?2 THEN 1
            WHEN server_name IS NOT NULL AND typeof(server_name) != 'text' THEN 1
            WHEN server_name IS NOT NULL AND octet_length(server_name) NOT BETWEEN 1 AND ?3 THEN 1
            WHEN server_fingerprint IS NOT NULL AND typeof(server_fingerprint) != 'text' THEN 1
            WHEN server_fingerprint IS NOT NULL AND octet_length(server_fingerprint) NOT BETWEEN 1 AND ?3 THEN 1
            WHEN account_subject IS NOT NULL AND typeof(account_subject) != 'text' THEN 1
            WHEN account_subject IS NOT NULL AND octet_length(account_subject) NOT BETWEEN 1 AND ?3 THEN 1
            WHEN typeof(personal_vaults_enabled) != 'integer' THEN 1
            WHEN personal_vaults_enabled NOT IN (0, 1) THEN 1
            WHEN auth_method IS NOT NULL AND typeof(auth_method) != 'integer' THEN 1
            WHEN auth_method IS NOT NULL AND auth_method NOT IN (1, 2, 3) THEN 1
            WHEN sync_config_repository_fp IS NULL AND (
                sync_stable_target_fp IS NOT NULL
                OR sync_config_revision IS NOT NULL
                OR sync_config_content_fp IS NOT NULL
            ) THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND kind != 2 THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND typeof(sync_config_repository_fp) != 'blob' THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND octet_length(sync_config_repository_fp) != 32 THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND typeof(sync_stable_target_fp) != 'blob' THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND octet_length(sync_stable_target_fp) != 32 THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND typeof(sync_config_revision) != 'blob' THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND octet_length(sync_config_revision) != 8 THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND typeof(sync_config_content_fp) != 'blob' THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND octet_length(sync_config_content_fp) != 32 THEN 1
            ELSE 0
        END = 1
        LIMIT 1
        "#,
        MAX_STORAGE_NAME_BYTES,
        MAX_SERVER_URL_BYTES,
        MAX_SERVER_METADATA_BYTES,
    )
    .fetch_optional(&mut **tx)
    .await
    .map(|row| row.is_some())
}

async fn storage_headers_corrupt(
    tx: &mut Transaction<'_, Sqlite>,
) -> Result<bool, sqlx_core::Error> {
    query!(
        r#"
        SELECT 1
        FROM storages
        WHERE CASE
            WHEN typeof(id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(id) NOT IN (16, 36) THEN 1
            WHEN typeof(kind) != 'integer' THEN 1
            WHEN kind NOT IN (1, 2) THEN 1
            WHEN sync_config_repository_fp IS NULL AND (
                sync_stable_target_fp IS NOT NULL
                OR sync_config_revision IS NOT NULL
                OR sync_config_content_fp IS NOT NULL
            ) THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND kind != 2 THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND typeof(sync_config_repository_fp) != 'blob' THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND octet_length(sync_config_repository_fp) != 32 THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND typeof(sync_stable_target_fp) != 'blob' THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND octet_length(sync_stable_target_fp) != 32 THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND typeof(sync_config_revision) != 'blob' THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND octet_length(sync_config_revision) != 8 THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND typeof(sync_config_content_fp) != 'blob' THEN 1
            WHEN sync_config_repository_fp IS NOT NULL AND octet_length(sync_config_content_fp) != 32 THEN 1
            ELSE 0
        END
        LIMIT 1
        "#
    )
    .fetch_optional(&mut **tx)
    .await
    .map(|row| row.is_some())
}
