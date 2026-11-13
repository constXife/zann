use std::collections::HashSet;
use std::error::Error as StdError;
use std::fmt;

use sqlx_core::row::Row;
use sqlx_core::transaction::Transaction;
use sqlx_sqlite::Sqlite;
use uuid::Uuid;

use crate::local::sync_repo::{
    claim_generation, ensure_bound_generation_and_advance, ensure_storage_proof,
    inspect_generation_binding, validate_storage_proof, LocalGenerationBindingState,
};
use crate::local::{
    KeyWrapType, LocalProjectionReadError, LocalStorageProof, LocalStorageRepo, LocalSyncError,
    LocalSyncGenerationProof, LocalVault,
};
use crate::SqlitePool;

const MAX_LOCAL_VAULTS_PER_STORAGE: usize = 200;
const LOCAL_VAULT_QUERY_LIMIT: i64 = 201;
const LOCAL_VAULT_CAP_OFFSET: i64 = 199;
const MAX_LOCAL_VAULT_NAME_BYTES: usize = 200;
const MAX_LOCAL_VAULT_SLUG_BYTES: usize = 128;
const LOCAL_VAULT_INTERNAL_SLUG_BYTES: usize = 39;
const MAX_LOCAL_VAULT_KEY_ENVELOPE_BYTES: usize = 65_536;
const LOCAL_VAULT_CACHE_KEY_FP_BYTES: usize = 12;

/// Exact immutable inputs for one cache-key fingerprint transition.
#[derive(Clone, Copy)]
pub struct CacheKeyFingerprintBinding<'a> {
    pub storage_id: Uuid,
    pub vault_id: Uuid,
    pub expected_slug: &'a str,
    pub expected_name: &'a str,
    pub expected_kind: zann_core::VaultKind,
    pub expected_is_default: bool,
    pub expected_vault_key_enc: &'a [u8],
    pub expected_key_wrap_type: KeyWrapType,
    pub target_cache_key_fp: &'a str,
}

impl fmt::Debug for CacheKeyFingerprintBinding<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CacheKeyFingerprintBinding")
            .field("storage_id", &self.storage_id)
            .field("vault_id", &self.vault_id)
            .field("expected_kind", &self.expected_kind)
            .field("binding", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheKeyFingerprintBatchBind {
    bound: usize,
    already_bound: usize,
}

impl CacheKeyFingerprintBatchBind {
    pub fn bound(self) -> usize {
        self.bound
    }

    pub fn already_bound(self) -> usize {
        self.already_bound
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheKeyFingerprintBind {
    Bound,
    AlreadyBound,
}

pub enum LocalVaultKeyBindError {
    InvalidInput,
    NotFound,
    KeyBindingChanged,
    GenerationChanged,
    ProjectionNotEmpty,
    /// SQLite returned an error while committing. The binding may or may not
    /// be durable, so callers must reconcile before retrying.
    CommitOutcomeUnknown,
    Database(sqlx_core::Error),
}

impl fmt::Debug for LocalVaultKeyBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => formatter.write_str("InvalidInput"),
            Self::NotFound => formatter.write_str("NotFound"),
            Self::KeyBindingChanged => formatter.write_str("KeyBindingChanged(<redacted>)"),
            Self::GenerationChanged => formatter.write_str("GenerationChanged(<redacted>)"),
            Self::ProjectionNotEmpty => formatter.write_str("ProjectionNotEmpty"),
            Self::CommitOutcomeUnknown => formatter.write_str("CommitOutcomeUnknown(<redacted>)"),
            Self::Database(_) => formatter.write_str("Database(<redacted>)"),
        }
    }
}

impl fmt::Display for LocalVaultKeyBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidInput => "invalid local vault key binding",
            Self::NotFound => "local vault does not exist",
            Self::KeyBindingChanged => "local vault key binding changed",
            Self::GenerationChanged => "local sync generation changed",
            Self::ProjectionNotEmpty => "local vault projection is not empty",
            Self::CommitOutcomeUnknown => "local vault key binding outcome is unknown",
            Self::Database(_) => "local vault key binding database operation failed",
        };
        formatter.write_str(message)
    }
}

impl StdError for LocalVaultKeyBindError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Database(source) => Some(source),
            _ => None,
        }
    }
}

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
                slug,
                name,
                kind,
                is_default,
                vault_key_enc,
                key_wrap_type,
                cache_key_fp,
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

    pub async fn exists(&self, storage_id: Uuid, vault_id: Uuid) -> Result<bool, sqlx_core::Error> {
        query!(
            r#"SELECT 1 FROM local_vaults WHERE storage_id = ?1 AND id = ?2"#,
            storage_id,
            vault_id
        )
        .fetch_optional(self.pool)
        .await
        .map(|row| row.is_some())
    }

    /// Proves one storage-scoped vault exists without decoding an unbounded SQLite value before the identity/body preflight.
    pub async fn exists_bounded(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
    ) -> Result<bool, LocalProjectionReadError> {
        if storage_id.is_nil() || vault_id.is_nil() {
            return Err(LocalProjectionReadError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let result = match bounded_vault_preflight(&mut tx, storage_id, Some(vault_id)).await? {
            None => false,
            Some(true) => true,
            Some(false) => {
                tx.rollback().await?;
                return Err(LocalProjectionReadError::CorruptProjection);
            }
        };
        tx.commit().await?;
        Ok(result)
    }

    /// Reads one vault after a same-snapshot scalar preflight bounds all
    /// dynamically typed identity/envelope columns.
    pub async fn get_by_id_bounded(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
    ) -> Result<Option<LocalVault>, LocalProjectionReadError> {
        if storage_id.is_nil() || vault_id.is_nil() {
            return Err(LocalProjectionReadError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let preflight = bounded_vault_preflight(&mut tx, storage_id, Some(vault_id)).await?;
        let Some(valid) = preflight else {
            tx.commit().await?;
            return Ok(None);
        };
        if !valid {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::CorruptProjection);
        }
        let vault = query_as!(
            LocalVault,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                slug,
                name,
                kind,
                is_default,
                vault_key_enc,
                key_wrap_type,
                cache_key_fp,
                last_synced_at as "last_synced_at"
            FROM local_vaults
            WHERE storage_id = ?1 AND id = ?2
            "#,
            storage_id,
            vault_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(vault)
    }

    pub async fn create(&self, vault: &LocalVault) -> Result<(), sqlx_core::Error> {
        validate_vault(vault)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        ensure_vault_capacity(&mut tx, vault.storage_id).await?;
        insert_vault(&mut tx, vault).await?;
        tx.commit().await
    }

    /// Inserts remote catalog metadata without replacing an existing
    /// storage-scoped vault identity. Callers re-read and compare every field
    /// afterwards.
    pub async fn insert_if_absent(&self, vault: &LocalVault) -> Result<bool, sqlx_core::Error> {
        validate_vault(vault)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let present = query!(
            r#"SELECT 1 AS present FROM local_vaults WHERE storage_id = ?1 AND id = ?2"#,
            vault.storage_id,
            vault.id
        )
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        if present {
            tx.commit().await?;
            return Ok(false);
        }
        ensure_vault_capacity(&mut tx, vault.storage_id).await?;
        insert_vault(&mut tx, vault).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Binds an exact key fingerprint to an existing, completely empty vault.
    ///
    /// The encrypted envelope and wrap type are compare-and-swap inputs. The
    /// target fingerprint may replace `NULL` or prove an identical prior bind;
    /// any other state fails closed.
    pub async fn bind_cache_key_fingerprint(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        expected_vault_key_enc: &[u8],
        expected_key_wrap_type: KeyWrapType,
        target_cache_key_fp: &str,
    ) -> Result<CacheKeyFingerprintBind, LocalVaultKeyBindError> {
        let storage = LocalStorageRepo::new(self.pool)
            .get_bounded(storage_id)
            .await
            .map_err(map_projection_read_key_error)?
            .ok_or(LocalVaultKeyBindError::NotFound)?;
        let storage_proof = LocalStorageProof::try_from(&storage)
            .map_err(|_| LocalVaultKeyBindError::InvalidInput)?;
        let vault = self
            .get_by_id_bounded(storage_id, vault_id)
            .await
            .map_err(map_projection_read_key_error)?
            .ok_or(LocalVaultKeyBindError::NotFound)?;
        let receipt = self
            .bind_cache_key_fingerprints(
                &storage_proof,
                &[CacheKeyFingerprintBinding {
                    storage_id,
                    vault_id,
                    expected_slug: &vault.slug,
                    expected_name: &vault.name,
                    expected_kind: vault.kind,
                    expected_is_default: vault.is_default,
                    expected_vault_key_enc,
                    expected_key_wrap_type,
                    target_cache_key_fp,
                }],
            )
            .await?;
        Ok(if receipt.bound == 1 {
            CacheKeyFingerprintBind::Bound
        } else {
            CacheKeyFingerprintBind::AlreadyBound
        })
    }

    /// Atomically verifies a complete bounded catalog and binds its exact
    /// cache-key fingerprints. An empty slice is an exact empty-catalog proof.
    ///
    /// Every row, envelope, wrap type, existing fingerprint, and empty
    /// projection proof is checked under one `BEGIN IMMEDIATE` reservation
    /// before any row is updated. A failure rolls back the complete batch.
    pub async fn bind_cache_key_fingerprints(
        &self,
        expected_storage: &LocalStorageProof,
        bindings: &[CacheKeyFingerprintBinding<'_>],
    ) -> Result<CacheKeyFingerprintBatchBind, LocalVaultKeyBindError> {
        validate_storage_proof(expected_storage)
            .map_err(|_| LocalVaultKeyBindError::InvalidInput)?;
        validate_fingerprint_bindings(expected_storage.storage_id(), bindings)?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(LocalVaultKeyBindError::Database)?;
        let result =
            bind_cache_key_fingerprints_bound_in(&mut tx, expected_storage, bindings).await;
        match result {
            Ok(receipt) => {
                tx.commit()
                    .await
                    .map_err(|_| LocalVaultKeyBindError::CommitOutcomeUnknown)?;
                Ok(receipt)
            }
            Err(error) => {
                tx.rollback()
                    .await
                    .map_err(LocalVaultKeyBindError::Database)?;
                Err(error)
            }
        }
    }

    /// Reconciles an exact catalog under a configuration generation lease.
    ///
    /// The first generation claim is allowed only when the complete catalog
    /// matches, every target fingerprint is `NULL`, and the storage has no
    /// item, history, pending, or cursor rows. A storage whose claim was
    /// released (`LocalStorageRepo::release_claim`) is claimed again with its
    /// projection when at least one target fingerprint is already bound and
    /// none differs. The generation claim and all fingerprint transitions
    /// commit atomically.
    /// Once claimed, catalog reconciliation only proves identical already-
    /// bound fingerprints; a newer authorized config revision may advance in
    /// this same transaction.
    pub async fn bind_cache_key_fingerprints_leased(
        &self,
        expected_storage: &LocalStorageProof,
        generation: &LocalSyncGenerationProof,
        bindings: &[CacheKeyFingerprintBinding<'_>],
    ) -> Result<CacheKeyFingerprintBatchBind, LocalVaultKeyBindError> {
        validate_storage_proof(expected_storage)
            .map_err(|_| LocalVaultKeyBindError::InvalidInput)?;
        validate_fingerprint_bindings(expected_storage.storage_id(), bindings)?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(LocalVaultKeyBindError::Database)?;
        let result =
            bind_cache_key_fingerprints_leased_in(&mut tx, expected_storage, generation, bindings)
                .await;
        match result {
            Ok(receipt) => {
                tx.commit()
                    .await
                    .map_err(|_| LocalVaultKeyBindError::CommitOutcomeUnknown)?;
                Ok(receipt)
            }
            Err(error) => {
                tx.rollback()
                    .await
                    .map_err(LocalVaultKeyBindError::Database)?;
                Err(error)
            }
        }
    }

    pub async fn get_by_name(
        &self,
        storage_id: Uuid,
        name: &str,
    ) -> Result<Option<LocalVault>, sqlx_core::Error> {
        if name.is_empty() || name.len() > MAX_LOCAL_VAULT_NAME_BYTES {
            return Err(invalid_vault_input());
        }
        query_as!(
            LocalVault,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                slug,
                name,
                kind,
                is_default,
                vault_key_enc,
                key_wrap_type,
                cache_key_fp,
                last_synced_at as "last_synced_at"
            FROM local_vaults
            WHERE storage_id = ?1 AND name = ?2
            ORDER BY slug
            LIMIT 1
            "#,
            storage_id,
            name
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn get_by_slug(
        &self,
        storage_id: Uuid,
        slug: &str,
    ) -> Result<Option<LocalVault>, sqlx_core::Error> {
        if !valid_vault_slug(slug) {
            return Err(invalid_vault_input());
        }
        query_as!(
            LocalVault,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                slug,
                name,
                kind,
                is_default,
                vault_key_enc,
                key_wrap_type,
                cache_key_fp,
                last_synced_at as "last_synced_at"
            FROM local_vaults
            WHERE storage_id = ?1 AND slug = ?2
            "#,
            storage_id,
            slug
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn list_by_storage(
        &self,
        storage_id: Uuid,
    ) -> Result<Vec<LocalVault>, sqlx_core::Error> {
        let vaults = query_as!(
            LocalVault,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                slug,
                name,
                kind,
                is_default,
                vault_key_enc,
                key_wrap_type,
                cache_key_fp,
                last_synced_at as "last_synced_at"
            FROM local_vaults
            WHERE storage_id = ?1
            ORDER BY name, slug
            LIMIT ?2
            "#,
            storage_id,
            LOCAL_VAULT_QUERY_LIMIT
        )
        .fetch_all(self.pool)
        .await?;
        if vaults.len() > MAX_LOCAL_VAULTS_PER_STORAGE {
            return Err(sqlx_core::Error::Protocol(
                "local vault count exceeds the supported range".to_string(),
            ));
        }
        Ok(vaults)
    }

    /// Reads a complete capped catalog only after scalar count/type/length
    /// preflights in the same SQLite snapshot.
    pub async fn list_by_storage_bounded(
        &self,
        storage_id: Uuid,
    ) -> Result<Vec<LocalVault>, LocalProjectionReadError> {
        if storage_id.is_nil() {
            return Err(LocalProjectionReadError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        if !vault_identifiers_are_bounded(&mut tx).await? {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::CorruptProjection);
        }
        let count = query!(
            r#"
            SELECT COUNT(*) AS count
            FROM (
                SELECT 1
                FROM local_vaults
                WHERE storage_id = ?1
                LIMIT ?2
            )
            "#,
            storage_id,
            LOCAL_VAULT_QUERY_LIMIT
        )
        .fetch_one(&mut *tx)
        .await?
        .try_get::<i64, _>("count")?;
        if count > MAX_LOCAL_VAULTS_PER_STORAGE as i64 {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::TooManyRows);
        }
        if bounded_vault_preflight(&mut tx, storage_id, None)
            .await?
            .is_some_and(|valid| !valid)
        {
            tx.rollback().await?;
            return Err(LocalProjectionReadError::CorruptProjection);
        }
        let vaults = query_as!(
            LocalVault,
            r#"
            SELECT
                id as "id",
                storage_id as "storage_id",
                slug,
                name,
                kind,
                is_default,
                vault_key_enc,
                key_wrap_type,
                cache_key_fp,
                last_synced_at as "last_synced_at"
            FROM local_vaults
            WHERE storage_id = ?1
            ORDER BY name, slug
            LIMIT ?2
            "#,
            storage_id,
            MAX_LOCAL_VAULTS_PER_STORAGE as i64
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(vaults)
    }

    pub async fn update_key(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        vault_key_enc: &[u8],
        key_wrap_type: crate::local::KeyWrapType,
    ) -> Result<u64, sqlx_core::Error> {
        if vault_key_enc.len() > MAX_LOCAL_VAULT_KEY_ENVELOPE_BYTES {
            return Err(invalid_vault_input());
        }
        query!(
            r#"
            UPDATE local_vaults
            SET vault_key_enc = ?3,
                key_wrap_type = ?4,
                cache_key_fp = NULL
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

pub(crate) async fn bounded_vault_preflight(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
    vault_id: Option<Uuid>,
) -> Result<Option<bool>, sqlx_core::Error> {
    if let Some(vault_id) = vault_id {
        match bounded_vault_scope_membership(tx, storage_id, vault_id).await? {
            None => return Ok(None),
            Some(false) => return Ok(Some(false)),
            Some(true) => {}
        }
        let valid = query!(
            r#"
            SELECT CASE WHEN
                CASE WHEN typeof(id) IN ('blob', 'text')
                    THEN octet_length(id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(storage_id) IN ('blob', 'text')
                    THEN octet_length(storage_id) IN (16, 36) ELSE 0 END
                AND CASE WHEN typeof(slug) = 'text'
                    THEN octet_length(slug) BETWEEN 1 AND ?2 ELSE 0 END
                AND CASE WHEN typeof(name) = 'text'
                    THEN octet_length(name) BETWEEN 1 AND ?3 ELSE 0 END
                AND CASE WHEN typeof(kind) = 'integer'
                    THEN kind IN (1, 2) ELSE 0 END
                AND CASE WHEN typeof(is_default) = 'integer'
                    THEN is_default IN (0, 1) ELSE 0 END
                AND CASE WHEN typeof(vault_key_enc) = 'blob'
                    THEN length(vault_key_enc) BETWEEN 1 AND ?4 ELSE 0 END
                AND CASE WHEN typeof(key_wrap_type) = 'integer'
                    THEN key_wrap_type IN (1, 2, 3) ELSE 0 END
                AND (cache_key_fp IS NULL OR CASE WHEN typeof(cache_key_fp) = 'text'
                    THEN octet_length(cache_key_fp) = ?5 ELSE 0 END)
                AND (last_synced_at IS NULL OR typeof(last_synced_at) = 'integer')
            THEN 1 ELSE 0 END AS valid
            FROM local_vaults
            WHERE storage_id = ?6 AND id = ?1
            "#,
            vault_id,
            MAX_LOCAL_VAULT_SLUG_BYTES as i64,
            MAX_LOCAL_VAULT_NAME_BYTES as i64,
            MAX_LOCAL_VAULT_KEY_ENVELOPE_BYTES as i64,
            LOCAL_VAULT_CACHE_KEY_FP_BYTES as i64,
            storage_id
        )
        .fetch_optional(&mut **tx)
        .await?;
        return valid
            .map(|row| row.try_get::<i64, _>("valid").map(|value| value == 1))
            .transpose();
    }

    if !vault_identifiers_are_bounded(tx).await? {
        return Ok(Some(false));
    }

    let exists = query!(
        r#"
        SELECT 1
        FROM local_vaults
        WHERE storage_id = ?1
        LIMIT 1
        "#,
        storage_id
    )
    .fetch_optional(&mut **tx)
    .await?
    .is_some();
    if !exists {
        return Ok(None);
    }
    let corrupt = query!(
        r#"
        SELECT 1
        FROM local_vaults
        WHERE storage_id = ?1
          AND CASE WHEN
            CASE WHEN typeof(id) IN ('blob', 'text')
                THEN octet_length(id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(storage_id) IN ('blob', 'text')
                THEN octet_length(storage_id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(slug) = 'text'
                THEN octet_length(slug) BETWEEN 1 AND ?2 ELSE 0 END
            AND CASE WHEN typeof(name) = 'text'
                THEN octet_length(name) BETWEEN 1 AND ?3 ELSE 0 END
            AND CASE WHEN typeof(kind) = 'integer'
                THEN kind IN (1, 2) ELSE 0 END
            AND CASE WHEN typeof(is_default) = 'integer'
                THEN is_default IN (0, 1) ELSE 0 END
            AND CASE WHEN typeof(vault_key_enc) = 'blob'
                THEN length(vault_key_enc) BETWEEN 1 AND ?4 ELSE 0 END
            AND CASE WHEN typeof(key_wrap_type) = 'integer'
                THEN key_wrap_type IN (1, 2, 3) ELSE 0 END
            AND (cache_key_fp IS NULL OR CASE WHEN typeof(cache_key_fp) = 'text'
                THEN octet_length(cache_key_fp) = ?5 ELSE 0 END)
            AND (last_synced_at IS NULL OR typeof(last_synced_at) = 'integer')
          THEN 1 ELSE 0 END = 0
        LIMIT 1
        "#,
        storage_id,
        MAX_LOCAL_VAULT_SLUG_BYTES as i64,
        MAX_LOCAL_VAULT_NAME_BYTES as i64,
        MAX_LOCAL_VAULT_KEY_ENVELOPE_BYTES as i64,
        LOCAL_VAULT_CACHE_KEY_FP_BYTES as i64
    )
    .fetch_optional(&mut **tx)
    .await?
    .is_some();
    Ok(Some(!corrupt))
}

pub(crate) async fn bounded_vault_scope_membership(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
    vault_id: Uuid,
) -> Result<Option<bool>, sqlx_core::Error> {
    if !vault_identifiers_are_bounded(tx).await? {
        return Ok(Some(false));
    }
    query!(
        r#"SELECT 1 FROM local_vaults WHERE storage_id = ?1 AND id = ?2"#,
        storage_id,
        vault_id
    )
    .fetch_optional(&mut **tx)
    .await
    .map(|row| row.map(|_| true))
}

/// Checks only SQLite record metadata, so even an attacker-sized dynamic ID is
/// rejected without loading the identifier body into application memory.
pub(crate) async fn vault_identifiers_are_bounded(
    tx: &mut Transaction<'static, Sqlite>,
) -> Result<bool, sqlx_core::Error> {
    query!(
        r#"
        SELECT 1
        FROM local_vaults
        WHERE CASE
            WHEN typeof(id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(id) NOT IN (16, 36) THEN 1
            WHEN typeof(storage_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(storage_id) NOT IN (16, 36) THEN 1
            ELSE 0
        END
        LIMIT 1
        "#
    )
    .fetch_optional(&mut **tx)
    .await
    .map(|row| row.is_none())
}

async fn ensure_vault_capacity(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
) -> Result<(), sqlx_core::Error> {
    let at_capacity = query!(
        r#"
        SELECT 1
        FROM local_vaults
        WHERE storage_id = ?1
        LIMIT 1 OFFSET ?2
        "#,
        storage_id,
        LOCAL_VAULT_CAP_OFFSET
    )
    .fetch_optional(&mut **tx)
    .await?
    .is_some();
    if at_capacity {
        return Err(sqlx_core::Error::Protocol(
            "local vault count exceeds the supported range".to_string(),
        ));
    }
    Ok(())
}

async fn insert_vault(
    tx: &mut Transaction<'static, Sqlite>,
    vault: &LocalVault,
) -> Result<(), sqlx_core::Error> {
    query!(
        r#"
        INSERT INTO local_vaults (
            id, storage_id, slug, name, kind, is_default, vault_key_enc, key_wrap_type,
            cache_key_fp, last_synced_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
        vault.id,
        vault.storage_id,
        vault.slug.as_str(),
        vault.name.as_str(),
        vault.kind.as_i32(),
        vault.is_default,
        &vault.vault_key_enc,
        vault.key_wrap_type.as_i32(),
        vault.cache_key_fp.as_deref(),
        vault.last_synced_at
    )
    .execute(&mut **tx)
    .await
    .map(|_| ())
}

fn validate_fingerprint_bindings(
    expected_storage_id: Uuid,
    bindings: &[CacheKeyFingerprintBinding<'_>],
) -> Result<(), LocalVaultKeyBindError> {
    if bindings.len() > MAX_LOCAL_VAULTS_PER_STORAGE {
        return Err(LocalVaultKeyBindError::InvalidInput);
    }
    let mut vault_ids = HashSet::with_capacity(bindings.len());
    for binding in bindings {
        if binding.storage_id.is_nil()
            || binding.storage_id != expected_storage_id
            || binding.vault_id.is_nil()
            || !valid_vault_slug(binding.expected_slug)
            || binding.expected_name.is_empty()
            || binding.expected_name.len() > MAX_LOCAL_VAULT_NAME_BYTES
            || binding.expected_vault_key_enc.is_empty()
            || binding.expected_vault_key_enc.len() > MAX_LOCAL_VAULT_KEY_ENVELOPE_BYTES
            || !matches!(
                binding.expected_key_wrap_type,
                KeyWrapType::RemoteServer | KeyWrapType::RemoteStrict
            )
            || !valid_cache_key_fingerprint(binding.target_cache_key_fp)
            || !vault_ids.insert(binding.vault_id)
        {
            return Err(LocalVaultKeyBindError::InvalidInput);
        }
    }
    Ok(())
}

async fn bind_cache_key_fingerprints_bound_in(
    tx: &mut Transaction<'static, Sqlite>,
    expected_storage: &LocalStorageProof,
    bindings: &[CacheKeyFingerprintBinding<'_>],
) -> Result<CacheKeyFingerprintBatchBind, LocalVaultKeyBindError> {
    ensure_storage_proof(tx, expected_storage)
        .await
        .map_err(map_storage_proof_key_error)?;
    let bounded = bounded_vault_preflight(tx, expected_storage.storage_id(), None)
        .await
        .map_err(LocalVaultKeyBindError::Database)?;
    match (bounded, bindings.is_empty()) {
        (Some(true), _) | (None, true) => {}
        (Some(false), _) => return Err(LocalVaultKeyBindError::KeyBindingChanged),
        (None, false) => return Err(LocalVaultKeyBindError::NotFound),
    }
    let count = query!(
        r#"SELECT COUNT(*) AS count FROM local_vaults WHERE storage_id = ?1"#,
        expected_storage.storage_id()
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(LocalVaultKeyBindError::Database)?
    .try_get::<i64, _>("count")
    .map_err(LocalVaultKeyBindError::Database)?;
    if count != bindings.len() as i64 {
        return Err(LocalVaultKeyBindError::KeyBindingChanged);
    }
    bind_cache_key_fingerprints_in(tx, bindings).await
}

async fn bind_cache_key_fingerprints_leased_in(
    tx: &mut Transaction<'static, Sqlite>,
    expected_storage: &LocalStorageProof,
    generation: &LocalSyncGenerationProof,
    bindings: &[CacheKeyFingerprintBinding<'_>],
) -> Result<CacheKeyFingerprintBatchBind, LocalVaultKeyBindError> {
    ensure_storage_proof(tx, expected_storage)
        .await
        .map_err(map_storage_proof_key_error)?;
    ensure_exact_catalog(tx, expected_storage.storage_id(), bindings).await?;
    let fingerprint_states = inspect_fingerprint_bindings(tx, bindings).await?;

    match inspect_generation_binding(tx, expected_storage.storage_id(), generation)
        .await
        .map_err(map_storage_proof_key_error)?
    {
        LocalGenerationBindingState::Unbound => {
            // A storage released for a new connection keeps its projection;
            // the fingerprints bound before prove this master key opens the
            // same vault keys, so it is claimed as it stands. A storage that
            // never bound a key is claimed only while empty.
            // A legacy storage (MIG-009) is claimed with its projection
            // only within the catalog's vaults; each one then proves its key
            // or stays empty in the bind below.
            if fingerprint_states
                .iter()
                .all(|state| state.fingerprint == 0)
            {
                if fingerprint_states.iter().any(|state| state.legacy) {
                    ensure_storage_projection_within_catalog(tx, expected_storage.storage_id())
                        .await?;
                } else {
                    ensure_storage_projection_empty_for_claim(
                        tx,
                        expected_storage.storage_id(),
                        bindings,
                    )
                    .await?;
                }
            }
            claim_generation(tx, expected_storage.storage_id(), generation)
                .await
                .map_err(map_storage_proof_key_error)?;
            bind_cache_key_fingerprints_in(tx, bindings).await
        }
        LocalGenerationBindingState::Exact | LocalGenerationBindingState::Older => {
            if fingerprint_states
                .iter()
                .any(|state| state.fingerprint != 1)
            {
                return Err(LocalVaultKeyBindError::GenerationChanged);
            }
            ensure_bound_generation_and_advance(tx, expected_storage.storage_id(), generation)
                .await
                .map_err(map_storage_proof_key_error)?;
            Ok(CacheKeyFingerprintBatchBind {
                bound: 0,
                already_bound: bindings.len(),
            })
        }
    }
}

async fn ensure_exact_catalog(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
    bindings: &[CacheKeyFingerprintBinding<'_>],
) -> Result<(), LocalVaultKeyBindError> {
    let bounded = bounded_vault_preflight(tx, storage_id, None)
        .await
        .map_err(LocalVaultKeyBindError::Database)?;
    match (bounded, bindings.is_empty()) {
        (Some(true), _) | (None, true) => {}
        (Some(false), _) => return Err(LocalVaultKeyBindError::KeyBindingChanged),
        (None, false) => return Err(LocalVaultKeyBindError::NotFound),
    }
    let count = query!(
        r#"SELECT COUNT(*) AS count FROM local_vaults WHERE storage_id = ?1"#,
        storage_id
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(LocalVaultKeyBindError::Database)?
    .try_get::<i64, _>("count")
    .map_err(LocalVaultKeyBindError::Database)?;
    if count != bindings.len() as i64 {
        return Err(LocalVaultKeyBindError::KeyBindingChanged);
    }
    Ok(())
}

/// One catalog binding as the row stands: its fingerprint state (0 for NULL,
/// 1 for the exact target) and whether it still carries the internal slug
/// migration 0002 gave a legacy vault (MIG-009). Every mismatched identity
/// or fingerprint is rejected; the catalog preflight has already bounded every
/// selected dynamic value before this comparison runs.
#[derive(Clone, Copy)]
struct BindingState {
    fingerprint: i64,
    legacy: bool,
}

async fn inspect_binding(
    tx: &mut Transaction<'static, Sqlite>,
    binding: &CacheKeyFingerprintBinding<'_>,
) -> Result<BindingState, LocalVaultKeyBindError> {
    let current = query!(
        r#"
        SELECT
                CASE WHEN
                (slug = ?3 OR (slug = ?10 AND cache_key_fp IS NULL))
                AND name = ?4
                AND kind = ?5
                AND is_default = ?6
                AND vault_key_enc = ?7
                AND key_wrap_type = ?8
            THEN 1 ELSE 0 END AS identity_matches,
            CASE
                WHEN cache_key_fp IS NULL THEN 0
                WHEN cache_key_fp = ?9 THEN 1
                ELSE 2
            END AS fingerprint_state,
            CASE WHEN slug = ?10 AND slug != ?3 THEN 1 ELSE 0 END AS legacy
        FROM local_vaults
        WHERE storage_id = ?1 AND id = ?2
        "#,
        binding.storage_id,
        binding.vault_id,
        binding.expected_slug,
        binding.expected_name,
        binding.expected_kind.as_i32(),
        binding.expected_is_default,
        binding.expected_vault_key_enc,
        binding.expected_key_wrap_type.as_i32(),
        binding.target_cache_key_fp,
        LocalVault::local_slug(binding.vault_id)
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalVaultKeyBindError::Database)?
    .ok_or(LocalVaultKeyBindError::NotFound)?;
    let read = |column: &str| -> Result<i64, LocalVaultKeyBindError> {
        current
            .try_get::<i64, _>(column)
            .map_err(LocalVaultKeyBindError::Database)
    };
    let fingerprint = read("fingerprint_state")?;
    if read("identity_matches")? != 1 || !matches!(fingerprint, 0 | 1) {
        return Err(LocalVaultKeyBindError::KeyBindingChanged);
    }
    Ok(BindingState {
        fingerprint,
        legacy: read("legacy")? == 1,
    })
}

async fn inspect_fingerprint_bindings(
    tx: &mut Transaction<'static, Sqlite>,
    bindings: &[CacheKeyFingerprintBinding<'_>],
) -> Result<Vec<BindingState>, LocalVaultKeyBindError> {
    let mut states = Vec::with_capacity(bindings.len());
    for binding in bindings {
        states.push(inspect_binding(tx, binding).await?);
    }
    Ok(states)
}

async fn ensure_storage_projection_empty_for_claim(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
    bindings: &[CacheKeyFingerprintBinding<'_>],
) -> Result<(), LocalVaultKeyBindError> {
    ensure_projection_identifiers_bounded(tx).await?;
    for binding in bindings {
        ensure_vault_projection_empty(tx, storage_id, binding.vault_id).await?;
    }
    for table in [
        "items_cache",
        "sync_cursors",
        "pending_changes",
        "item_history",
    ] {
        let sql = format!("SELECT 1 FROM {table} WHERE storage_id = ?1 LIMIT 1");
        if sqlx_core::query::query::<Sqlite>(&sql)
            .bind(storage_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(LocalVaultKeyBindError::Database)?
            .is_some()
        {
            return Err(LocalVaultKeyBindError::ProjectionNotEmpty);
        }
    }
    Ok(())
}

/// No projection row of the storage belongs to a vault outside its catalog;
/// the exact-catalog check has already made `local_vaults` that catalog.
async fn ensure_storage_projection_within_catalog(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
) -> Result<(), LocalVaultKeyBindError> {
    ensure_projection_identifiers_bounded(tx).await?;
    for table in [
        "items_cache",
        "sync_cursors",
        "pending_changes",
        "item_history",
    ] {
        // `table` comes only from the fixed list above.
        let sql = format!(
            "SELECT 1 FROM {table} WHERE storage_id = ?1 AND vault_id NOT IN \
             (SELECT id FROM local_vaults WHERE storage_id = ?1) LIMIT 1"
        );
        if sqlx_core::query::query::<Sqlite>(&sql)
            .bind(storage_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(LocalVaultKeyBindError::Database)?
            .is_some()
        {
            return Err(LocalVaultKeyBindError::ProjectionNotEmpty);
        }
    }
    Ok(())
}

async fn bind_cache_key_fingerprints_in(
    tx: &mut Transaction<'static, Sqlite>,
    bindings: &[CacheKeyFingerprintBinding<'_>],
) -> Result<CacheKeyFingerprintBatchBind, LocalVaultKeyBindError> {
    let mut requires_update = Vec::with_capacity(bindings.len());
    let mut adopts = Vec::new();

    // Preflight the complete catalog before the first UPDATE. BEGIN IMMEDIATE
    // prevents another writer from invalidating these proofs in between.
    for binding in bindings {
        let state = inspect_binding(tx, binding).await?;
        if state.fingerprint == 1 {
            continue;
        }
        if state.legacy {
            // MIG-009: a vault that predates migration 0002 keeps the
            // projection its legacy client synced, under the internal slug
            // the migration gave it. It takes the catalog's slug and key only
            // when every cached item proves that key.
            ensure_legacy_projection_proven(tx, binding).await?;
            adopts.push(*binding);
        } else {
            ensure_vault_projection_empty(tx, binding.storage_id, binding.vault_id).await?;
            requires_update.push(*binding);
        }
    }

    for binding in &requires_update {
        let updated = query!(
            r#"
            UPDATE local_vaults
            SET cache_key_fp = ?9
            WHERE storage_id = ?1
              AND id = ?2
              AND slug = ?3
              AND name = ?4
              AND kind = ?5
              AND is_default = ?6
              AND vault_key_enc = ?7
              AND key_wrap_type = ?8
              AND cache_key_fp IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM items_cache WHERE storage_id = ?1 AND vault_id = ?2
              )
              AND NOT EXISTS (
                  SELECT 1 FROM sync_cursors WHERE storage_id = ?1 AND vault_id = ?2
              )
              AND NOT EXISTS (
                  SELECT 1 FROM pending_changes WHERE storage_id = ?1 AND vault_id = ?2
              )
              AND NOT EXISTS (
                  SELECT 1 FROM item_history WHERE storage_id = ?1 AND vault_id = ?2
              )
            "#,
            binding.storage_id,
            binding.vault_id,
            binding.expected_slug,
            binding.expected_name,
            binding.expected_kind.as_i32(),
            binding.expected_is_default,
            binding.expected_vault_key_enc,
            binding.expected_key_wrap_type.as_i32(),
            binding.target_cache_key_fp
        )
        .execute(&mut **tx)
        .await
        .map_err(LocalVaultKeyBindError::Database)?
        .rows_affected();
        if updated != 1 {
            return Err(LocalVaultKeyBindError::KeyBindingChanged);
        }
    }

    for binding in &adopts {
        let updated = query!(
            r#"
            UPDATE local_vaults
            SET cache_key_fp = ?9,
                slug = ?3
            WHERE storage_id = ?1
              AND id = ?2
              AND slug = ?10
              AND name = ?4
              AND kind = ?5
              AND is_default = ?6
              AND vault_key_enc = ?7
              AND key_wrap_type = ?8
              AND cache_key_fp IS NULL
              AND EXISTS (
                  SELECT 1 FROM items_cache WHERE storage_id = ?1 AND vault_id = ?2
              )
              AND NOT EXISTS (
                  SELECT 1 FROM items_cache
                  WHERE storage_id = ?1 AND vault_id = ?2 AND cache_key_fp IS NOT ?9
              )
            "#,
            binding.storage_id,
            binding.vault_id,
            binding.expected_slug,
            binding.expected_name,
            binding.expected_kind.as_i32(),
            binding.expected_is_default,
            binding.expected_vault_key_enc,
            binding.expected_key_wrap_type.as_i32(),
            binding.target_cache_key_fp,
            LocalVault::local_slug(binding.vault_id)
        )
        .execute(&mut **tx)
        .await
        .map_err(LocalVaultKeyBindError::Database)?
        .rows_affected();
        if updated != 1 {
            return Err(LocalVaultKeyBindError::KeyBindingChanged);
        }
    }

    let bound = requires_update.len() + adopts.len();
    Ok(CacheKeyFingerprintBatchBind {
        bound,
        already_bound: bindings.len() - bound,
    })
}

/// A legacy vault's projection proves the catalog's key when it caches at
/// least one item, every cached item is encrypted under that key, and every
/// pending change belongs to one of those items. History rows follow their
/// items. Anything else is a projection the key cannot claim.
async fn ensure_legacy_projection_proven(
    tx: &mut Transaction<'static, Sqlite>,
    binding: &CacheKeyFingerprintBinding<'_>,
) -> Result<(), LocalVaultKeyBindError> {
    ensure_projection_identifiers_bounded(tx).await?;
    let proof = query!(
        r#"
        SELECT
            EXISTS(
                SELECT 1 FROM items_cache WHERE storage_id = ?1 AND vault_id = ?2
            ) AS cached,
            EXISTS(
                SELECT 1 FROM items_cache
                WHERE storage_id = ?1 AND vault_id = ?2 AND cache_key_fp IS NOT ?3
            ) AS foreign_key,
            EXISTS(
                SELECT 1 FROM pending_changes AS pending
                WHERE pending.storage_id = ?1 AND pending.vault_id = ?2
                  AND NOT EXISTS (
                      SELECT 1 FROM items_cache AS item
                      WHERE item.storage_id = ?1 AND item.vault_id = ?2
                        AND item.id = pending.item_id
                  )
            ) AS orphan_pending
        "#,
        binding.storage_id,
        binding.vault_id,
        binding.target_cache_key_fp
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(LocalVaultKeyBindError::Database)?;
    let flag = |column: &str| -> Result<bool, LocalVaultKeyBindError> {
        proof
            .try_get::<i64, _>(column)
            .map(|value| value != 0)
            .map_err(LocalVaultKeyBindError::Database)
    };
    if !flag("cached")? || flag("foreign_key")? || flag("orphan_pending")? {
        return Err(LocalVaultKeyBindError::ProjectionNotEmpty);
    }
    Ok(())
}

async fn ensure_vault_projection_empty(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
    vault_id: Uuid,
) -> Result<(), LocalVaultKeyBindError> {
    ensure_projection_identifiers_bounded(tx).await?;
    let references = query!(
        r#"
        SELECT
            EXISTS(
                SELECT 1 FROM items_cache WHERE storage_id = ?1 AND vault_id = ?2
            ) AS items,
            EXISTS(
                SELECT 1 FROM sync_cursors WHERE storage_id = ?1 AND vault_id = ?2
            ) AS checkpoints,
            EXISTS(
                SELECT 1 FROM pending_changes WHERE storage_id = ?1 AND vault_id = ?2
            ) AS pending,
            EXISTS(
                SELECT 1 FROM item_history WHERE storage_id = ?1 AND vault_id = ?2
            ) AS history
        "#,
        storage_id,
        vault_id
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(LocalVaultKeyBindError::Database)?;
    for column in ["items", "checkpoints", "pending", "history"] {
        let present: i64 = references
            .try_get(column)
            .map_err(LocalVaultKeyBindError::Database)?;
        if present != 0 {
            return Err(LocalVaultKeyBindError::ProjectionNotEmpty);
        }
    }
    Ok(())
}

async fn ensure_projection_identifiers_bounded(
    tx: &mut Transaction<'static, Sqlite>,
) -> Result<(), LocalVaultKeyBindError> {
    const TABLES: [&str; 4] = [
        "items_cache",
        "sync_cursors",
        "pending_changes",
        "item_history",
    ];
    for table in TABLES {
        // `table` comes only from the fixed list above. The query selects a
        // scalar and reads identifier metadata through typeof/octet_length.
        let sql = format!(
            "SELECT 1 FROM {table} WHERE CASE \
             WHEN typeof(storage_id) NOT IN ('blob', 'text') THEN 1 \
             WHEN octet_length(storage_id) NOT IN (16, 36) THEN 1 \
             WHEN typeof(vault_id) NOT IN ('blob', 'text') THEN 1 \
             WHEN octet_length(vault_id) NOT IN (16, 36) THEN 1 \
             ELSE 0 END LIMIT 1"
        );
        let corrupt = sqlx_core::query::query::<Sqlite>(&sql)
            .fetch_optional(&mut **tx)
            .await
            .map_err(LocalVaultKeyBindError::Database)?;
        if corrupt.is_some() {
            return Err(LocalVaultKeyBindError::KeyBindingChanged);
        }
    }
    Ok(())
}

fn validate_vault(vault: &LocalVault) -> Result<(), sqlx_core::Error> {
    if vault.name.is_empty()
        || vault.name.len() > MAX_LOCAL_VAULT_NAME_BYTES
        || !valid_vault_slug(&vault.slug)
        || vault.vault_key_enc.len() > MAX_LOCAL_VAULT_KEY_ENVELOPE_BYTES
        || vault
            .cache_key_fp
            .as_deref()
            .is_some_and(|fingerprint| !valid_cache_key_fingerprint(fingerprint))
    {
        return Err(invalid_vault_input());
    }
    Ok(())
}

fn valid_vault_slug(slug: &str) -> bool {
    let is_remote = !slug.is_empty()
        && slug.len() <= MAX_LOCAL_VAULT_SLUG_BYTES
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    let is_internal = slug.len() == LOCAL_VAULT_INTERNAL_SLUG_BYTES
        && slug.starts_with("local::")
        && slug["local::".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    is_remote || is_internal
}

fn valid_cache_key_fingerprint(fingerprint: &str) -> bool {
    fingerprint.len() == LOCAL_VAULT_CACHE_KEY_FP_BYTES
        && fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn map_projection_read_key_error(error: LocalProjectionReadError) -> LocalVaultKeyBindError {
    match error {
        LocalProjectionReadError::InvalidInput => LocalVaultKeyBindError::InvalidInput,
        LocalProjectionReadError::CorruptProjection | LocalProjectionReadError::TooManyRows => {
            LocalVaultKeyBindError::KeyBindingChanged
        }
        LocalProjectionReadError::Database(error) => LocalVaultKeyBindError::Database(error),
    }
}

fn map_storage_proof_key_error(error: LocalSyncError) -> LocalVaultKeyBindError {
    match error {
        LocalSyncError::Database(error) => LocalVaultKeyBindError::Database(error),
        LocalSyncError::StorageBindingChanged { .. } => LocalVaultKeyBindError::KeyBindingChanged,
        LocalSyncError::StorageGenerationChanged { .. } => {
            LocalVaultKeyBindError::GenerationChanged
        }
        _ => LocalVaultKeyBindError::InvalidInput,
    }
}

fn invalid_vault_input() -> sqlx_core::Error {
    sqlx_core::Error::Protocol("invalid local vault persistence row".to_string())
}
