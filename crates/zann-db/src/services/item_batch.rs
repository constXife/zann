//! One SQLite write transaction for bounded, prevalidated local creation batches.
use super::*;
use crate::local::{KeyWrapType, LocalItem};
use sqlx_core::{query_as::query_as, transaction::Transaction};
use sqlx_sqlite::Sqlite;
type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct PreparedItemBatch {
    transaction: Transaction<'static, Sqlite>,
    vault: LocalVault,
    key: SecretKey,
}
impl LocalServices<'_> {
    pub async fn begin_item_batch(
        &self,
        storage: Uuid,
        vault: Uuid,
    ) -> Result<PreparedItemBatch, Error> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| stage("begin write", error))?;
        let vault = LocalVaultRepo::get_by_id_in_bounded(&mut transaction, storage, vault)
            .await
            .map_err(|error| stage("vault lookup", error))?
            .ok_or_else(|| ServiceError::new("vault_not_found", "vault not found"))?;
        let key = if vault.kind == VaultKind::Shared {
            SecretKey::from_bytes(*self.master_key.as_bytes())
        } else {
            self.decrypt_vault_key(&vault)?
        };
        Ok(PreparedItemBatch {
            transaction,
            vault,
            key,
        })
    }
}
impl PreparedItemBatch {
    pub fn vault(&self) -> &LocalVault {
        &self.vault
    }
    /// The scalar preflight bounds both row count and total resident ciphertext/metadata.
    pub async fn read_type(
        &mut self,
        type_id: &str,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<Vec<(LocalItem, EncryptedPayload)>, Error> {
        let (count, bytes): (i64, i64) = query_as("SELECT count(*),coalesce(sum(length(payload_enc)+length(coalesce(metadata,''))+length(path)+length(name)),0) FROM (SELECT payload_enc,metadata,path,name FROM items_cache WHERE storage_id=? AND vault_id=? AND type_id=? AND deleted_at IS NULL LIMIT ?)")
            .bind(self.vault.storage_id).bind(self.vault.id).bind(type_id).bind(i64::try_from(max_rows)?.checked_add(1).ok_or("item batch limit")?).fetch_one(&mut *self.transaction).await?;
        if count > i64::try_from(max_rows)? || bytes > i64::try_from(max_bytes)? {
            return Err(ServiceError::new("item_batch_limit", "item batch limit exceeded").into());
        }
        let rows: Vec<LocalItem> = query_as("SELECT * FROM items_cache WHERE storage_id=? AND vault_id=? AND type_id=? AND deleted_at IS NULL ORDER BY id LIMIT ?")
            .bind(self.vault.storage_id).bind(self.vault.id).bind(type_id).bind(i64::try_from(max_rows)?).fetch_all(&mut *self.transaction).await?;
        rows.into_iter()
            .map(|item| {
                if item.checksum != core_crypto::payload_checksum(&item.payload_enc) {
                    return Err(
                        ServiceError::new("payload_checksum", "payload checksum mismatch").into(),
                    );
                }
                let bytes = Zeroizing::new(core_crypto::decrypt_payload_bytes(
                    &self.key,
                    self.vault.id,
                    item.id,
                    &item.payload_enc,
                )?);
                let payload = EncryptedPayload::from_bytes(&bytes)?;
                Ok((item, payload))
            })
            .collect()
    }
    pub async fn add(
        &mut self,
        path: String,
        type_id: String,
        payload: EncryptedPayload,
        metadata: zann_core::ItemMetadata,
    ) -> Result<Uuid, Error> {
        let path = LocalServices::validate_item_input(&path, &type_id, &payload, &metadata)?;
        zann_core::item_policy::admit_item_type(
            &type_id,
            self.vault.kind,
            if self.vault.key_wrap_type == KeyWrapType::RemoteServer {
                zann_core::VaultEncryptionType::Server
            } else {
                zann_core::VaultEncryptionType::Client
            },
        )?;
        let exists: Option<(i64,)> = query_as("SELECT 1 FROM items_cache WHERE storage_id=? AND vault_id=? AND path=? AND deleted_at IS NULL LIMIT 1")
            .bind(self.vault.storage_id).bind(self.vault.id).bind(&path).fetch_optional(&mut *self.transaction).await?;
        if exists.is_some() {
            return Err(ServiceError::new("item_exists", "item already exists").into());
        }
        let id = Uuid::now_v7();
        let bytes = Zeroizing::new(payload.to_bytes()?);
        let payload_enc = core_crypto::encrypt_payload_bytes(&self.key, self.vault.id, id, &bytes)?;
        let item = LocalItem {
            id,
            storage_id: self.vault.storage_id,
            vault_id: self.vault.id,
            name: LocalServices::name_from_path(&path),
            path,
            type_id,
            checksum: LocalServices::payload_checksum(&payload_enc),
            payload_enc,
            cache_key_fp: Some(LocalServices::key_fingerprint(&self.key)),
            metadata: Some(metadata),
            version: 1,
            deleted_at: None,
            updated_at: Utc::now(),
            sync_status: SyncStatus::Modified,
        };
        super::create_item::insert_created_item(&mut self.transaction, &item).await?;
        Ok(id)
    }
    /// Preserve the original error while completing rollback before a retry.
    /// Drop remains the cancellation path when the caller future is abandoned.
    pub async fn rollback_for_error<E: Into<Error>>(self, original: E) -> Result<E, Error> {
        match self.transaction.rollback().await {
            Ok(()) => Ok(original),
            Err(error) => Err(Box::new(RollbackFailure {
                original: original.into(),
                rollback: stage("rollback", error),
            })),
        }
    }
    /// Caller must await the commit result once publication starts.
    pub async fn commit(self) -> Result<(), Error> {
        self.transaction
            .commit()
            .await
            .map_err(|error| stage("commit", error))?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("item batch {stage} failed: {source}")]
struct StageError {
    stage: &'static str,
    #[source]
    source: Error,
}
pub(super) fn stage(stage: &'static str, source: impl Into<Error>) -> Error {
    Box::new(StageError {
        stage,
        source: source.into(),
    })
}
#[derive(Debug, thiserror::Error)]
#[error("item creation failed: {original}; rollback failed: {rollback}")]
struct RollbackFailure {
    #[source]
    original: Error,
    rollback: Error,
}
