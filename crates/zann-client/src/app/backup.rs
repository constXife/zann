//! Catalog preparation for restoring backups; no files or plaintext payloads cross this boundary.
use super::*;
pub const BACKUP_MAX_VAULTS: usize = crate::sync::MAX_CATALOG_VAULTS;
use crate::sync::transport::{HttpSyncRemote, SyncRemote};

/// A vault identity in the source backup. Personal vaults always map to the account's personal vault.
#[derive(Clone)]
pub struct BackupVaultSpec {
    pub source_id: Uuid,
    pub name: String,
    pub kind: zann_core::VaultKind,
}

impl BackupVaultSpec {
    pub fn import_slug(&self) -> String {
        format!("import-{}", self.source_id.simple())
    }
}

impl AppClient {
    /// Create missing shared vaults through the pinned authenticated session.
    /// The caller syncs before and after this operation to reconcile the canonical catalog.
    async fn prepare_backup_vaults(
        &self,
        target: SessionTarget,
        vaults: &[BackupVaultSpec],
        operation: SessionOperation,
    ) -> Result<(), SyncError> {
        use crate::sync::{SyncErrorKind, SyncStage};
        let error = |kind| SyncError::new(operation.operation_id(), kind, SyncStage::Catalog);
        if vaults.len() > BACKUP_MAX_VAULTS
            || vaults
                .iter()
                .any(|v| v.source_id.is_nil() || v.name.trim().is_empty() || v.name.len() > 200)
        {
            return Err(error(SyncErrorKind::LimitExceeded));
        }
        let access = self
            .session
            .access(&target, operation.detached_copy())
            .await
            .map_err(crate::sync::map_session_error)?;
        let remote =
            HttpSyncRemote::new().map_err(|_| error(SyncErrorKind::TransportUnavailable))?;
        let timeout = || {
            operation
                .deadline()
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| error(SyncErrorKind::DeadlineExceeded))
        };
        let catalog = crate::sync::await_remote(
            &operation,
            SyncStage::Catalog,
            remote.fetch_catalog(&access, timeout()?),
        )
        .await?;
        let mut total = catalog.vaults().len();
        // Resolve by identity, never by display name: names are not unique.
        let exists = |source: &BackupVaultSpec| -> Result<bool, SyncError> {
            if let Some(found) = catalog
                .vaults()
                .iter()
                .find(|v| v.id() == source.source_id || v.slug() == source.import_slug())
            {
                if found.plane() != crate::sync::VaultPlane::SharedServer {
                    return Err(error(SyncErrorKind::Protocol));
                }
                return Ok(true);
            }
            Ok(false)
        };
        for vault in vaults
            .iter()
            .filter(|v| v.kind == zann_core::VaultKind::Shared)
        {
            exists(vault)?;
        }
        let mut created = std::collections::HashSet::new();
        if vaults
            .iter()
            .any(|v| v.kind == zann_core::VaultKind::Personal)
            && !catalog
                .vaults()
                .iter()
                .any(|v| v.plane() == crate::sync::VaultPlane::PersonalClient)
        {
            return Err(error(SyncErrorKind::ServerCapabilityMismatch));
        }
        for vault in vaults {
            if operation.is_cancelled() {
                return Err(error(SyncErrorKind::Cancelled));
            }
            if vault.kind == zann_core::VaultKind::Shared
                && !exists(vault)?
                && created.insert(vault.source_id)
            {
                total += 1;
                if total > BACKUP_MAX_VAULTS {
                    return Err(error(SyncErrorKind::LimitExceeded));
                }
                crate::sync::await_remote(
                    &operation,
                    SyncStage::Catalog,
                    Box::pin(remote.create_backup_vault(
                        &access,
                        &vault.import_slug(),
                        &vault.name,
                        timeout()?,
                    )),
                )
                .await?;
            }
        }
        Ok(())
    }
}

/// An explicitly selected authenticated import operation. It grants only catalog
/// preparation and synchronization, never bearer access or arbitrary HTTP.
pub struct BackupImportSession {
    client: AppClient,
    target: SessionTarget,
    storage_id: String,
    key: SecretKey,
    operation: SessionOperation,
}
impl AppClient {
    pub fn backup_import_session(
        &self,
        storage_id: &str,
        key: SecretKey,
        operation: SessionOperation,
    ) -> Result<BackupImportSession, SessionError> {
        Ok(BackupImportSession {
            client: self.clone(),
            target: self.configured_target(Some(storage_id))?,
            storage_id: storage_id.into(),
            key,
            operation,
        })
    }
}
impl BackupImportSession {
    pub fn storage_id(&self) -> &str {
        &self.storage_id
    }
    pub fn is_cancelled(&self) -> bool {
        self.operation.is_cancelled()
    }
    pub fn deadline(&self) -> std::time::Instant {
        self.operation.deadline()
    }
    pub async fn sync(&self) -> Result<SyncOutcome, SyncError> {
        self.client
            .sync(
                self.target.clone(),
                SecretKey::from_bytes(*self.key.as_bytes()),
                self.operation.detached_copy(),
            )
            .await
    }
    pub async fn prepare_vaults(&self, vaults: &[BackupVaultSpec]) -> Result<(), SyncError> {
        self.client
            .prepare_backup_vaults(self.target.clone(), vaults, self.operation.detached_copy())
            .await
    }
}
