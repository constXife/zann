//! The account's personal vault keys inside a sync: publishing the first key
//! of a personal vault the server left uninitialized, and proving a master
//! key against the catalog before a connection that has not bound one binds
//! it. Binding an unproven key would keep a mistyped master password, or the
//! loser of two devices racing to publish the first key, bound for good.

use std::sync::Arc;

use zann_crypto::SecretKey;

use super::{await_remote, map_store_error, request_timeout, OpenedCatalog, SyncEngine};
use crate::session::{SessionAccess, SessionOperation, SessionTarget};
use crate::sync::account_key::{check_catalog, AccountKeyCheck};
use crate::sync::model::{
    CatalogSnapshot, CatalogVault, ResolvedSyncTarget, SyncError, SyncErrorKind, SyncScope,
    SyncStage, VaultPlane,
};
use crate::sync::transport::SyncRemote;

#[cfg_attr(not(feature = "app"), allow(dead_code))]
impl SyncEngine {
    /// Proves `master_key` for a connection with no master-key binding and
    /// calls `bind` with the session it was proved for only once it is
    /// proved.
    ///
    /// The key is proved when it opens every published personal vault key,
    /// or when this device publishes the account's first one. A server
    /// without personal vaults wraps nothing with the key, so there it only
    /// guards this device's cache and needs no proof. Nothing is reconciled
    /// or committed locally: the store may resolve the target with the key
    /// still unbound, and the caller syncs afresh once it is bound.
    pub(crate) async fn prove_and_bind_master_key(
        &self,
        target: &SessionTarget,
        master_key: &SecretKey,
        operation: &SessionOperation,
        bind: impl FnOnce(&SessionAccess) -> Result<(), SyncError>,
    ) -> Result<(), SyncError> {
        let operation_id = operation.operation_id();
        let OpenedCatalog {
            remote,
            access,
            resolved,
            mut catalog,
        } = self.open_catalog(target, operation).await?;
        let mut check = check_catalog(master_key, &catalog);
        if check == AccountKeyCheck::Unpublished {
            self.publish_uninitialized_keys(remote, &access, &resolved, &mut catalog, operation)
                .await?;
            check = check_catalog(master_key, &catalog);
        }
        match check {
            AccountKeyCheck::Matches => {}
            AccountKeyCheck::Unpublished if !access.personal_vaults_enabled() => {}
            AccountKeyCheck::Mismatch => {
                return Err(SyncError::new(
                    operation_id,
                    SyncErrorKind::Crypto,
                    SyncStage::Catalog,
                ));
            }
            // The server creates every account's personal vault at sign-in,
            // so a catalog without one leaves the key unproved.
            AccountKeyCheck::Unpublished => {
                return Err(SyncError::new(
                    operation_id,
                    SyncErrorKind::Protocol,
                    SyncStage::Catalog,
                ));
            }
        }
        self.ensure_dispatchable(operation, SyncStage::ResolveTarget)?;
        bind(&access)
    }

    /// Generates, publishes and installs a key for every personal vault the
    /// catalog lists without one. The adapter generates and wraps the key;
    /// the server initializes each vault key at most once.
    pub(super) async fn publish_uninitialized_keys(
        &self,
        remote: &Arc<dyn SyncRemote>,
        access: &SessionAccess,
        resolved: &ResolvedSyncTarget,
        catalog: &mut CatalogSnapshot,
        operation: &SessionOperation,
    ) -> Result<(), SyncError> {
        let operation_id = operation.operation_id();
        let internal = || {
            SyncError::new(
                operation_id,
                SyncErrorKind::Internal,
                SyncStage::ReconcileCatalog,
            )
        };
        let uninitialized = catalog
            .vaults()
            .iter()
            .filter(|vault| {
                vault.plane() == VaultPlane::PersonalClient && vault.vault_key_envelope().is_empty()
            })
            .map(CatalogVault::id)
            .collect::<Vec<_>>();
        for vault_id in uninitialized {
            self.ensure_dispatchable(operation, SyncStage::ReconcileCatalog)?;
            let scope = SyncScope::new(resolved.storage_id(), vault_id).map_err(|_| {
                SyncError::new(
                    operation_id,
                    SyncErrorKind::Protocol,
                    SyncStage::ReconcileCatalog,
                )
            })?;
            let publication = Arc::clone(&self.local)
                .prepare_generated_key(scope, Vec::new())
                .await
                .map_err(|error| {
                    map_store_error(operation_id, SyncStage::ReconcileCatalog, error)
                })?;
            let published_envelope = publication.published_envelope().to_vec();
            let timeout = request_timeout(operation, SyncStage::Catalog)?;
            await_remote(
                operation,
                SyncStage::Catalog,
                remote.publish_personal_vault_key(access, vault_id, &published_envelope, timeout),
            )
            .await?;
            tokio::spawn(Arc::clone(&self.local).commit_generated_key(publication))
                .await
                .map_err(|_| internal())?
                .map_err(|error| {
                    map_store_error(operation_id, SyncStage::ReconcileCatalog, error)
                })?;
            catalog
                .install_generated_envelope(vault_id, &[], published_envelope)
                .map_err(|_| internal())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
