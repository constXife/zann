//! Canonical key proof before either enrollment or synchronization can persist cache data.
use super::*;
use crate::config::{ConfigSnapshot, SyncCommitLease};

/// The config lease and facade admission stay alive through the SQLite keyring CAS.
pub struct AccountKeyEnrollment {
    _lease: SyncCommitLease,
    _permit: Arc<AppSyncPermit>,
    pub storage_id: String,
    pub server_id: String,
    pub account_subject: String,
}

impl AppClient {
    pub(super) async fn proven_sync_store(
        &self,
        target: &SessionTarget,
        master_key: &Arc<SecretKey>,
        permit: Arc<AppSyncPermit>,
        operation: &SessionOperation,
    ) -> Result<Arc<dyn SyncLocalStore>, SyncError> {
        let operation_id = operation.operation_id();
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(SyncError::new(
                operation_id,
                SyncErrorKind::Local,
                SyncStage::ResolveTarget,
            ));
        }
        let fingerprint = zann_crypto::cache_key_fingerprint(master_key);
        let open = || {
            open_operation_store(
                Arc::clone(&self.sync_store_factory),
                self.paths.clone(),
                target.clone(),
                Arc::clone(master_key),
                Arc::clone(&permit),
                operation,
            )
        };

        let local = open().await?;
        let anchor = self
            .repository
            .resolve_credential_profile_anchor(target.connection_id(), target.profile_name())
            .map_err(|source| {
                SyncError::new(operation_id, SyncErrorKind::Local, SyncStage::ResolveTarget)
                    .with_source(source)
            })?;
        let crypto_error = || {
            SyncError::new(
                operation_id,
                SyncErrorKind::Crypto,
                SyncStage::ResolveTarget,
            )
        };
        let local = match anchor.expected_master_key_fp() {
            Some(bound) if bound == fingerprint => local,
            Some(_) => return Err(crypto_error()),
            None => {
                SyncEngine::new(self.session.clone(), local)
                    .prove_and_bind_master_key(target, master_key, operation, |access| {
                        bind_proven_master_key(&self.repository, target, access, &fingerprint)
                    })
                    .await?;
                // The proof's lease resolved the unbound generation, which
                // the bind has just superseded.
                open().await?
            }
        };
        Ok(local)
    }

    /// Captures the exact active profile without remote I/O and excludes config
    /// mutations until the caller publishes its corresponding local selection.
    pub async fn active_account_key_lease(
        &self,
        target: &SessionTarget,
    ) -> Result<SyncCommitLease, ConfigError> {
        let snapshot = self.repository.snapshot()?;
        let config = snapshot.config();
        let active = config
            .clients
            .get(&self.client_id)
            .and_then(|client| client.active_connection());
        if active.is_some_and(|id| id != target.connection_id())
            || (active.is_none() && config.connections.len() != 1)
            || config
                .connections
                .get(target.connection_id())
                .and_then(|connection| connection.active_credential())
                != Some(target.profile_name())
        {
            return Err(ConfigError::IdentityChanged);
        }
        let generation = self.repository.authorized_target_generation_from_snapshot(
            &snapshot,
            target.connection_id(),
            target.profile_name(),
        )?;
        self.repository.acquire_sync_commit_lease(&generation).await
    }

    pub async fn prepare_account_key(
        &self,
        target: &SessionTarget,
        key: Arc<SecretKey>,
        expected_identity: &ConfigIdentity,
        operation: SessionOperation,
    ) -> Result<AccountKeyEnrollment, SyncError> {
        let operation_id = operation.operation_id();
        let conflict = || {
            SyncError::new(
                operation_id,
                SyncErrorKind::ConcurrentLocalChange,
                SyncStage::ResolveTarget,
            )
        };
        let source = self
            .repository
            .snapshot()
            .map_err(|source| conflict().with_source(source))?;
        if self
            .account_identity(target)
            .map_err(|source| conflict().with_source(source))?
            != *expected_identity
        {
            return Err(conflict());
        }
        let source_binding = enrollment_binding(&source, target).ok_or_else(conflict)?;
        let permit = Arc::new(AppSyncPermit::try_acquire().map_err(|_| conflict())?);
        let _store = self
            .proven_sync_store(target, &key, permit.clone(), &operation)
            .await?;
        let snapshot = self
            .repository
            .snapshot()
            .map_err(|source| conflict().with_source(source))?;
        let binding = enrollment_binding(&snapshot, target).ok_or_else(conflict)?;
        let identity = snapshot.config().account_identities.get(&format!(
            "{}/{}",
            target.connection_id(),
            target.profile_name()
        ));
        if source_binding != binding
            || identity != Some(expected_identity)
            || snapshot
                .config()
                .clients
                .get(&self.client_id)
                .and_then(|client| client.active_connection())
                .is_some_and(|active| active != target.connection_id())
        {
            return Err(conflict());
        }
        let generation = self
            .repository
            .authorized_target_generation_from_snapshot(
                &snapshot,
                target.connection_id(),
                target.profile_name(),
            )
            .map_err(|source| conflict().with_source(source))?;
        let lease = self
            .repository
            .acquire_sync_commit_lease(&generation)
            .await
            .map_err(|source| conflict().with_source(source))?;
        Ok(AccountKeyEnrollment {
            _lease: lease,
            _permit: permit,
            storage_id: binding.0,
            server_id: binding.1,
            account_subject: binding.4,
        })
    }
}

// Stable account binding deliberately excludes refreshable credential ids and expiry.
fn enrollment_binding(
    snapshot: &ConfigSnapshot,
    target: &SessionTarget,
) -> Option<(String, String, String, String, String, AuthMethod)> {
    let connection = snapshot.config().connections.get(target.connection_id())?;
    let metadata = connection.metadata();
    let profile = connection
        .credential_profiles()
        .get(target.profile_name())?;
    Some((
        metadata.storage_id.clone()?,
        metadata.server_id.clone()?,
        metadata.address.clone(),
        metadata.server_fingerprint.clone()?,
        profile.account_subject()?.to_owned(),
        profile.auth_method()?,
    ))
}
