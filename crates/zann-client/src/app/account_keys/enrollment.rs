//! Verified account-key enrollment; retains the Config lease through keyring publication.
use super::*;
impl AppClient {
    pub async fn prepare_account_key(
        &self,
        target: &SessionTarget,
        key: Arc<SecretKey>,
        origin: AccountKeyOrigin,
        expected_identity: Option<&ConfigIdentity>,
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
        let slot = format!("{}/{}", target.connection_id(), target.profile_name());
        if (origin == AccountKeyOrigin::AccountPassword) != expected_identity.is_some()
            || expected_identity.is_some_and(|identity| {
                source.config().account_identities.get(&slot) != Some(identity)
            })
        {
            return Err(conflict());
        }
        let source_binding = enrollment_binding(&source, target).ok_or_else(conflict)?;
        let permit = Arc::new(AppSyncPermit::try_acquire().map_err(|_| conflict())?);
        if self
            .account_key_requirement(target, operation.detached_copy())
            .await?
            != origin
        {
            return Err(SyncError::new(
                operation_id,
                SyncErrorKind::AccountKeyEnrollmentRequired,
                SyncStage::Authorization,
            ));
        }
        if origin == AccountKeyOrigin::LocalCacheKey {
            let bound = source.config().connections[target.connection_id()].credential_profiles()
                [target.profile_name()]
            .expected_master_key_fp();
            if bound.is_some() {
                return Err(SyncError::new(
                    operation_id,
                    SyncErrorKind::Crypto,
                    SyncStage::ResolveTarget,
                ));
            }
            let local = open_operation_store(
                Arc::clone(&self.sync_store_factory),
                self.paths.clone(),
                target.clone(),
                Arc::clone(&key),
                Arc::clone(&permit),
                &operation,
            )
            .await?;
            // Resolve the exact cache and authenticated shared-only catalog, but
            // do NOT bind a random key in Config before the keyring CAS. If that
            // CAS fails, retry may safely generate a key; after it succeeds,
            // normal sync binds the durable key's fingerprint.
            SyncEngine::new(self.session.clone(), local, origin)
                .prove_and_bind_master_key(target, &key, &operation, |_| Ok(()))
                .await?;
        } else {
            self.proven_sync_store(target, &key, origin, permit.clone(), &operation)
                .await?;
        }
        if self
            .account_key_requirement(target, operation.detached_copy())
            .await?
            != origin
        {
            return Err(SyncError::new(
                operation_id,
                SyncErrorKind::AccountKeyEnrollmentRequired,
                SyncStage::Authorization,
            ));
        }
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
            || expected_identity.is_some_and(|expected| identity != Some(expected))
            || snapshot
                .config()
                .clients
                .get(&self.client_id)
                .and_then(|client| client.active_connection())
                .is_some_and(|active| active != target.connection_id())
        {
            return Err(conflict());
        }
        if snapshot.config().connections[target.connection_id()].active_credential()
            != Some(target.profile_name())
        {
            return Err(conflict());
        }
        let bound = snapshot.config().connections[target.connection_id()].credential_profiles()
            [target.profile_name()]
        .expected_master_key_fp();
        if bound.is_some_and(|value| value != zann_crypto::cache_key_fingerprint(&key)) {
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
        ensure_operation_dispatchable(&operation)?;
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
        profile.storage_id()?.to_owned(),
        metadata.server_id.clone()?,
        metadata.address.clone(),
        metadata.server_fingerprint.clone()?,
        profile.account_subject()?.to_owned(),
        profile.auth_method()?,
    ))
}
