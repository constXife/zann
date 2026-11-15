//! Account, capability and catalog admission before local reconciliation.
use super::*;
impl SyncEngine {
    /// Authorizes the target, resolves its local projection against the
    /// session's bindings and fetches the server's catalog. Nothing local is
    /// committed yet.
    pub(super) async fn open_catalog(
        &self,
        target: &SessionTarget,
        operation: &SessionOperation,
    ) -> Result<OpenedCatalog<'_>, SyncError> {
        let operation_id = operation.operation_id();
        self.ensure_dispatchable(operation, SyncStage::Authorization)?;
        self.report(operation_id, SyncProgressPhase::Authorizing, 0, 0, 0, 0);
        let access = self
            .authorizer
            .authorize(target, operation.detached_copy())
            .await
            .map_err(map_session_error)?;

        self.key_origin
            .admit_policy(access.personal_vaults_enabled())
            .map_err(|source| {
                SyncError::new(
                    operation_id,
                    SyncErrorKind::AccountKeyEnrollmentRequired,
                    SyncStage::Authorization,
                )
                .with_source(std::io::Error::other(source))
            })?;

        let access_storage_id = access
            .storage_id()
            .and_then(|value| Uuid::parse_str(value).ok())
            .filter(|value| !value.is_nil())
            .ok_or_else(|| {
                SyncError::new(
                    operation_id,
                    SyncErrorKind::NoLocalTarget,
                    SyncStage::ResolveTarget,
                )
            })?;
        let access_account_subject = access
            .account_subject()
            .filter(|subject| {
                Uuid::parse_str(subject).is_ok_and(|parsed| parsed.to_string() == *subject)
            })
            .ok_or_else(|| {
                SyncError::new(
                    operation_id,
                    SyncErrorKind::AccountBindingRequired,
                    SyncStage::ResolveTarget,
                )
            })?;
        let access_auth_method = access.auth_method().ok_or_else(|| {
            SyncError::new(
                operation_id,
                SyncErrorKind::AuthenticationBindingRequired,
                SyncStage::ResolveTarget,
            )
        })?;

        self.ensure_dispatchable(operation, SyncStage::ResolveTarget)?;
        let authorized_target_generation = access.authorized_target_generation();
        let resolved = self
            .local
            .resolve_target(
                target,
                authorized_target_generation,
                access.personal_vaults_enabled(),
            )
            .await
            .map_err(|error| map_store_error(operation_id, SyncStage::ResolveTarget, error))?;
        if resolved.storage_id() != access_storage_id
            || resolved.binding().server_url() != access.endpoint()
            || resolved.binding().server_fingerprint() != access.server_fingerprint()
        {
            return Err(SyncError::new(
                operation_id,
                SyncErrorKind::ConcurrentLocalChange,
                SyncStage::ResolveTarget,
            ));
        }
        if resolved.binding().account_subject() != Some(access_account_subject) {
            return Err(SyncError::new(
                operation_id,
                SyncErrorKind::AccountBindingMismatch,
                SyncStage::ResolveTarget,
            ));
        }
        if resolved.binding().personal_vaults_enabled() != access.personal_vaults_enabled() {
            return Err(SyncError::new(
                operation_id,
                SyncErrorKind::ServerCapabilityMismatch,
                SyncStage::ResolveTarget,
            ));
        }
        let local_auth_method = resolved.binding().auth_method().ok_or_else(|| {
            SyncError::new(
                operation_id,
                SyncErrorKind::AuthenticationBindingRequired,
                SyncStage::ResolveTarget,
            )
        })?;
        if local_auth_method != access_auth_method {
            return Err(SyncError::new(
                operation_id,
                SyncErrorKind::AuthenticationBindingMismatch,
                SyncStage::ResolveTarget,
            ));
        }

        self.ensure_dispatchable(operation, SyncStage::Catalog)?;
        self.report(operation_id, SyncProgressPhase::Catalog, 0, 0, 0, 0);
        let remote = self.remote.as_ref().map_err(|_| {
            SyncError::new(
                operation_id,
                SyncErrorKind::TransportUnavailable,
                SyncStage::Catalog,
            )
        })?;
        let timeout = request_timeout(operation, SyncStage::Catalog)?;
        let catalog = await_remote(
            operation,
            SyncStage::Catalog,
            remote.fetch_catalog(&access, timeout),
        )
        .await?;
        if !access.personal_vaults_enabled()
            && catalog
                .vaults()
                .iter()
                .any(|vault| vault.plane() == VaultPlane::PersonalClient)
        {
            return Err(SyncError::new(
                operation_id,
                SyncErrorKind::ServerCapabilityMismatch,
                SyncStage::Catalog,
            ));
        }
        Ok(OpenedCatalog {
            remote,
            access,
            resolved,
            catalog,
        })
    }
}
