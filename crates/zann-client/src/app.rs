//! Database-free application facade for authenticated, existing-target flows.
//!
//! This module composes the internal session owner with a caller-injected sync
//! persistence factory. It deliberately exposes neither that owner nor the sync
//! engine, so shells cannot extract bearer material or bypass target policy.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use uuid::Uuid;
use zann_core::AuthMethod;

pub use zann_crypto::SecretKey;

pub use crate::config::{
    ClientId, ClientPaths, ConnectionId, CredentialId, CredentialPortError,
    CredentialPortErrorKind, CredentialSecret, CredentialStore, LegacyCredentialSource,
};
use crate::session::AppSession;
pub use crate::session::{
    AccessSource, LegacySessionImport, LocalLogoutStatus, LoginPassword, LogoutOutcome,
    OidcLoginInput, OidcLoginInputError, OidcToken, OperationCompletion, PasswordLoginInputError,
    PasswordLoginRequest, PasswordRegistrationRequest, RemoteLogoutStatus, SessionAccess,
    SessionCancellationHandle, SessionClient, SessionError, SessionErrorKind, SessionOperation,
    SessionOperationId, SessionTarget, SessionTargetError,
};
use crate::sync::{SyncEngine, SyncFuture};
pub use crate::sync::{
    SyncError, SyncErrorKind, SyncOutcome, SyncOutcomeStatus, SyncProgress, SyncProgressPhase,
    SyncProgressSink, SyncStage,
};
use crate::{config::ConfigRepository, remote::auth::AuthHttpTransport};

/// Narrow persistence-adapter SPI. It contains bounded plans, opaque proofs
/// and the transactional local-store port, but no session or sync owner.
pub mod spi {
    pub use crate::config::AuthorizedTargetGeneration;
    pub use crate::sync::{
        CatalogSnapshot, CatalogVault, ContentChecksum, GeneratedVaultKeyCommit, HistoryAuthority,
        HistoryProjection, ItemProjection, ItemProof, ItemState, PendingExpectation, PendingProof,
        ProjectionReset, PullCommitChange, PullCommitReceipt, PullPageCommit, PushCommitChange,
        PushCommitPlan, PushCommitReceipt, ReconciledCatalog, ResolvedSyncTarget,
        ResolvedSyncVault, StorageBindingProof, SyncCheckpoint, SyncCursor, SyncLocalStore,
        SyncModelError, SyncScope, SyncSeq, SyncStoreError, SyncStoreErrorKind, SyncStoreFuture,
        VaultPayloadKey, VaultPlane,
    };
}

use spi::{
    AuthorizedTargetGeneration, CatalogSnapshot, GeneratedVaultKeyCommit, ItemState,
    ProjectionReset, PullCommitReceipt, PullPageCommit, PushCommitPlan, PushCommitReceipt,
    ReconciledCatalog, ResolvedSyncTarget, SyncCheckpoint, SyncLocalStore, SyncScope,
    SyncStoreError, SyncStoreErrorKind, SyncStoreFuture,
};

static APP_SYNC_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Creates one operation-scoped local sync store for an explicit target.
///
/// This is a trusted, security-sensitive SPI: implementations can retain the
/// supplied key and must therefore be selected by the application composition
/// root, never from untrusted plugin code.
///
/// Implementations receive owned, exact inputs and must not consult ambient
/// paths, active-profile state or mutable key maps. Opening is read-only: any
/// migration, projection creation or binding belongs to a separate explicit
/// workflow. Implementations must remain lazy and perform no I/O before the
/// returned future is polled.
pub trait AppSyncStoreFactory: Send + Sync {
    fn open_existing(
        self: Arc<Self>,
        paths: ClientPaths,
        target: SessionTarget,
        master_key: Arc<SecretKey>,
    ) -> SyncStoreFuture<'static, Arc<dyn SyncLocalStore>>;

    /// Removes one target's complete local projection (items, history,
    /// cursors, pending rows, vaults) in a single terminal transaction.
    ///
    /// Unlike [`Self::open_existing`] this is a local maintenance mutation,
    /// not an operation-scoped open: it must refuse while any pending or
    /// otherwise unconfirmed local state would be discarded, and it must not
    /// require remote authorization. Implementations must remain lazy and
    /// perform no I/O before the returned future is polled.
    fn reset_projection(
        self: Arc<Self>,
        paths: ClientPaths,
        target: SessionTarget,
        master_key: Arc<SecretKey>,
    ) -> SyncStoreFuture<'static, ()>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedConnection {
    target: SessionTarget,
    auth_methods: Vec<AuthMethod>,
    registration_available: bool,
    server_name: Option<String>,
    storage_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalVaultStatus {
    personal_vaults_present: bool,
    personal_key_envelopes_present: bool,
    personal_vault_id: Option<Uuid>,
}

impl PersonalVaultStatus {
    #[must_use]
    pub fn personal_vaults_present(&self) -> bool {
        self.personal_vaults_present
    }

    #[must_use]
    pub fn personal_key_envelopes_present(&self) -> bool {
        self.personal_key_envelopes_present
    }

    #[must_use]
    pub fn personal_vault_id(&self) -> Option<Uuid> {
        self.personal_vault_id
    }
}

impl PreparedConnection {
    #[must_use]
    pub fn target(&self) -> &SessionTarget {
        &self.target
    }

    #[must_use]
    pub fn auth_methods(&self) -> &[AuthMethod] {
        &self.auth_methods
    }

    #[must_use]
    pub fn registration_available(&self) -> bool {
        self.registration_available
    }

    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    #[must_use]
    pub fn storage_id(&self) -> &str {
        &self.storage_id
    }
}

pub struct ConnectionTrustChallenge {
    expected_revision: u64,
    connection_id: ConnectionId,
    expected_old_fingerprint: String,
    verified: crate::remote::trust::VerifiedSystemInfo,
    prepared: PreparedConnection,
}

impl fmt::Debug for ConnectionTrustChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionTrustChallenge")
            .field("connection_id", &self.connection_id)
            .field("old_fingerprint", &self.expected_old_fingerprint)
            .field(
                "new_fingerprint",
                &self.verified.binding().server_fingerprint(),
            )
            .finish_non_exhaustive()
    }
}

impl ConnectionTrustChallenge {
    #[must_use]
    pub fn old_fingerprint(&self) -> &str {
        &self.expected_old_fingerprint
    }

    #[must_use]
    pub fn new_fingerprint(&self) -> &str {
        self.verified.binding().server_fingerprint()
    }

    #[must_use]
    pub fn prepared(&self) -> &PreparedConnection {
        &self.prepared
    }
}

#[derive(Debug)]
pub enum PrepareConnectionOutcome {
    Ready(PreparedConnection),
    FingerprintChanged(Box<ConnectionTrustChallenge>),
}

/// Application policy facade over session and bidirectional sync owners.
#[derive(Clone)]
pub struct AppClient {
    paths: ClientPaths,
    client_id: ClientId,
    pub(crate) repository: ConfigRepository,
    credential_store: Arc<dyn CredentialStore>,
    session: AppSession,
    sync_store_factory: Arc<dyn AppSyncStoreFactory>,
    sync_progress: Option<Arc<dyn SyncProgressSink>>,
}

impl AppClient {
    #[must_use]
    pub fn new(
        paths: ClientPaths,
        credential_store: Arc<dyn CredentialStore>,
        client: SessionClient,
        sync_store_factory: Arc<dyn AppSyncStoreFactory>,
    ) -> Self {
        let client_id = client.client_id().clone();
        let repository = ConfigRepository::new(paths.clone());
        Self {
            session: AppSession::for_client(paths.clone(), Arc::clone(&credential_store), client),
            paths,
            client_id,
            repository,
            credential_store,
            sync_store_factory,
            sync_progress: None,
        }
    }

    pub fn initialize(
        &self,
        legacy_credentials: &dyn LegacyCredentialSource,
    ) -> Result<(), crate::config::ConfigError> {
        self.repository
            .initialize(
                &self.client_id,
                self.credential_store.as_ref(),
                legacy_credentials,
            )
            .map(|_| ())
    }

    /// Resolves one configured remote target without consulting ambient
    /// "current context" state. An explicit storage id wins; otherwise the
    /// calling client's active connection must be unambiguous.
    pub fn configured_target(
        &self,
        storage_id: Option<&str>,
    ) -> Result<SessionTarget, SessionError> {
        let operation_id = SessionOperationId::new();
        let snapshot = self
            .repository
            .snapshot()
            .map_err(|_| SessionError::for_app(operation_id, SessionErrorKind::Configuration))?;
        let config = snapshot.config();
        let connection_id = if let Some(storage_id) = storage_id {
            let mut matches = config.connections.iter().filter(|(_, connection)| {
                connection.metadata().storage_id.as_deref() == Some(storage_id)
            });
            let selected = matches.next().map(|(id, _)| id.clone());
            if matches.next().is_some() {
                return Err(SessionError::for_app(
                    operation_id,
                    SessionErrorKind::Configuration,
                ));
            }
            selected.ok_or_else(|| {
                SessionError::for_app(operation_id, SessionErrorKind::Configuration)
            })?
        } else if let Some(active) = config
            .clients
            .get(&self.client_id)
            .and_then(crate::config::ClientConfig::active_connection)
        {
            active.clone()
        } else if config.connections.len() == 1 {
            config.connections.keys().next().cloned().ok_or_else(|| {
                SessionError::for_app(operation_id, SessionErrorKind::Configuration)
            })?
        } else {
            return Err(SessionError::for_app(
                operation_id,
                SessionErrorKind::Configuration,
            ));
        };
        let connection = config
            .connections
            .get(&connection_id)
            .ok_or_else(|| SessionError::for_app(operation_id, SessionErrorKind::Configuration))?;
        let profile = connection
            .active_credential()
            .ok_or_else(|| SessionError::for_app(operation_id, SessionErrorKind::Configuration))?;
        SessionTarget::new(connection_id, profile)
            .map_err(|_| SessionError::for_app(operation_id, SessionErrorKind::Configuration))
    }

    pub async fn prepare_connection(
        &self,
        endpoint: &str,
        connection_name: &str,
        profile_name: &str,
    ) -> Result<PrepareConnectionOutcome, SessionError> {
        let operation_id = SessionOperationId::new();
        let transport = AuthHttpTransport::new(endpoint)
            .map_err(|_| SessionError::for_app(operation_id, SessionErrorKind::Protocol))?;
        let info = transport
            .system_info()
            .await
            .map_err(|error| SessionError::from_http_for_app(operation_id, &error))?;
        let verified = crate::remote::trust::verify_and_bind_system_info(endpoint, info)
            .map_err(|_| SessionError::for_app(operation_id, SessionErrorKind::TrustInvalid))?;
        let snapshot = self
            .repository
            .snapshot()
            .map_err(|_| SessionError::for_app(operation_id, SessionErrorKind::Configuration))?;
        let connection_id = ConnectionId::deterministic(connection_name, endpoint);
        let existing = snapshot.config().connections.get(&connection_id);
        let storage_id = existing
            .and_then(|connection| connection.metadata().storage_id.clone())
            .unwrap_or_else(|| Uuid::now_v7().to_string());
        let target = SessionTarget::new(connection_id.clone(), profile_name.to_string())
            .map_err(|_| SessionError::for_app(operation_id, SessionErrorKind::Configuration))?;
        let prepared = PreparedConnection {
            target,
            auth_methods: verified
                .info()
                .auth_methods
                .iter()
                .filter_map(|value| AuthMethod::try_from(*value).ok())
                .collect(),
            registration_available: verified.info().internal_users_present == Some(false),
            server_name: verified.info().server_name.clone(),
            storage_id: storage_id.clone(),
        };
        if let Some(connection) = existing {
            let metadata = connection.metadata();
            if metadata.server_id.as_deref() != Some(verified.binding().server_id()) {
                return Err(SessionError::for_app(
                    operation_id,
                    SessionErrorKind::TrustInvalid,
                ));
            }
            if let Some(old) = metadata.server_fingerprint.as_deref() {
                if old != verified.binding().server_fingerprint() {
                    return Ok(PrepareConnectionOutcome::FingerprintChanged(Box::new(
                        ConnectionTrustChallenge {
                            expected_revision: snapshot.revision(),
                            connection_id,
                            expected_old_fingerprint: old.to_string(),
                            verified,
                            prepared,
                        },
                    )));
                }
            }
        }
        self.repository
            .pin_verified_connection(
                snapshot.revision(),
                connection_id,
                connection_name.to_string(),
                verified.binding(),
                storage_id,
            )
            .map_err(|_| SessionError::for_app(operation_id, SessionErrorKind::Configuration))?;
        Ok(PrepareConnectionOutcome::Ready(prepared))
    }

    pub fn trust_connection(
        &self,
        challenge: ConnectionTrustChallenge,
    ) -> Result<PreparedConnection, SessionError> {
        let operation_id = SessionOperationId::new();
        self.repository
            .replace_verified_fingerprint(
                challenge.expected_revision,
                &challenge.connection_id,
                &challenge.expected_old_fingerprint,
                challenge.verified.binding(),
            )
            .map_err(|_| SessionError::for_app(operation_id, SessionErrorKind::Configuration))?;
        Ok(challenge.prepared)
    }

    /// Installs a metadata-only progress observer for subsequent sync calls.
    #[must_use]
    pub fn with_sync_progress(mut self, progress: Arc<dyn SyncProgressSink>) -> Self {
        self.sync_progress = Some(progress);
        self
    }

    /// Delegates an explicit password login to the session owner.
    pub async fn password_login(
        &self,
        request: PasswordLoginRequest,
        operation: SessionOperation,
    ) -> Result<SessionAccess, SessionError> {
        self.session.password_login(request, operation).await
    }

    pub async fn password_register(
        &self,
        request: PasswordRegistrationRequest,
        operation: SessionOperation,
    ) -> Result<SessionAccess, SessionError> {
        self.session.password_register(request, operation).await
    }

    /// Exchanges one external OIDC token with the verified server and commits
    /// the resulting account-bound session without exposing bearer material.
    pub async fn oidc_login(
        &self,
        request: OidcLoginInput,
        operation: SessionOperation,
    ) -> Result<SessionAccess, SessionError> {
        self.session.oidc_login(request, operation).await
    }

    /// Commits an already-authenticated legacy session (live tokens, known
    /// storage) as a Config v2 connection without any login call.
    pub async fn import_legacy_session(
        &self,
        request: LegacySessionImport,
        operation: SessionOperation,
    ) -> Result<SessionAccess, SessionError> {
        self.session.import_session_tokens(request, operation).await
    }

    /// Reads the server's personal-vault initialization state using an opaque
    /// session capability; bearer material remains crate-owned.
    pub async fn personal_vault_status(
        &self,
        access: &SessionAccess,
    ) -> Result<PersonalVaultStatus, SessionError> {
        let transport = AuthHttpTransport::new(access.endpoint())
            .map_err(|error| SessionError::from_http_for_app(access.operation_id(), &error))?;
        let status = transport
            .personal_vault_status(access.bearer())
            .await
            .map_err(|error| SessionError::from_http_for_app(access.operation_id(), &error))?;
        Ok(PersonalVaultStatus {
            personal_vaults_present: status.personal_vaults_present,
            personal_key_envelopes_present: status.personal_key_envelopes_present,
            personal_vault_id: status.personal_vault_id,
        })
    }

    /// Delegates an explicit profile logout to the session owner.
    pub async fn logout(
        &self,
        target: &SessionTarget,
        operation: SessionOperation,
    ) -> Result<LogoutOutcome, SessionError> {
        self.session.logout(target, operation).await
    }

    /// Synchronizes one target using an owned, non-cloneable operation key and
    /// one freshly opened local-store lease.
    ///
    /// The local store must exist before authorization or network dispatch.
    /// Factory opening is raced against the same cancellation/deadline context
    /// used by the session and sync owners. Only one facade pull may be active
    /// in the process; a contender fails before opening local state. The
    /// returned future must be polled on a Tokio runtime with its time driver
    /// enabled.
    pub fn sync(
        &self,
        target: SessionTarget,
        master_key: SecretKey,
        operation: SessionOperation,
    ) -> SyncFuture<'static, SyncOutcome> {
        let operation_id = operation.operation_id();
        if let Some(kind) = operation.pre_dispatch_error() {
            return ready_sync_error(operation_id, map_operation_error(kind));
        }
        let master_key_fingerprint = zann_crypto::cache_key_fingerprint(&master_key);
        let permit = match AppSyncPermit::try_acquire() {
            Ok(permit) => permit,
            Err(()) => {
                return ready_sync_error(operation_id, SyncErrorKind::Local);
            }
        };

        let paths = self.paths.clone();
        let factory = Arc::clone(&self.sync_store_factory);
        let repository = self.repository.clone();
        let session = self.session.clone();
        let progress = self.sync_progress.clone();
        Box::pin(async move {
            ensure_operation_dispatchable(&operation)?;
            if tokio::runtime::Handle::try_current().is_err() {
                return Err(SyncError::new(
                    operation_id,
                    SyncErrorKind::Local,
                    SyncStage::ResolveTarget,
                ));
            }

            let open = factory.open_existing(paths, target.clone(), Arc::new(master_key));
            tokio::pin!(open);
            let deadline = tokio::time::sleep_until(operation.deadline().into());
            tokio::pin!(deadline);
            let local = tokio::select! {
                biased;
                () = operation.cancelled() => {
                    return Err(SyncError::new(
                        operation_id,
                        SyncErrorKind::Cancelled,
                        SyncStage::ResolveTarget,
                    ));
                }
                () = &mut deadline => {
                    return Err(SyncError::new(
                        operation_id,
                        SyncErrorKind::DeadlineExceeded,
                        SyncStage::ResolveTarget,
                    ));
                }
                result = &mut open => result.map_err(|error| {
                    map_factory_error(operation_id, error)
                })?,
            };
            ensure_operation_dispatchable(&operation)?;

            let anchor = repository
                .resolve_credential_profile_anchor(target.connection_id(), target.profile_name())
                .map_err(|_| {
                    SyncError::new(operation_id, SyncErrorKind::Local, SyncStage::ResolveTarget)
                })?;
            repository
                .bind_expected_master_key_fingerprint_if_profile_matches(
                    &anchor,
                    master_key_fingerprint,
                )
                .map_err(|_| {
                    SyncError::new(
                        operation_id,
                        SyncErrorKind::Crypto,
                        SyncStage::ResolveTarget,
                    )
                })?;

            let local: Arc<dyn SyncLocalStore> = Arc::new(AppOperationStore {
                inner: local,
                _permit: permit,
            });
            let engine = SyncEngine::new(session, local);
            let engine = if let Some(progress) = progress {
                engine.with_progress(progress)
            } else {
                engine
            };
            engine.pull(&target, operation).await
        })
    }

    /// Removes the target's complete local projection through the persistence
    /// factory. This is the explicit recovery path for a rebuilt or re-trusted
    /// server: no remote authorization is attempted, and the factory must
    /// refuse the reset while any unconfirmed local state would be discarded.
    /// The same single-flight admission as [`Self::sync`] applies.
    pub fn reset_sync(
        &self,
        target: SessionTarget,
        master_key: SecretKey,
    ) -> SyncFuture<'static, ()> {
        let operation_id = SessionOperationId::new();
        let permit = match AppSyncPermit::try_acquire() {
            Ok(permit) => permit,
            Err(()) => {
                return Box::pin(async move {
                    Err(SyncError::new(
                        operation_id,
                        SyncErrorKind::Local,
                        SyncStage::ResolveTarget,
                    ))
                });
            }
        };

        let paths = self.paths.clone();
        let factory = Arc::clone(&self.sync_store_factory);
        Box::pin(async move {
            let _permit = permit;
            factory
                .reset_projection(paths, target, Arc::new(master_key))
                .await
                .map_err(|error| {
                    SyncError::new(
                        operation_id,
                        map_reset_store_error(error),
                        SyncStage::ResolveTarget,
                    )
                })
        })
    }
}

impl fmt::Debug for AppClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("AppClient").finish_non_exhaustive()
    }
}

struct AppSyncPermit {
    _private: (),
}

impl AppSyncPermit {
    fn try_acquire() -> Result<Self, ()> {
        APP_SYNC_IN_FLIGHT
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ())?;
        Ok(Self { _private: () })
    }
}

impl Drop for AppSyncPermit {
    fn drop(&mut self) {
        APP_SYNC_IN_FLIGHT.store(false, Ordering::Release);
    }
}

/// Keeps process-wide facade admission alive in every owned terminal local
/// mutation, even after the caller drops the outer [`AppClient`] future.
struct AppOperationStore {
    // Field order is intentional: release the underlying operation store and
    // its key before reopening process-wide facade admission.
    inner: Arc<dyn SyncLocalStore>,
    _permit: AppSyncPermit,
}

impl SyncLocalStore for AppOperationStore {
    fn resolve_target<'a>(
        &'a self,
        target: &'a SessionTarget,
        generation: Arc<AuthorizedTargetGeneration>,
        personal_vaults_enabled: bool,
    ) -> SyncStoreFuture<'a, ResolvedSyncTarget> {
        self.inner
            .resolve_target(target, generation, personal_vaults_enabled)
    }

    fn reconcile_catalog(
        self: Arc<Self>,
        target: Arc<ResolvedSyncTarget>,
        catalog: Arc<CatalogSnapshot>,
    ) -> SyncStoreFuture<'static, ReconciledCatalog> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let _operation_guard = self;
            inner.reconcile_catalog(target, catalog).await
        })
    }

    fn load_checkpoint<'a>(&'a self, scope: SyncScope) -> SyncStoreFuture<'a, SyncCheckpoint> {
        self.inner.load_checkpoint(scope)
    }

    fn load_item_states<'a>(
        &'a self,
        scope: SyncScope,
        item_ids: &'a [uuid::Uuid],
    ) -> SyncStoreFuture<'a, Vec<ItemState>> {
        self.inner.load_item_states(scope, item_ids)
    }

    fn prepare_generated_key(
        self: Arc<Self>,
        scope: SyncScope,
        expected_remote_envelope: Vec<u8>,
    ) -> SyncStoreFuture<'static, GeneratedVaultKeyCommit> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let _operation_guard = self;
            inner
                .prepare_generated_key(scope, expected_remote_envelope)
                .await
        })
    }

    fn commit_generated_key(
        self: Arc<Self>,
        commit: GeneratedVaultKeyCommit,
    ) -> SyncStoreFuture<'static, ()> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let _operation_guard = self;
            inner.commit_generated_key(commit).await
        })
    }

    fn commit_push(
        self: Arc<Self>,
        commit: PushCommitPlan,
    ) -> SyncStoreFuture<'static, PushCommitReceipt> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let _operation_guard = self;
            inner.commit_push(commit).await
        })
    }

    fn commit_pull_page(
        self: Arc<Self>,
        commit: PullPageCommit,
    ) -> SyncStoreFuture<'static, PullCommitReceipt> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let _operation_guard = self;
            inner.commit_pull_page(commit).await
        })
    }

    fn reset_projection_if_clean(
        self: Arc<Self>,
        reset: ProjectionReset,
    ) -> SyncStoreFuture<'static, ()> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let _operation_guard = self;
            inner.reset_projection_if_clean(reset).await
        })
    }
}

impl fmt::Debug for AppOperationStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppOperationStore")
            .finish_non_exhaustive()
    }
}

fn ensure_operation_dispatchable(operation: &SessionOperation) -> Result<(), SyncError> {
    operation.pre_dispatch_error().map_or(Ok(()), |kind| {
        Err(SyncError::new(
            operation.operation_id(),
            map_operation_error(kind),
            SyncStage::ResolveTarget,
        ))
    })
}

const fn map_operation_error(kind: SessionErrorKind) -> SyncErrorKind {
    match kind {
        SessionErrorKind::Cancelled => SyncErrorKind::Cancelled,
        SessionErrorKind::DeadlineExceeded => SyncErrorKind::DeadlineExceeded,
        _ => SyncErrorKind::Internal,
    }
}

fn map_factory_error(
    operation_id: crate::session::SessionOperationId,
    error: SyncStoreError,
) -> SyncError {
    let kind = match error.kind() {
        SyncStoreErrorKind::CommitOutcomeUnknown => SyncErrorKind::CommitOutcomeUnknown,
        SyncStoreErrorKind::StaleCheckpoint
        | SyncStoreErrorKind::StaleKeyBinding
        | SyncStoreErrorKind::StaleItem
        | SyncStoreErrorKind::PendingChanged
        | SyncStoreErrorKind::PendingPresent => SyncErrorKind::ConcurrentLocalChange,
        _ => SyncErrorKind::Local,
    };
    SyncError::new(operation_id, kind, SyncStage::ResolveTarget)
}

fn ready_sync_error(
    operation_id: crate::session::SessionOperationId,
    kind: SyncErrorKind,
) -> SyncFuture<'static, SyncOutcome> {
    Box::pin(async move { Err(SyncError::new(operation_id, kind, SyncStage::ResolveTarget)) })
}

/// Factory reset failures keep the same shape as engine store failures:
/// unconfirmed local state blocking the reset is a local conflict, everything
/// else is a local persistence problem.
fn map_reset_store_error(error: SyncStoreError) -> SyncErrorKind {
    match error.kind() {
        SyncStoreErrorKind::PendingPresent => SyncErrorKind::ConcurrentLocalChange,
        _ => SyncErrorKind::Local,
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use tokio::sync::Notify;
    use uuid::Uuid;
    use zann_core::AuthMethod;

    use super::*;
    use crate::sync::{StorageBindingProof, SyncCursor, SyncSeq};

    static APP_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct EmptyCredentials;

    impl CredentialStore for EmptyCredentials {
        fn put(
            &self,
            _credential_id: &CredentialId,
            _secret: &CredentialSecret,
        ) -> Result<(), CredentialPortError> {
            Ok(())
        }

        fn get(
            &self,
            _credential_id: &CredentialId,
        ) -> Result<Option<CredentialSecret>, CredentialPortError> {
            Ok(None)
        }

        fn delete(&self, _credential_id: &CredentialId) -> Result<(), CredentialPortError> {
            Ok(())
        }
    }

    struct ErrorFactory {
        calls: AtomicUsize,
        kind: SyncStoreErrorKind,
    }

    impl ErrorFactory {
        fn new(kind: SyncStoreErrorKind) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                kind,
            }
        }
    }

    impl AppSyncStoreFactory for ErrorFactory {
        fn open_existing(
            self: Arc<Self>,
            _paths: ClientPaths,
            _target: SessionTarget,
            _master_key: Arc<SecretKey>,
        ) -> SyncStoreFuture<'static, Arc<dyn SyncLocalStore>> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let error = SyncStoreError::new(self.kind);
            Box::pin(async move { Err(error) })
        }

        fn reset_projection(
            self: Arc<Self>,
            _paths: ClientPaths,
            _target: SessionTarget,
            _master_key: Arc<SecretKey>,
        ) -> SyncStoreFuture<'static, ()> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let error = SyncStoreError::new(self.kind);
            Box::pin(async move { Err(error) })
        }
    }

    struct PendingFactory {
        calls: AtomicUsize,
        started: Notify,
        dropped: Arc<AtomicBool>,
    }

    struct DropMarker(Arc<AtomicBool>);

    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    impl AppSyncStoreFactory for PendingFactory {
        fn open_existing(
            self: Arc<Self>,
            _paths: ClientPaths,
            _target: SessionTarget,
            _master_key: Arc<SecretKey>,
        ) -> SyncStoreFuture<'static, Arc<dyn SyncLocalStore>> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                let _drop_marker = DropMarker(Arc::clone(&self.dropped));
                self.started.notify_one();
                pending::<Result<Arc<dyn SyncLocalStore>, SyncStoreError>>().await
            })
        }

        fn reset_projection(
            self: Arc<Self>,
            _paths: ClientPaths,
            _target: SessionTarget,
            _master_key: Arc<SecretKey>,
        ) -> SyncStoreFuture<'static, ()> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                let _drop_marker = DropMarker(Arc::clone(&self.dropped));
                self.started.notify_one();
                pending::<Result<(), SyncStoreError>>().await
            })
        }
    }

    struct TerminalStore {
        catalog_started: Notify,
        catalog_release: Notify,
        pull_started: Notify,
        pull_release: Notify,
    }

    impl TerminalStore {
        fn new() -> Self {
            Self {
                catalog_started: Notify::new(),
                catalog_release: Notify::new(),
                pull_started: Notify::new(),
                pull_release: Notify::new(),
            }
        }
    }

    impl SyncLocalStore for TerminalStore {
        fn resolve_target<'a>(
            &'a self,
            _target: &'a SessionTarget,
            _generation: Arc<AuthorizedTargetGeneration>,
            _personal_vaults_enabled: bool,
        ) -> SyncStoreFuture<'a, ResolvedSyncTarget> {
            Box::pin(async { Err(SyncStoreError::new(SyncStoreErrorKind::Unavailable)) })
        }

        fn reconcile_catalog(
            self: Arc<Self>,
            _target: Arc<ResolvedSyncTarget>,
            _catalog: Arc<CatalogSnapshot>,
        ) -> SyncStoreFuture<'static, ReconciledCatalog> {
            Box::pin(async move {
                self.catalog_started.notify_one();
                self.catalog_release.notified().await;
                Err(SyncStoreError::new(SyncStoreErrorKind::Unavailable))
            })
        }

        fn load_checkpoint<'a>(&'a self, _scope: SyncScope) -> SyncStoreFuture<'a, SyncCheckpoint> {
            Box::pin(async { Err(SyncStoreError::new(SyncStoreErrorKind::Unavailable)) })
        }

        fn load_item_states<'a>(
            &'a self,
            _scope: SyncScope,
            _item_ids: &'a [Uuid],
        ) -> SyncStoreFuture<'a, Vec<ItemState>> {
            Box::pin(async { Err(SyncStoreError::new(SyncStoreErrorKind::Unavailable)) })
        }

        fn commit_generated_key(
            self: Arc<Self>,
            _commit: GeneratedVaultKeyCommit,
        ) -> SyncStoreFuture<'static, ()> {
            Box::pin(async { Err(SyncStoreError::new(SyncStoreErrorKind::Unavailable)) })
        }

        fn commit_push(
            self: Arc<Self>,
            _commit: PushCommitPlan,
        ) -> SyncStoreFuture<'static, PushCommitReceipt> {
            Box::pin(async { Err(SyncStoreError::new(SyncStoreErrorKind::Unavailable)) })
        }

        fn commit_pull_page(
            self: Arc<Self>,
            _commit: PullPageCommit,
        ) -> SyncStoreFuture<'static, PullCommitReceipt> {
            Box::pin(async move {
                self.pull_started.notify_one();
                self.pull_release.notified().await;
                Err(SyncStoreError::new(SyncStoreErrorKind::Unavailable))
            })
        }

        fn reset_projection_if_clean(
            self: Arc<Self>,
            _reset: ProjectionReset,
        ) -> SyncStoreFuture<'static, ()> {
            Box::pin(async { Err(SyncStoreError::new(SyncStoreErrorKind::Unavailable)) })
        }
    }

    fn target() -> SessionTarget {
        SessionTarget::new(
            ConnectionId::deterministic("app-client-test", "https://app-client.test/"),
            "profile",
        )
        .expect("valid target")
    }

    fn client(suffix: &str, factory: Arc<dyn AppSyncStoreFactory>) -> AppClient {
        AppClient::new(
            ClientPaths::new(PathBuf::from(format!("/app-client-test-{suffix}"))),
            Arc::new(EmptyCredentials),
            SessionClient::new(ClientId::new("app-client-test").expect("valid client id")),
            factory,
        )
    }

    fn operation_after(
        duration: Duration,
    ) -> (SessionOperation, crate::session::SessionCancellationHandle) {
        SessionOperation::new(Instant::now() + duration)
    }

    fn resolved_target() -> Arc<ResolvedSyncTarget> {
        Arc::new(ResolvedSyncTarget::new(
            StorageBindingProof::new(
                Uuid::now_v7(),
                "App terminal test",
                "https://app-client.test",
                None,
                "app-terminal-fingerprint",
                Some(Uuid::now_v7().to_string()),
                true,
                Some(AuthMethod::Password),
            )
            .expect("valid terminal target binding"),
        ))
    }

    fn empty_pull_commit() -> PullPageCommit {
        let scope = SyncScope::new(Uuid::now_v7(), Uuid::now_v7()).expect("valid sync scope");
        PullPageCommit::validated(
            scope,
            "001122aabbcc".to_string(),
            None,
            None,
            SyncCursor::new("eyJzZXEiOjF9").expect("valid sequence-one cursor"),
            Some(SyncSeq::new(1).expect("valid sequence")),
            chrono::Utc::now(),
            Vec::new(),
        )
        .expect("valid empty pull commit")
    }

    #[tokio::test]
    async fn facade_preflights_factory_and_bounds_all_instances() {
        let _test_lock = APP_TEST_LOCK.lock().await;
        let first_factory = Arc::new(ErrorFactory::new(SyncStoreErrorKind::Unavailable));
        let second_factory = Arc::new(ErrorFactory::new(SyncStoreErrorKind::Unavailable));
        let first_client = client("first", first_factory.clone());
        let second_client = client("second", second_factory.clone());
        assert_eq!(format!("{first_client:?}"), "AppClient { .. }");

        let (first_operation, _) = operation_after(Duration::from_secs(30));
        let first = first_client.sync(target(), SecretKey::from_bytes([7_u8; 32]), first_operation);
        let (busy_operation, _) = operation_after(Duration::from_secs(30));
        let busy_id = busy_operation.operation_id();
        let busy = second_client
            .sync(target(), SecretKey::from_bytes([7_u8; 32]), busy_operation)
            .await
            .expect_err("a second facade must fail before opening local state");
        assert_eq!(busy.operation_id(), busy_id);
        assert_eq!(busy.kind(), SyncErrorKind::Local);
        assert_eq!(busy.stage(), SyncStage::ResolveTarget);
        assert_eq!(first_factory.calls.load(Ordering::Acquire), 0);
        assert_eq!(second_factory.calls.load(Ordering::Acquire), 0);
        drop(first);

        let (factory_operation, _) = operation_after(Duration::from_secs(30));
        let factory_id = factory_operation.operation_id();
        let factory_error = second_client
            .sync(
                target(),
                SecretKey::from_bytes([7_u8; 32]),
                factory_operation,
            )
            .await
            .expect_err("factory failure must remain local and operation-scoped");
        assert_eq!(factory_error.operation_id(), factory_id);
        assert_eq!(factory_error.kind(), SyncErrorKind::Local);
        assert_eq!(factory_error.stage(), SyncStage::ResolveTarget);
        assert_eq!(second_factory.calls.load(Ordering::Acquire), 1);

        let (expired_operation, _) = SessionOperation::new(Instant::now());
        let expired_id = expired_operation.operation_id();
        let expired = second_client
            .sync(
                target(),
                SecretKey::from_bytes([7_u8; 32]),
                expired_operation,
            )
            .await
            .expect_err("expired operation must not call the factory");
        assert_eq!(expired.operation_id(), expired_id);
        assert_eq!(expired.kind(), SyncErrorKind::DeadlineExceeded);
        assert_eq!(second_factory.calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn cancellation_drops_factory_open_and_releases_process_admission() {
        let _test_lock = APP_TEST_LOCK.lock().await;
        let pending_factory = Arc::new(PendingFactory {
            calls: AtomicUsize::new(0),
            started: Notify::new(),
            dropped: Arc::new(AtomicBool::new(false)),
        });
        let app = client("pending", pending_factory.clone());
        let (operation, cancellation) = operation_after(Duration::from_secs(30));
        let operation_id = operation.operation_id();
        let task = tokio::spawn(app.sync(target(), SecretKey::from_bytes([8_u8; 32]), operation));
        tokio::time::timeout(Duration::from_secs(2), pending_factory.started.notified())
            .await
            .expect("factory open must begin");
        cancellation.cancel();
        let error = task
            .await
            .expect("facade task must not panic")
            .expect_err("cancellation must stop the read-only factory open");
        assert_eq!(error.operation_id(), operation_id);
        assert_eq!(error.kind(), SyncErrorKind::Cancelled);
        assert_eq!(error.stage(), SyncStage::ResolveTarget);
        assert!(pending_factory.dropped.load(Ordering::Acquire));

        let recovery_factory = Arc::new(ErrorFactory::new(SyncStoreErrorKind::Unavailable));
        let recovery = client("recovery", recovery_factory.clone());
        let (recovery_operation, _) = operation_after(Duration::from_secs(30));
        recovery
            .sync(
                target(),
                SecretKey::from_bytes([9_u8; 32]),
                recovery_operation,
            )
            .await
            .expect_err("released admission reaches the scripted factory error");
        assert_eq!(recovery_factory.calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn detached_catalog_and_pull_keep_facade_admission_until_terminal_completion() {
        let _test_lock = APP_TEST_LOCK.lock().await;

        let catalog_inner = Arc::new(TerminalStore::new());
        let catalog_store = Arc::new(AppOperationStore {
            inner: catalog_inner.clone(),
            _permit: AppSyncPermit::try_acquire().expect("acquire catalog operation"),
        });
        let catalog_task = tokio::spawn(catalog_store.clone().reconcile_catalog(
            resolved_target(),
            Arc::new(CatalogSnapshot::validated(Vec::new())),
        ));
        drop(catalog_store);
        tokio::time::timeout(
            Duration::from_secs(2),
            catalog_inner.catalog_started.notified(),
        )
        .await
        .expect("catalog terminal mutation must start");

        let catalog_contender_factory =
            Arc::new(ErrorFactory::new(SyncStoreErrorKind::Unavailable));
        let catalog_contender = client("catalog-contender", catalog_contender_factory.clone());
        let (catalog_contender_operation, _) = operation_after(Duration::from_secs(30));
        catalog_contender
            .sync(
                target(),
                SecretKey::from_bytes([10_u8; 32]),
                catalog_contender_operation,
            )
            .await
            .expect_err("catalog terminal mutation must retain facade admission");
        assert_eq!(catalog_contender_factory.calls.load(Ordering::Acquire), 0);
        catalog_inner.catalog_release.notify_one();
        catalog_task
            .await
            .expect("catalog terminal task must not panic")
            .expect_err("scripted catalog terminal result");

        let pull_inner = Arc::new(TerminalStore::new());
        let pull_store = Arc::new(AppOperationStore {
            inner: pull_inner.clone(),
            _permit: AppSyncPermit::try_acquire().expect("catalog completion releases admission"),
        });
        let pull_task = tokio::spawn(pull_store.clone().commit_pull_page(empty_pull_commit()));
        drop(pull_store);
        tokio::time::timeout(Duration::from_secs(2), pull_inner.pull_started.notified())
            .await
            .expect("pull terminal mutation must start");

        let pull_contender_factory = Arc::new(ErrorFactory::new(SyncStoreErrorKind::Unavailable));
        let pull_contender = client("pull-contender", pull_contender_factory.clone());
        let (pull_contender_operation, _) = operation_after(Duration::from_secs(30));
        pull_contender
            .sync(
                target(),
                SecretKey::from_bytes([11_u8; 32]),
                pull_contender_operation,
            )
            .await
            .expect_err("pull terminal mutation must retain facade admission");
        assert_eq!(pull_contender_factory.calls.load(Ordering::Acquire), 0);
        pull_inner.pull_release.notify_one();
        pull_task
            .await
            .expect("pull terminal task must not panic")
            .expect_err("scripted pull terminal result");

        let released = AppSyncPermit::try_acquire().expect("pull completion releases admission");
        drop(released);
    }

    #[tokio::test]
    async fn reset_sync_maps_unconfirmed_local_state_to_a_local_conflict() {
        let _test_lock = APP_TEST_LOCK.lock().await;
        let factory = Arc::new(ErrorFactory::new(SyncStoreErrorKind::PendingPresent));
        let client = client("reset-pending", factory.clone());

        let error = client
            .reset_sync(target(), SecretKey::from_bytes([12_u8; 32]))
            .await
            .expect_err("scripted pending-present reset failure");
        assert_eq!(error.kind(), SyncErrorKind::ConcurrentLocalChange);
        assert_eq!(error.stage(), SyncStage::ResolveTarget);
        assert_eq!(factory.calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn reset_sync_maps_other_store_failures_to_local() {
        let _test_lock = APP_TEST_LOCK.lock().await;
        let factory = Arc::new(ErrorFactory::new(SyncStoreErrorKind::InvalidData));
        let client = client("reset-invalid", factory.clone());

        let error = client
            .reset_sync(target(), SecretKey::from_bytes([13_u8; 32]))
            .await
            .expect_err("scripted invalid-data reset failure");
        assert_eq!(error.kind(), SyncErrorKind::Local);
        assert_eq!(error.stage(), SyncStage::ResolveTarget);
        assert_eq!(factory.calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn reset_sync_is_bounded_by_the_facade_single_flight() {
        let _test_lock = APP_TEST_LOCK.lock().await;
        let pending_factory = Arc::new(PendingFactory {
            calls: AtomicUsize::new(0),
            started: Notify::new(),
            dropped: Arc::new(AtomicBool::new(false)),
        });
        let pending_client = client("reset-in-flight", pending_factory.clone());
        let first =
            tokio::spawn(pending_client.reset_sync(target(), SecretKey::from_bytes([14_u8; 32])));
        tokio::time::timeout(Duration::from_secs(2), pending_factory.started.notified())
            .await
            .expect("scripted reset must start");

        let contender_factory = Arc::new(ErrorFactory::new(SyncStoreErrorKind::Unavailable));
        let contender = client("reset-contender", contender_factory.clone());
        let (contender_operation, _) = operation_after(Duration::from_secs(30));
        let sync_error = contender
            .sync(
                target(),
                SecretKey::from_bytes([14_u8; 32]),
                contender_operation,
            )
            .await
            .expect_err("a concurrent sync must fail before opening local state");
        assert_eq!(sync_error.kind(), SyncErrorKind::Local);
        let reset_error = contender
            .reset_sync(target(), SecretKey::from_bytes([14_u8; 32]))
            .await
            .expect_err("a concurrent reset must fail before opening local state");
        assert_eq!(reset_error.kind(), SyncErrorKind::Local);
        assert_eq!(contender_factory.calls.load(Ordering::Acquire), 0);
        assert_eq!(pending_factory.calls.load(Ordering::Acquire), 1);
        first.abort();
        first.await.expect_err("aborted reset task");
        assert!(pending_factory.dropped.load(Ordering::Acquire));
    }
}
