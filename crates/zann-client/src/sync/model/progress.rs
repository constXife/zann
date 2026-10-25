use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncStage {
    Authorization,
    ResolveTarget,
    Catalog,
    ReconcileCatalog,
    LoadCheckpoint,
    Pull,
    LoadItemStates,
    CommitPullPage,
    Push,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SyncErrorKind {
    Cancelled,
    DeadlineExceeded,
    Session,
    NoLocalTarget,
    AccountBindingRequired,
    AccountBindingMismatch,
    ServerCapabilityMismatch,
    AuthenticationBindingRequired,
    AuthenticationBindingMismatch,
    Timeout,
    TransportUnavailable,
    TransportRejected,
    SessionExpired,
    Protocol,
    BodyTooLarge,
    Crypto,
    Local,
    ConcurrentLocalChange,
    ConcurrentRemoteChange,
    CommitOutcomeUnknown,
    PushUnavailable,
    InitialSharedSnapshotUnavailable,
    LimitExceeded,
    Internal,
}

pub struct SyncError {
    pub(super) operation_id: SessionOperationId,
    pub(super) kind: SyncErrorKind,
    pub(super) stage: SyncStage,
    pub(super) status: Option<u16>,
}

impl SyncError {
    pub(crate) const fn new(
        operation_id: SessionOperationId,
        kind: SyncErrorKind,
        stage: SyncStage,
    ) -> Self {
        Self {
            operation_id,
            kind,
            stage,
            status: None,
        }
    }

    pub(crate) const fn with_status(mut self, status: Option<u16>) -> Self {
        self.status = status;
        self
    }

    #[must_use]
    pub fn operation_id(&self) -> SessionOperationId {
        self.operation_id
    }

    #[must_use]
    pub fn kind(&self) -> SyncErrorKind {
        self.kind
    }

    #[must_use]
    pub fn stage(&self) -> SyncStage {
        self.stage
    }

    #[must_use]
    pub fn status(&self) -> Option<u16> {
        self.status
    }
}

impl fmt::Debug for SyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncError")
            .field("operation_id", &self.operation_id)
            .field("kind", &self.kind)
            .field("stage", &self.stage)
            .field("status", &self.status)
            .finish()
    }
}

impl fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "sync:{}:{:?}:{:?}",
            self.operation_id, self.stage, self.kind
        )
    }
}

impl std::error::Error for SyncError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncOutcomeStatus {
    Complete,
    CancelledPartial,
    DeadlinePartial,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncOutcome {
    pub(super) operation_id: SessionOperationId,
    pub(super) status: SyncOutcomeStatus,
    pub(super) completion: OperationCompletion,
    pub(super) vaults_reconciled: usize,
    pub(super) pages_committed: usize,
    pub(super) changes_committed: usize,
}

impl SyncOutcome {
    pub(crate) fn new(
        operation_id: SessionOperationId,
        status: SyncOutcomeStatus,
        completion: OperationCompletion,
        vaults_reconciled: usize,
        pages_committed: usize,
        changes_committed: usize,
    ) -> Self {
        Self {
            operation_id,
            status,
            completion,
            vaults_reconciled,
            pages_committed,
            changes_committed,
        }
    }

    #[must_use]
    pub fn operation_id(&self) -> SessionOperationId {
        self.operation_id
    }

    #[must_use]
    pub fn status(&self) -> SyncOutcomeStatus {
        self.status
    }

    #[must_use]
    pub fn completion(&self) -> OperationCompletion {
        self.completion
    }

    #[must_use]
    pub fn vaults_reconciled(&self) -> usize {
        self.vaults_reconciled
    }

    #[must_use]
    pub fn pages_committed(&self) -> usize {
        self.pages_committed
    }

    #[must_use]
    pub fn changes_committed(&self) -> usize {
        self.changes_committed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncProgressPhase {
    Authorizing,
    Catalog,
    Pushing,
    Pulling,
    Committing,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncProgress {
    pub(super) operation_id: SessionOperationId,
    pub(super) phase: SyncProgressPhase,
    pub(super) vault_index: usize,
    pub(super) vault_count: usize,
    pub(super) pages_committed: usize,
    pub(super) changes_committed: usize,
}

impl SyncProgress {
    pub(crate) fn new(
        operation_id: SessionOperationId,
        phase: SyncProgressPhase,
        vault_index: usize,
        vault_count: usize,
        pages_committed: usize,
        changes_committed: usize,
    ) -> Self {
        Self {
            operation_id,
            phase,
            vault_index,
            vault_count,
            pages_committed,
            changes_committed,
        }
    }

    #[must_use]
    pub fn operation_id(&self) -> SessionOperationId {
        self.operation_id
    }

    #[must_use]
    pub fn phase(&self) -> SyncProgressPhase {
        self.phase
    }

    #[must_use]
    pub fn vault_index(&self) -> usize {
        self.vault_index
    }

    #[must_use]
    pub fn vault_count(&self) -> usize {
        self.vault_count
    }

    #[must_use]
    pub fn pages_committed(&self) -> usize {
        self.pages_committed
    }

    #[must_use]
    pub fn changes_committed(&self) -> usize {
        self.changes_committed
    }
}

pub trait SyncProgressSink: Send + Sync {
    fn report(&self, progress: SyncProgress);
}
