use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncStoreErrorKind {
    NotFound,
    Busy,
    StaleCheckpoint,
    StaleKeyBinding,
    StaleItem,
    PendingChanged,
    PendingPresent,
    CommitOutcomeUnknown,
    InvalidData,
    Unavailable,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncStoreError {
    pub(super) kind: SyncStoreErrorKind,
}

impl SyncStoreError {
    #[must_use]
    pub const fn new(kind: SyncStoreErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> SyncStoreErrorKind {
        self.kind
    }
}

impl fmt::Display for SyncStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sync_store:{}", sync_store_error_code(self.kind))
    }
}

impl std::error::Error for SyncStoreError {}

pub(super) const fn sync_store_error_code(kind: SyncStoreErrorKind) -> &'static str {
    match kind {
        SyncStoreErrorKind::NotFound => "not_found",
        SyncStoreErrorKind::Busy => "busy",
        SyncStoreErrorKind::StaleCheckpoint => "stale_checkpoint",
        SyncStoreErrorKind::StaleKeyBinding => "stale_key_binding",
        SyncStoreErrorKind::StaleItem => "stale_item",
        SyncStoreErrorKind::PendingChanged => "pending_changed",
        SyncStoreErrorKind::PendingPresent => "pending_present",
        SyncStoreErrorKind::CommitOutcomeUnknown => "commit_outcome_unknown",
        SyncStoreErrorKind::InvalidData => "invalid_data",
        SyncStoreErrorKind::Unavailable => "unavailable",
        SyncStoreErrorKind::Internal => "internal",
    }
}

pub type SyncStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, SyncStoreError>> + Send + 'a>>;

/// Boxed future used by the crate-internal DB-free sync owner and public facade.
pub type SyncFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SyncError>> + Send + 'a>>;

/// Transactional local projection port. Implementations may use SQLite, but this crate cannot.
pub trait SyncLocalStore: Send + Sync {
    fn resolve_target<'a>(
        &'a self,
        target: &'a SessionTarget,
        generation: Arc<AuthorizedTargetGeneration>,
        personal_vaults_enabled: bool,
    ) -> SyncStoreFuture<'a, ResolvedSyncTarget>;

    /// Atomically reconciles safe catalog metadata and existing key bindings.
    /// It must never delete dirty/pending/conflict projections, silently
    /// replace a bound key, or initialize a shared first-snapshot cursor.
    fn reconcile_catalog(
        self: Arc<Self>,
        target: Arc<ResolvedSyncTarget>,
        catalog: Arc<CatalogSnapshot>,
    ) -> SyncStoreFuture<'static, ReconciledCatalog>;

    fn load_checkpoint<'a>(&'a self, scope: SyncScope) -> SyncStoreFuture<'a, SyncCheckpoint>;

    fn load_item_states<'a>(
        &'a self,
        scope: SyncScope,
        item_ids: &'a [Uuid],
    ) -> SyncStoreFuture<'a, Vec<ItemState>>;

    fn prepare_generated_key(
        self: Arc<Self>,
        _scope: SyncScope,
        _expected_remote_envelope: Vec<u8>,
    ) -> SyncStoreFuture<'static, GeneratedVaultKeyCommit> {
        Box::pin(async { Err(SyncStoreError::new(SyncStoreErrorKind::Unavailable)) })
    }

    fn commit_generated_key(
        self: Arc<Self>,
        commit: GeneratedVaultKeyCommit,
    ) -> SyncStoreFuture<'static, ()>;

    fn commit_push(
        self: Arc<Self>,
        commit: PushCommitPlan,
    ) -> SyncStoreFuture<'static, PushCommitReceipt>;

    /// Applies the complete page and advances `(cursor, last_seq)` atomically.
    /// Every [`ItemProjection`] in the plan must be persisted with
    /// `SyncStatus::Synced`; `deleted_at` alone distinguishes a confirmed
    /// remote tombstone. Each [`HistoryProjection`] is authoritative only for
    /// the matching server-confirmed history identity. Reconciliation may
    /// replace stale server-confirmed rows for that identity, but must preserve
    /// local/UI, pending, rejected, and conflict history.
    /// The owned plan lets the engine detach this terminal transaction from a
    /// dropped/cancelled caller once dispatch has begun. Ambiguous database
    /// COMMIT outcomes must be returned as `CommitOutcomeUnknown` and
    /// reconciled from the durable checkpoint before any retry. Runtime or
    /// process shutdown can still abort the terminal task; after restart the
    /// adapter must read the atomic checkpoint before dispatching another page.
    fn commit_pull_page(
        self: Arc<Self>,
        commit: PullPageCommit,
    ) -> SyncStoreFuture<'static, PullCommitReceipt>;

    fn reset_projection_if_clean(
        self: Arc<Self>,
        reset: ProjectionReset,
    ) -> SyncStoreFuture<'static, ()>;
}
