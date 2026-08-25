//! Database-free sync owner.
//!
//! The public surface contains bounded domain models and a transactional local
//! store port. HTTP authorization, wire DTOs and bearer handling stay private.

mod engine;
mod model;
mod transport;
mod wire;

#[cfg(feature = "app")]
pub(crate) use engine::SyncEngine;
pub use model::{
    CatalogSnapshot, CatalogVault, ContentChecksum, GeneratedVaultKeyCommit, HistoryAuthority,
    HistoryProjection, ItemProjection, ItemProof, ItemState, PendingExpectation, PendingProof,
    ProjectionReset, PullCommitChange, PullCommitReceipt, PullPageCommit, PushCommitChange,
    PushCommitPlan, PushCommitReceipt, ReconciledCatalog, ResolvedSyncTarget, ResolvedSyncVault,
    StorageBindingProof, SyncCheckpoint, SyncCursor, SyncError, SyncErrorKind, SyncFuture,
    SyncLocalStore, SyncModelError, SyncOutcome, SyncOutcomeStatus, SyncProgress,
    SyncProgressPhase, SyncProgressSink, SyncScope, SyncSeq, SyncStage, SyncStoreError,
    SyncStoreErrorKind, SyncStoreFuture, VaultPayloadKey, VaultPlane,
};
