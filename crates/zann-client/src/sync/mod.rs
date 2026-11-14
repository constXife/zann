//! Database-free sync owner.
//!
//! The public surface contains bounded domain models and a transactional local
//! store port. HTTP authorization, wire DTOs and bearer handling stay private.

#[cfg_attr(not(feature = "app"), allow(dead_code))]
mod account_key;
mod engine;
mod model;
mod schedule;
pub(crate) mod transport;
#[cfg(feature = "app")]
pub(crate) use engine::{await_remote, map_session_error};
#[cfg(feature = "app")]
pub(crate) use model::MAX_CATALOG_VAULTS;
mod wire;

#[cfg(feature = "app")]
pub(crate) use account_key::verify_with_session;
pub use account_key::AccountKeyCheck;
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
pub use schedule::{AutoSyncSchedule, AutoSyncTicket, AUTO_SYNC_DEBOUNCE, AUTO_SYNC_INTERVAL};
