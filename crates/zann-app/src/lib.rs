//! Headless application layer.
//!
//! The logic every Zann client needs and no client should own: no toolkit, no
//! `$HOME`, no file dialogs. Callers hand in an open pool, an unlocked key, and
//! the paths they have already resolved.
//!
//! Today this is backup, snapshots and verification; ADR 0003 moves session,
//! items, vaults, storage, history and sync orchestration here in later phases.

pub mod backup;
pub mod snapshot;
pub mod verify;

pub use backup::{
    BackupCtx, BackupError, ExportReport, ImportOutcome, ImportReport, PlainBackupItem,
    PlainBackupStorage, PlainBackupVault,
};
pub use snapshot::{RestoreOutcome, RetentionPolicy, Snapshot, SnapshotError};
pub use verify::{VerifyError, VerifyProblem, VerifyReport};
