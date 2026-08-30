//! Transitional local maintenance implementations.
//!
//! `zann-client::app` is the sole application-composition owner. This crate is
//! frozen under MIG-008 at the three implementations extracted before that
//! decision: backup, snapshots and verification. Callers hand in an open pool,
//! an unlocked key and explicit paths; no new session, auth, sync, item, vault
//! or storage orchestration belongs here.

pub mod backup;
pub mod secure_file;
pub mod snapshot;
pub mod verify;

pub use backup::{
    ApplePasswordsImportReport, ApplePasswordsPreflight, BackupCtx, BackupError, ExportReport,
    ImportOutcome, ImportReport, PlainBackupItem, PlainBackupStorage, PlainBackupVault,
};
pub use snapshot::{RestoreOutcome, RetentionPolicy, Snapshot, SnapshotError};
pub use verify::{VerifyError, VerifyProblem, VerifyReport};
