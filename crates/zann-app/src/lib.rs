//! Headless application layer.
//!
//! The logic every Zann client needs and no client should own: no toolkit, no
//! `$HOME`, no file dialogs. Callers hand in an open pool, an unlocked key, and
//! the paths they have already resolved.
//!
//! Today this is backup only; ADR 0003 moves session, items, vaults, storage,
//! history and sync orchestration here in later phases.

pub mod backup;

pub use backup::{
    BackupCtx, BackupError, ExportReport, ImportOutcome, ImportReport, PlainBackupItem,
    PlainBackupStorage, PlainBackupVault,
};
