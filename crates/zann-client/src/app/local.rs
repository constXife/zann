//! Local vault application contract; implementations receive explicit native paths.

mod backup_error;
mod browser;
mod encrypted_backup;
pub use backup_error::*;
mod error;
mod export;
pub use browser::*;
pub use encrypted_backup::*;
pub use export::*;
mod model;
mod port;
mod recovery;
pub use error::*;
pub use model::*;
pub use port::*;
pub use recovery::*;

/// Maximum age of automatic local snapshots at native lifecycle opportunities.
pub const AUTO_SNAPSHOT_MAX_AGE_HOURS: u32 = 24;

/// Cancellation/deadline controls accepted by the local item-read port.
pub use crate::session::{SessionCancellationHandle, SessionOperation};

/// When an unlocked shell syncs; the shell runs the timer and `remote_sync`.
pub use crate::sync::{AutoSyncSchedule, AutoSyncTicket, AUTO_SYNC_DEBOUNCE, AUTO_SYNC_INTERVAL};
