//! Local vault application contract; implementations receive explicit native paths.

mod browser;
mod error;
pub use browser::*;
mod model;
mod port;
pub use error::*;
pub use model::*;
pub use port::*;

/// Cancellation/deadline controls accepted by the local item-read port.
pub use crate::session::{SessionCancellationHandle, SessionOperation};

/// When an unlocked shell syncs; the shell runs the timer and `remote_sync`.
pub use crate::sync::{AutoSyncSchedule, AutoSyncTicket, AUTO_SYNC_DEBOUNCE, AUTO_SYNC_INTERVAL};
