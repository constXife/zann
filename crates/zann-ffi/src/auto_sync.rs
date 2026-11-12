//! The core's automatic sync schedule, read against the monotonic clock here
//! so a shell only runs a timer and the sync itself.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use zann_client::app::local::{AutoSyncSchedule, AutoSyncTicket};

/// Admission for one sync; hand it back to `finished`.
#[derive(uniffi::Object)]
pub struct AutoSyncTicketFfi(AutoSyncTicket);

#[derive(uniffi::Object)]
pub struct AutoSyncScheduleFfi(Mutex<AutoSyncSchedule>);

impl AutoSyncScheduleFfi {
    fn with<T>(&self, change: impl FnOnce(&mut AutoSyncSchedule) -> T) -> T {
        change(&mut self.0.lock().expect("lock poisoned"))
    }
}

#[uniffi::export]
impl AutoSyncScheduleFfi {
    /// A locked schedule; nothing is due until `unlocked`.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(AutoSyncSchedule::new())))
    }

    /// `synced` is whether a sync already ran as part of opening the vault.
    pub fn unlocked(&self, synced: bool) {
        self.with(|schedule| schedule.unlocked(Instant::now(), synced));
    }

    pub fn locked(&self) {
        self.with(AutoSyncSchedule::locked);
    }

    /// A local write committed.
    pub fn local_change(&self) {
        self.with(|schedule| schedule.local_change(Instant::now()));
    }

    /// The automatic sync to run now, if one is due.
    pub fn take_due(&self) -> Option<Arc<AutoSyncTicketFfi>> {
        self.with(|schedule| schedule.take_due(Instant::now()))
            .map(|ticket| Arc::new(AutoSyncTicketFfi(ticket)))
    }

    /// The sync the user asked for; `None` while one already runs.
    pub fn take_now(&self) -> Option<Arc<AutoSyncTicketFfi>> {
        self.with(AutoSyncSchedule::take_now)
            .map(|ticket| Arc::new(AutoSyncTicketFfi(ticket)))
    }

    /// The admitted sync ended, whatever its outcome.
    pub fn finished(&self, ticket: Arc<AutoSyncTicketFfi>) {
        // The shell drops its vault model on lock, so no stale result
        // can reach a later unlock there.
        self.with(|schedule| schedule.finished(ticket.0, Instant::now()));
    }
}
