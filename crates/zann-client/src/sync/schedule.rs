//! When an unlocked client syncs without being asked.
//!
//! Shells own the timer and the call to sync; this type owns every decision
//! about when: right after unlock, shortly after a local write so a burst of
//! saves leaves as one sync, and on a fixed interval to pick up other devices'
//! changes. It admits one sync at a time, manual or automatic, and forgets
//! everything on lock, so a completion from an earlier unlock cannot schedule
//! anything. It reads no clock: callers pass `now`.

use std::time::{Duration, Instant};

/// How long a local write waits before it is pushed.
pub const AUTO_SYNC_DEBOUNCE: Duration = Duration::from_secs(2);

/// How long an unlocked client waits between syncs when nothing changed
/// locally. It bounds how stale another device's change can be here.
pub const AUTO_SYNC_INTERVAL: Duration = Duration::from_secs(60);

/// Admission for one sync, handed back on completion. A ticket from before a
/// lock no longer matches and its completion is ignored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutoSyncTicket {
    unlock: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Locked,
    Waiting {
        due: Instant,
    },
    /// `changed` records a local write the running sync may have missed.
    Running {
        changed: bool,
    },
}

#[derive(Debug)]
pub struct AutoSyncSchedule {
    /// Bumped on every unlock and lock.
    unlock: u64,
    state: State,
}

impl Default for AutoSyncSchedule {
    fn default() -> Self {
        Self::new()
    }
}

impl AutoSyncSchedule {
    /// A locked schedule: nothing is due until [`Self::unlocked`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            unlock: 0,
            state: State::Locked,
        }
    }

    /// The vault opened. A sync is due at once, unless one already ran as
    /// part of opening it.
    pub fn unlocked(&mut self, now: Instant, synced: bool) {
        self.unlock = self.unlock.wrapping_add(1);
        let due = if synced {
            now + AUTO_SYNC_INTERVAL
        } else {
            now
        };
        self.state = State::Waiting { due };
    }

    /// The vault locked: nothing is due, and a running sync's completion will
    /// be ignored.
    pub fn locked(&mut self) {
        self.unlock = self.unlock.wrapping_add(1);
        self.state = State::Locked;
    }

    /// A local write committed; it is pushed after [`AUTO_SYNC_DEBOUNCE`], or
    /// right after the sync already running.
    pub fn local_change(&mut self, now: Instant) {
        match &mut self.state {
            State::Locked => {}
            State::Waiting { due } => *due = (*due).min(now + AUTO_SYNC_DEBOUNCE),
            State::Running { changed } => *changed = true,
        }
    }

    /// When the next automatic sync is due; `None` while locked or while a
    /// sync runs.
    #[must_use]
    pub fn next_due(&self) -> Option<Instant> {
        match self.state {
            State::Waiting { due } => Some(due),
            State::Locked | State::Running { .. } => None,
        }
    }

    /// Admits the automatic sync if it is due.
    pub fn take_due(&mut self, now: Instant) -> Option<AutoSyncTicket> {
        match self.state {
            State::Waiting { due } if due <= now => self.admit(),
            _ => None,
        }
    }

    /// Admits a sync the user asked for; `None` while one already runs or
    /// the vault is locked.
    pub fn take_now(&mut self) -> Option<AutoSyncTicket> {
        match self.state {
            State::Waiting { .. } => self.admit(),
            State::Locked | State::Running { .. } => None,
        }
    }

    /// The admitted sync ended, whatever its outcome. A failure waits the
    /// full interval like a success, so an unreachable server is not hammered;
    /// a local write starts the next one sooner. Returns whether the ticket
    /// belongs to the current unlock; a caller drops a stale sync's result.
    pub fn finished(&mut self, ticket: AutoSyncTicket, now: Instant) -> bool {
        let State::Running { changed } = self.state else {
            return false;
        };
        if ticket.unlock != self.unlock {
            return false;
        }
        let wait = if changed {
            AUTO_SYNC_DEBOUNCE
        } else {
            AUTO_SYNC_INTERVAL
        };
        self.state = State::Waiting { due: now + wait };
        true
    }

    fn admit(&mut self) -> Option<AutoSyncTicket> {
        self.state = State::Running { changed: false };
        Some(AutoSyncTicket {
            unlock: self.unlock,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unlocked(now: Instant) -> AutoSyncSchedule {
        let mut schedule = AutoSyncSchedule::new();
        schedule.unlocked(now, false);
        schedule
    }

    #[test]
    fn nothing_is_due_while_locked() {
        let now = Instant::now();
        let mut schedule = AutoSyncSchedule::new();
        schedule.local_change(now);
        assert_eq!(schedule.next_due(), None);
        assert_eq!(schedule.take_due(now + AUTO_SYNC_INTERVAL), None);
        assert_eq!(schedule.take_now(), None);
    }

    #[test]
    fn unlock_syncs_at_once_unless_opening_already_synced() {
        let now = Instant::now();
        let mut schedule = unlocked(now);
        assert_eq!(schedule.next_due(), Some(now));
        assert!(schedule.take_due(now).is_some());

        let mut schedule = AutoSyncSchedule::new();
        schedule.unlocked(now, true);
        assert_eq!(schedule.next_due(), Some(now + AUTO_SYNC_INTERVAL));
        assert_eq!(schedule.take_due(now), None);
    }

    #[test]
    fn a_finished_sync_waits_the_interval() {
        let now = Instant::now();
        let mut schedule = unlocked(now);
        let ticket = schedule.take_due(now).expect("due on unlock");
        assert!(schedule.finished(ticket, now));
        assert_eq!(schedule.take_due(now + AUTO_SYNC_INTERVAL / 2), None);
        assert!(schedule.take_due(now + AUTO_SYNC_INTERVAL).is_some());
    }

    #[test]
    fn a_local_write_is_pushed_after_the_debounce() {
        let start = Instant::now();
        let mut schedule = unlocked(start);
        let ticket = schedule.take_due(start).expect("due on unlock");
        assert!(schedule.finished(ticket, start));

        let saved = start + Duration::from_secs(10);
        schedule.local_change(saved);
        assert_eq!(schedule.next_due(), Some(saved + AUTO_SYNC_DEBOUNCE));
        // A second save in the burst does not push the first one back.
        schedule.local_change(saved + Duration::from_secs(1));
        assert_eq!(schedule.next_due(), Some(saved + AUTO_SYNC_DEBOUNCE));
        assert!(schedule.take_due(saved + AUTO_SYNC_DEBOUNCE).is_some());
    }

    #[test]
    fn a_local_write_never_delays_a_sync_already_due_sooner() {
        let now = Instant::now();
        let mut schedule = unlocked(now);
        schedule.local_change(now);
        assert_eq!(schedule.next_due(), Some(now));
    }

    #[test]
    fn a_write_during_a_sync_is_pushed_right_after_it() {
        let now = Instant::now();
        let mut schedule = unlocked(now);
        let ticket = schedule.take_due(now).expect("due on unlock");
        schedule.local_change(now);
        assert_eq!(schedule.next_due(), None);
        let done = now + Duration::from_secs(5);
        assert!(schedule.finished(ticket, done));
        assert_eq!(schedule.next_due(), Some(done + AUTO_SYNC_DEBOUNCE));
    }

    #[test]
    fn only_one_sync_runs_at_a_time() {
        let now = Instant::now();
        let mut schedule = unlocked(now);
        let ticket = schedule.take_now().expect("manual sync admitted");
        assert_eq!(schedule.take_now(), None);
        assert_eq!(schedule.take_due(now + AUTO_SYNC_INTERVAL), None);
        assert!(schedule.finished(ticket, now));
        assert!(schedule.take_now().is_some());
    }

    #[test]
    fn lock_drops_what_was_due_and_ignores_the_running_sync() {
        let now = Instant::now();
        let mut schedule = unlocked(now);
        let stale = schedule.take_due(now).expect("due on unlock");
        schedule.locked();
        assert_eq!(schedule.next_due(), None);

        // The sync from before the lock ends after the next unlock started
        // its own; it must neither end nor reschedule the new one.
        schedule.unlocked(now, false);
        let current = schedule.take_due(now).expect("due on the new unlock");
        assert!(!schedule.finished(stale, now));
        assert_eq!(schedule.take_now(), None);
        assert!(schedule.finished(current, now));
        assert_eq!(schedule.next_due(), Some(now + AUTO_SYNC_INTERVAL));
    }

    #[test]
    fn a_stale_completion_after_lock_schedules_nothing() {
        let now = Instant::now();
        let mut schedule = unlocked(now);
        let ticket = schedule.take_due(now).expect("due on unlock");
        schedule.locked();
        assert!(!schedule.finished(ticket, now));
        assert_eq!(schedule.next_due(), None);
    }
}
