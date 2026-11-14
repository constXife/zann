//! The open local database, owned for the lifetime of the app.
//!
//! A `Session` only exists when the database opened, so no screen has to carry
//! an `Option<Facade>` or guess what to do without one — the shell shows
//! [`crate::Shell::Blocked`] instead.

use std::cell::{RefCell, RefMut};

use zann_client::app::local::AppStatus;
use zann_client::app::local::AutoSyncSchedule;

use crate::backend::local::{self, Facade};
use crate::backend::{activate_database, ActiveDatabaseGuard, DatabaseLocation};

pub struct Session {
    daemon: zann_daemon::Daemon,
    facade: Facade,
    location: DatabaseLocation,
    /// Outlives every vault screen, so a lock from any path forgets what was
    /// due and a sync from before it cannot complete into the next unlock.
    auto_sync: RefCell<AutoSyncSchedule>,
    _active_database: ActiveDatabaseGuard,
}

impl Session {
    pub fn open() -> Result<(Self, AppStatus), String> {
        Self::open_at(DatabaseLocation::resolve_default()?)
    }

    /// Opens a database location already resolved by the composition root.
    pub fn open_at<L>(location: L) -> Result<(Self, AppStatus), String>
    where
        L: TryInto<DatabaseLocation>,
        L::Error: ToString,
    {
        let location = location.try_into().map_err(|err| err.to_string())?;
        let (facade, status) = local::open_at(&location)?;
        let daemon = zann_daemon::Daemon::start(
            location.client_root(),
            facade.clone(),
        )
        .map_err(|error| error.to_string())?;
        let active_database = activate_database(location.clone());
        Ok((
            Self {
                daemon,
                facade,
                location,
                auto_sync: RefCell::new(AutoSyncSchedule::new()),
                _active_database: active_database,
            },
            status,
        ))
    }

    /// A handle to hand to a worker thread.
    pub fn facade(&self) -> Facade {
        self.facade.clone()
    }

    pub fn browser_control(&self) -> zann_daemon::DaemonControl {
        self.daemon.control()
    }

    pub fn database_location(&self) -> &DatabaseLocation {
        &self.location
    }

    /// When the core says to sync; screens run the timer and the sync.
    pub fn auto_sync(&self) -> RefMut<'_, AutoSyncSchedule> {
        self.auto_sync.borrow_mut()
    }

    /// Also cancels a sync in flight and everything the schedule had due.
    pub fn lock(&self) {
        let _ = self.facade.lock();
        self.auto_sync().locked();
    }
}
