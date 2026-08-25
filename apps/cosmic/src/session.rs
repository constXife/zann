//! The open local database, owned for the lifetime of the app.
//!
//! A `Session` only exists when the database opened, so no screen has to carry
//! an `Option<Facade>` or guess what to do without one — the shell shows
//! [`crate::Shell::Blocked`] instead.

use zann_ffi::AppStatusFfi;

use crate::backend::local::{self, Facade};
use crate::backend::{activate_database, ActiveDatabaseGuard, DatabaseLocation};

pub struct Session {
    facade: Facade,
    location: DatabaseLocation,
    _active_database: ActiveDatabaseGuard,
}

impl Session {
    pub fn open() -> Result<(Self, AppStatusFfi), String> {
        Self::open_at(DatabaseLocation::resolve_default()?)
    }

    /// Opens a database location already resolved by the composition root.
    pub fn open_at<L>(location: L) -> Result<(Self, AppStatusFfi), String>
    where
        L: TryInto<DatabaseLocation>,
        L::Error: ToString,
    {
        let location = location.try_into().map_err(|err| err.to_string())?;
        let (facade, status) = local::open_at(&location)?;
        let active_database = activate_database(location.clone());
        Ok((
            Self {
                facade,
                location,
                _active_database: active_database,
            },
            status,
        ))
    }

    /// A handle to hand to a worker thread.
    pub fn facade(&self) -> Facade {
        self.facade.clone()
    }

    pub fn database_location(&self) -> &DatabaseLocation {
        &self.location
    }

    /// A server login rewrites the identity config, so the facade derived from
    /// it is stale afterwards.
    pub fn reload(&mut self) -> Result<(), String> {
        self.facade = local::reopen_at(&self.location)?;
        Ok(())
    }

    pub fn lock(&self) {
        let _ = self.facade.lock();
    }
}
