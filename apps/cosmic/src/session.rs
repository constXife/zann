//! The open local database, owned for the lifetime of the app.
//!
//! A `Session` only exists when the database opened, so no screen has to carry
//! an `Option<Facade>` or guess what to do without one — the shell shows
//! [`crate::Shell::Blocked`] instead.

use zann_ffi::AppStatusFfi;

use crate::backend::local::{self, Facade};

pub struct Session {
    facade: Facade,
}

impl Session {
    pub fn open() -> Result<(Self, AppStatusFfi), String> {
        let (facade, status) = local::open()?;
        Ok((Self { facade }, status))
    }

    /// [`Session::open`] against an explicit database, for tests.
    pub fn open_at(db_url: String) -> Result<(Self, AppStatusFfi), String> {
        let (facade, status) = local::open_at(db_url)?;
        Ok((Self { facade }, status))
    }

    /// A handle to hand to a worker thread.
    pub fn facade(&self) -> Facade {
        self.facade.clone()
    }

    /// A server login rewrites the identity config, so the facade derived from
    /// it is stale afterwards.
    pub fn reload(&mut self) -> Result<(), String> {
        self.facade = local::reopen()?;
        Ok(())
    }

    pub fn lock(&self) {
        let _ = self.facade.lock();
    }
}
