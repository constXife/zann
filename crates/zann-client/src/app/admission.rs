//! One admission owner for sync, enrollment, reset and database replacement.
use super::AppClient;
use std::sync::atomic::{AtomicBool, Ordering};
static APP_SYNC_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

pub(super) struct AppSyncPermit {
    _private: (),
}

impl AppSyncPermit {
    pub(super) fn try_acquire() -> Result<Self, ()> {
        APP_SYNC_IN_FLIGHT
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ())?;
        Ok(Self { _private: () })
    }
}

impl Drop for AppSyncPermit {
    fn drop(&mut self) {
        APP_SYNC_IN_FLIGHT.store(false, Ordering::Release);
    }
}

/// Excludes operation-scoped stores while the native adapter replaces SQLite.
pub struct AppMaintenanceLease {
    _permit: AppSyncPermit,
}
impl AppClient {
    pub fn try_exclusive_local_maintenance(&self) -> Option<AppMaintenanceLease> {
        AppSyncPermit::try_acquire()
            .ok()
            .map(|permit| AppMaintenanceLease { _permit: permit })
    }
}
