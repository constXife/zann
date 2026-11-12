//! The syncs in flight, so a lock can cancel them.
//!
//! A sync works with its own copy of the master key until it returns. Without
//! cancellation, locking while one runs would leave that copy alive for as
//! long as the server takes to answer.

use std::sync::Mutex;

use zann_client::app::{SessionCancellationHandle, SessionOperationId};

#[derive(Default)]
pub(super) struct InFlightSyncs(Mutex<Vec<(SessionOperationId, SessionCancellationHandle)>>);

impl InFlightSyncs {
    /// Tracks one sync until the returned guard drops.
    pub(super) fn register(
        &self,
        operation_id: SessionOperationId,
        cancel: SessionCancellationHandle,
    ) -> InFlightSync<'_> {
        self.0
            .lock()
            .expect("lock poisoned")
            .push((operation_id, cancel));
        InFlightSync {
            syncs: self,
            operation_id,
        }
    }

    pub(super) fn cancel_all(&self) {
        for (_, cancel) in self.0.lock().expect("lock poisoned").iter() {
            cancel.cancel();
        }
    }
}

pub(super) struct InFlightSync<'a> {
    syncs: &'a InFlightSyncs,
    operation_id: SessionOperationId,
}

impl Drop for InFlightSync<'_> {
    fn drop(&mut self) {
        self.syncs
            .0
            .lock()
            .expect("lock poisoned")
            .retain(|(id, _)| *id != self.operation_id);
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use zann_client::app::SessionOperation;

    use super::*;

    fn operation() -> (SessionOperation, SessionCancellationHandle) {
        SessionOperation::new(Instant::now() + Duration::from_secs(60))
    }

    #[test]
    fn cancel_all_cancels_every_registered_sync() {
        let syncs = InFlightSyncs::default();
        let (first, first_cancel) = operation();
        let (second, second_cancel) = operation();
        let _first = syncs.register(first.operation_id(), first_cancel.clone());
        let _second = syncs.register(second.operation_id(), second_cancel.clone());

        syncs.cancel_all();

        assert!(first_cancel.is_cancelled());
        assert!(second_cancel.is_cancelled());
    }

    #[test]
    fn a_finished_sync_is_no_longer_cancelled() {
        let syncs = InFlightSyncs::default();
        let (finished, finished_cancel) = operation();
        drop(syncs.register(finished.operation_id(), finished_cancel.clone()));

        syncs.cancel_all();

        assert!(!finished_cancel.is_cancelled());
        assert!(syncs.0.lock().expect("lock poisoned").is_empty());
    }
}
