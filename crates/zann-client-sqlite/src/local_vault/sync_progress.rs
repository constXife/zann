//! Coalesced durable sync notices, published outside the Tokio entry context.
use super::*;
use zann_client::app::{SyncProgress, SyncProgressPhase, SyncProgressSink};

/// One latest notice plus one wake token bounds memory even if a reader is slow.
struct CommittedProgress {
    latest: Mutex<Option<SyncProgress>>,
    wake: tokio::sync::mpsc::Sender<()>,
}

impl SyncProgressSink for CommittedProgress {
    fn report(&self, progress: SyncProgress) {
        if matches!(
            progress.phase(),
            SyncProgressPhase::CatalogCommitted | SyncProgressPhase::PageCommitted
        ) {
            *self.latest.lock().expect("progress lock poisoned") = Some(progress);
            // A full channel already has the wake token for the latest notice.
            let _ = self.wake.try_send(());
        }
    }
}

impl LocalVault {
    /// Runs until completion or lock; each durable notice may expose cached
    /// data before the whole pull finishes. No observer runs with a core lock.
    pub fn remote_sync(
        &self,
        storage_id: Option<String>,
        observer: Option<&LocalSyncObserver>,
    ) -> LocalResult<LocalSyncOutcome> {
        let (operation, cancel) = SessionOperation::new(
            std::time::Instant::now() + std::time::Duration::from_secs(10 * 60),
        );
        let _in_flight = self.syncs.register(operation.operation_id(), cancel);
        let (wake, mut receiver) = tokio::sync::mpsc::channel(1);
        let progress = Arc::new(CommittedProgress {
            latest: Mutex::new(None),
            wake,
        });
        let client = self.app_client()?.with_sync_progress(progress.clone());
        let target = client
            .configured_target(storage_id.as_deref())
            .map_err(|error| LocalError::Service(error.to_string()))?;
        let master_key = self.account_key_for_target(&target)?;
        let (selection_before, generation) = {
            let _context = self.context_gate.read().expect("lock poisoned");
            (
                *self.storage_id.lock().expect("lock poisoned"),
                self.context_generation.load(Ordering::SeqCst),
            )
        };
        let operation_key = SecretKey::from_bytes(*master_key.as_bytes());
        let mut sync = client.sync(target, operation_key, operation);
        loop {
            // Retain the same sync future across notices. Returning from
            // block_on lets selection and callbacks safely use blocking reads.
            let finished = self.runtime.block_on(async {
                tokio::select! {
                    biased;
                    _ = receiver.recv() => None,
                    outcome = &mut sync => Some(outcome),
                }
            });
            let notice = progress
                .latest
                .lock()
                .expect("progress lock poisoned")
                .take();
            if let Some(notice) = notice {
                let storage = notice.storage_id().expect("durable notice has a storage");
                self.select_synced_catalog(
                    Some(storage.to_string()),
                    selection_before,
                    &master_key,
                    generation,
                )?;
                if let Some(observer) = observer {
                    observer(notice);
                }
            }
            // A ready sync may have reported its last commit during the same
            // poll, after select! checked the receiver. Drain it before return.
            if let Some(outcome) = finished {
                return outcome
                    .map(LocalSyncOutcome::from)
                    .map_err(LocalError::from);
            }
        }
    }
}
