//! Durable metadata notifications; item data stays in the local read projections.
use crate::*;
use zann_client::app::{SyncProgress, SyncProgressPhase};

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum SyncCommitPhaseFfi {
    Catalog,
    Page,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SyncCommitFfi {
    pub storage_id: String,
    pub phase: SyncCommitPhaseFfi,
    pub pages_committed: u64,
    pub changes_committed: u64,
}

#[uniffi::export(callback_interface)]
pub trait SyncCommitObserver: Send + Sync {
    fn committed(&self, update: SyncCommitFfi);
}

#[uniffi::export]
impl CoreFacade {
    pub fn remote_sync(
        &self,
        storage_id: Option<String>,
        progress: Option<Box<dyn SyncCommitObserver>>,
    ) -> CoreResult<SyncOutcomeFfi> {
        let report = move |notice: SyncProgress| {
            if let Some(progress) = &progress {
                progress.committed(SyncCommitFfi {
                    storage_id: notice
                        .storage_id()
                        .expect("durable notice has a storage")
                        .to_string(),
                    phase: match notice.phase() {
                        SyncProgressPhase::CatalogCommitted => SyncCommitPhaseFfi::Catalog,
                        SyncProgressPhase::PageCommitted => SyncCommitPhaseFfi::Page,
                        _ => unreachable!("local service reports only durable commits"),
                    },
                    pages_committed: notice.pages_committed() as u64,
                    changes_committed: notice.changes_committed() as u64,
                });
            }
        };
        self.inner
            .remote_sync(storage_id, Some(&report))
            .map(Into::into)
            .map_err(Into::into)
    }
}
