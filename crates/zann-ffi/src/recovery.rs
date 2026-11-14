//! Scoped local recovery is implemented by the native core, never by IPC.
use crate::{CoreFacade, CoreResult};
use zann_client::app::local as model;
#[derive(Clone, Debug, uniffi::Record)]
pub struct SetupAccountFfi {
    pub storage_id: String,
    pub name: String,
    pub account_name: Option<String>,
    pub server_url: String,
    pub enrolled: bool,
    pub has_replica: bool,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct RecoveryPreviewFfi {
    pub id: String,
    pub accounts: u64,
    pub items: u64,
    pub pending: u64,
    pub dirty: u64,
    pub local_history: u64,
    pub has_unsent: bool,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct RecoveryOutcomeFfi {
    pub snapshot_path: String,
    pub device_reset: bool,
}
#[uniffi::export]
impl CoreFacade {
    pub fn setup_accounts(&self) -> CoreResult<Vec<SetupAccountFfi>> {
        self.inner
            .setup_accounts()
            .map(|rows| {
                rows.into_iter()
                    .map(|row| SetupAccountFfi {
                        storage_id: row.location.storage_id,
                        name: row.location.name,
                        account_name: row.location.account_name,
                        server_url: row.location.server_url,
                        enrolled: row.enrolled,
                        has_replica: row.has_replica,
                    })
                    .collect()
            })
            .map_err(Into::into)
    }
    pub fn prepare_local_recovery(
        &self,
        storage_id: Option<String>,
    ) -> CoreResult<RecoveryPreviewFfi> {
        let scope = storage_id.map_or(model::RecoveryScope::Device, model::RecoveryScope::Account);
        self.inner
            .prepare_local_recovery(scope)
            .map(|row| RecoveryPreviewFfi {
                has_unsent: row.has_unsent(),
                id: row.id,
                accounts: row.accounts,
                items: row.items,
                pending: row.pending,
                dirty: row.dirty,
                local_history: row.local_history,
            })
            .map_err(Into::into)
    }
    pub fn cancel_local_recovery(&self, id: String) -> CoreResult<()> {
        self.inner.cancel_local_recovery(id).map_err(Into::into)
    }
    pub fn confirm_local_recovery(
        &self,
        id: String,
        discard_unsent: bool,
    ) -> CoreResult<RecoveryOutcomeFfi> {
        self.inner
            .confirm_local_recovery(id, discard_unsent)
            .map(|row| RecoveryOutcomeFfi {
                snapshot_path: row.snapshot_path,
                device_reset: row.device_reset,
            })
            .map_err(Into::into)
    }
}
