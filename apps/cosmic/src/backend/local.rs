//! The vault on this machine, through `zann-ffi`.

use std::sync::Arc;

use zann_ffi::{
    create_core_at_file_location, AppStatusFfi, BackupExportReport, CoreFacade, HardwareKeyFfi,
    ItemDetail, ItemSummary, ItemsFilter, Page, RememberedUnlockFfi, SnapshotFfi,
    SnapshotRestoreFfi, StorageSummaryFfi, VerifyReportFfi,
};
use zann_ui_core::ItemCounts;

use super::DatabaseLocation;

/// How many items a single `items_list` call pages in.
pub const PAGE_LIMIT: u32 = 200;

/// How stale the newest snapshot may get before start-up takes another.
const SNAPSHOT_MAX_AGE_HOURS: u32 = 24;

pub type Facade = Arc<CoreFacade>;

/// A page of items plus the totals the nav bar badges need.
#[derive(Debug, Clone)]
pub struct ItemsPage {
    pub items: Vec<ItemSummary>,
    pub next_cursor: Option<String>,
    pub total: u64,
    pub counts: ItemCounts,
}

/// Opens an explicitly resolved database and reports what the app should show first.
pub fn open_at(location: &DatabaseLocation) -> Result<(Facade, AppStatusFfi), String> {
    std::fs::create_dir_all(location.client_root()).map_err(|err| err.to_string())?;
    let facade = open_core(location)?;

    // A daily copy of the database, taken before the user touches anything and
    // without needing the key. Deliberately not fatal: failing to take a
    // snapshot is a reason to tell someone later, never a reason to refuse to
    // open the vault.
    if let Err(err) = facade.snapshot_create_if_due(SNAPSHOT_MAX_AGE_HOURS, None) {
        eprintln!("zann: could not take a snapshot: {err}");
    }

    let status = facade.app_status().map_err(|err| err.to_string())?;
    Ok((facade, status))
}

/// Connecting to a server rewrites the identity config, so the facade has to be
/// rebuilt from the same explicitly resolved database afterwards.
pub fn reopen_at(location: &DatabaseLocation) -> Result<Facade, String> {
    open_core(location)
}

fn open_core(location: &DatabaseLocation) -> Result<Facade, String> {
    create_core_at_file_location(location.file_location()).map_err(|err| err.to_string())
}

pub fn initialize_master_password(facade: &CoreFacade, password: String) -> Result<(), String> {
    facade
        .initialize_master_password(password)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

pub fn unlock(facade: &CoreFacade, password: String) -> Result<(), String> {
    facade
        .unlock(password)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

pub fn sync(facade: &CoreFacade, storage_id: Option<String>) -> Result<(), String> {
    facade
        .remote_sync(storage_id)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

pub fn storages(facade: &CoreFacade) -> Result<Vec<StorageSummaryFfi>, String> {
    facade.list_storages().map_err(|err| err.to_string())
}

pub fn items(facade: &CoreFacade, cursor: Option<String>) -> Result<ItemsPage, String> {
    let page = facade
        .items_list(
            ItemsFilter {
                query: None,
                // The trash category filters client-side, so deleted items have
                // to be part of the page.
                include_deleted: true,
            },
            Page {
                limit: PAGE_LIMIT,
                cursor,
            },
        )
        .map_err(|err| err.to_string())?;
    Ok(ItemsPage {
        counts: ItemCounts::from(&page.counts),
        items: page.items,
        next_cursor: page.next_cursor,
        total: page.total_count,
    })
}

pub fn item_get(facade: &CoreFacade, id: String) -> Result<ItemDetail, String> {
    facade.item_get(id).map_err(|err| err.to_string())
}

// -- Remembered unlock -------------------------------------------------------
//
// The policy lives in `zann-keystore` behind `zann-ffi`; this app only asks.
// Enrolment and unlocking wait on a physical touch, so both belong on a worker
// thread like everything else here.

pub fn remembered_unlock(facade: &CoreFacade) -> Result<RememberedUnlockFfi, String> {
    facade.remembered_unlock().map_err(|err| err.to_string())
}

/// One touch when the source is a hardware key.
pub fn unlock_remembered(facade: &CoreFacade) -> Result<(), String> {
    facade
        .unlock_remembered()
        .map(|_| ())
        .map_err(|err| err.to_string())
}

/// Silent — no touch. Safe to call while the user is doing something else.
pub fn hardware_key_present(facade: &CoreFacade) -> Result<bool, String> {
    facade.hardware_key_present().map_err(|err| err.to_string())
}

/// Two touches: create the credential, then prove it yields a secret.
pub fn enroll_hardware_key(facade: &CoreFacade, label: String) -> Result<HardwareKeyFfi, String> {
    facade
        .enroll_hardware_key(label)
        .map_err(|err| err.to_string())
}

pub fn remove_hardware_key(facade: &CoreFacade, credential_id: String) -> Result<(), String> {
    facade
        .remove_hardware_key(credential_id)
        .map_err(|err| err.to_string())
}

/// Writes a plain backup of every local vault. The facade picks the path,
/// because this client has no file picker of its own — see
/// docs/adr/0002-client-strategy.md on why being able to leave comes first.
pub fn export_backup(facade: &CoreFacade) -> Result<BackupExportReport, String> {
    facade
        .backup_export_file(String::new())
        .map_err(|err| err.to_string())
}

/// Copy the database aside now, whatever the schedule says.
pub fn snapshot_now(facade: &CoreFacade) -> Result<SnapshotFfi, String> {
    facade.snapshot_create(None).map_err(|err| err.to_string())
}

/// Newest first.
pub fn snapshots(facade: &CoreFacade) -> Result<Vec<SnapshotFfi>, String> {
    facade.snapshot_list().map_err(|err| err.to_string())
}

/// Put a snapshot back. Leaves the vault locked, because the restored database
/// may have been written under a different password.
pub fn restore_snapshot(facade: &CoreFacade, path: String) -> Result<SnapshotRestoreFfi, String> {
    facade.snapshot_restore(path).map_err(|err| err.to_string())
}

/// Walk every item and check it is still readable. Needs the vault unlocked.
pub fn verify(facade: &CoreFacade) -> Result<VerifyReportFfi, String> {
    facade.verify().map_err(|err| err.to_string())
}
