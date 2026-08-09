//! The vault on this machine, through `zann-ffi`.

use std::sync::Arc;

use zann_ffi::{
    create_core, AppStatusFfi, BackupExportReport, CoreFacade, HardwareKeyFfi, ItemDetail,
    ItemSummary, ItemsFilter, Page, RememberedUnlockFfi,
};
use zann_ui_core::ItemCounts;

use super::{default_db_url, local_root};

/// How many items a single `items_list` call pages in.
pub const PAGE_LIMIT: u32 = 200;

pub type Facade = Arc<CoreFacade>;

/// A page of items plus the totals the nav bar badges need.
#[derive(Debug, Clone)]
pub struct ItemsPage {
    pub items: Vec<ItemSummary>,
    pub next_cursor: Option<String>,
    pub total: u64,
    pub counts: ItemCounts,
}

/// Opens the local database and reports what the app should show first.
pub fn open() -> Result<(Facade, AppStatusFfi), String> {
    let _ = std::fs::create_dir_all(local_root());
    open_at(default_db_url())
}

/// [`open`] against an explicit database, for tests and for anything that has
/// already resolved the URL itself.
pub fn open_at(db_url: String) -> Result<(Facade, AppStatusFfi), String> {
    let facade = create_core(db_url).map_err(|err| err.to_string())?;
    let status = facade.app_status().map_err(|err| err.to_string())?;
    Ok((facade, status))
}

/// Connecting to a server rewrites the identity config, so the facade has to be
/// rebuilt from it afterwards.
pub fn reopen() -> Result<Facade, String> {
    create_core(default_db_url()).map_err(|err| err.to_string())
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
        .map_err(|err| err.to_string())
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
