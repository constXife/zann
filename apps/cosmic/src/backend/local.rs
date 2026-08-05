//! The vault on this machine, through `zann-ffi`.

use std::sync::Arc;

use zann_ffi::{create_core, AppStatusFfi, CoreFacade, ItemDetail, ItemSummary, ItemsFilter, Page};
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
/// rebuilt from it afterwards — same as the Qt PoC does.
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
