//! The vault on this machine through the canonical native local service.

use zann_client_sqlite::local_vault::open_vault_at_file_location;

use std::sync::Arc;
use zann_client::app::local::LocalVaultService;

use zann_client::app::local::{
    AppStatus, ApplePasswordsImportReport, ApplePasswordsPreflight, BackupExportReport,
    BackupImportOptions, HardwareKey, ItemCreate, ItemDetail, ItemHistoryDetail,
    ItemHistorySummary, ItemSummary, ItemUpdate, ItemsFilter, Page, RememberedUnlock, Snapshot,
    SnapshotRestore, StorageSummary, VaultSummary, VerifyReport,
};
use zann_ui_core::ItemCounts;

use super::DatabaseLocation;

/// How many items a single `items_list` call pages in.
pub const PAGE_LIMIT: u32 = 200;

/// How stale the newest snapshot may get before start-up takes another.
const SNAPSHOT_MAX_AGE_HOURS: u32 = 24;

pub type Facade = Arc<dyn LocalVaultService>;

/// A page of items plus the totals the nav bar badges need.
#[derive(Debug, Clone)]
pub struct ItemsPage {
    pub items: Vec<ItemSummary>,
    pub next_cursor: Option<String>,
    pub total: u64,
    pub counts: ItemCounts,
}

/// Vault choices for the current storage and the facade's active selection.
#[derive(Debug, Clone)]
pub struct VaultContext {
    pub vaults: Vec<VaultSummary>,
    pub current_vault_id: Option<String>,
}

/// Opens an explicitly resolved database and reports what the app should show first.
pub fn open_at(location: &DatabaseLocation) -> Result<(Facade, AppStatus), String> {
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
    open_vault_at_file_location(location.file_location())
        .map(|service| service as Arc<dyn LocalVaultService>)
        .map_err(|err| err.to_string())
}

pub fn initialize_master_password(facade: &Facade, password: String) -> Result<(), String> {
    facade
        .initialize_master_password(password)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

pub fn unlock(facade: &Facade, password: String) -> Result<(), String> {
    facade
        .unlock(password)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

pub fn sync(facade: &Facade, storage_id: Option<String>) -> Result<(), String> {
    facade
        .remote_sync(storage_id)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

pub fn storages(facade: &Facade) -> Result<Vec<StorageSummary>, String> {
    facade.list_storages().map_err(|err| err.to_string())
}

pub fn current_storage_id(facade: &Facade) -> String {
    facade.current_storage_id()
}

pub fn items(
    facade: &Facade,
    cursor: Option<String>,
    query: Option<String>,
) -> Result<ItemsPage, String> {
    let page = facade
        .items_list(
            ItemsFilter {
                query,
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
        counts: ItemCounts {
            all: page.counts.all,
            trash: page.counts.trash,
            by_type: page
                .counts
                .by_type
                .into_iter()
                .map(|entry| (entry.type_id, entry.count))
                .collect(),
        },
        items: page.items,
        next_cursor: page.next_cursor,
        total: page.total_count,
    })
}

pub fn vault_context(facade: &Facade) -> Result<VaultContext, String> {
    Ok(VaultContext {
        vaults: facade.list_vaults().map_err(|err| err.to_string())?,
        current_vault_id: facade.current_vault_id(),
    })
}

/// Change the facade selection and load the first page as one UI operation.
/// If loading fails, restore the old selection so the selector and list cannot
/// silently point at different vaults.
pub fn switch_vault(facade: &Facade, vault_id: String) -> Result<ItemsPage, String> {
    let previous = facade.current_vault_id();
    facade
        .set_current_vault(vault_id)
        .map_err(|err| err.to_string())?;
    match items(facade, None, None) {
        Ok(page) => Ok(page),
        Err(err) => {
            if let Some(previous) = previous {
                let _ = facade.set_current_vault(previous);
            }
            Err(err)
        }
    }
}

pub fn item_get(facade: &Facade, id: String) -> Result<ItemDetail, String> {
    facade.item_get(id).map_err(|err| err.to_string())
}

pub fn item_create(facade: &Facade, item: ItemCreate) -> Result<ItemDetail, String> {
    facade.item_create(item).map_err(|err| err.to_string())
}

pub fn item_update(facade: &Facade, id: String, item: ItemUpdate) -> Result<ItemDetail, String> {
    facade.item_update(id, item).map_err(|err| err.to_string())
}

// -- Remembered unlock -------------------------------------------------------
//
// The policy lives in `zann-keystore` behind `zann-ffi`; this app only asks.
// Enrolment and unlocking wait on a physical touch, so both belong on a worker
// thread like everything else here.

pub fn remembered_unlock(facade: &Facade) -> Result<RememberedUnlock, String> {
    facade.remembered_unlock().map_err(|err| err.to_string())
}

/// One touch when the source is a hardware key.
pub fn unlock_remembered(facade: &Facade) -> Result<(), String> {
    facade
        .unlock_remembered()
        .map(|_| ())
        .map_err(|err| err.to_string())
}

pub fn item_history(facade: &Facade, id: String) -> Result<Vec<ItemHistorySummary>, String> {
    facade
        .item_history_list(id, 20)
        .map_err(|err| err.to_string())
}

pub fn item_history_get(
    facade: &Facade,
    id: String,
    version: i64,
) -> Result<ItemHistoryDetail, String> {
    facade
        .item_history_get(id, version)
        .map_err(|err| err.to_string())
}

pub fn item_history_restore(
    facade: &Facade,
    id: String,
    version: i64,
) -> Result<ItemDetail, String> {
    facade
        .item_history_restore(id, version)
        .map_err(|err| err.to_string())
}

/// Silent — no touch. Safe to call while the user is doing something else.
pub fn hardware_key_present(facade: &Facade) -> Result<bool, String> {
    facade.hardware_key_present().map_err(|err| err.to_string())
}

/// Two touches: create the credential, then prove it yields a secret.
pub fn enroll_hardware_key(facade: &Facade, label: String) -> Result<HardwareKey, String> {
    facade
        .enroll_hardware_key(label)
        .map_err(|err| err.to_string())
}

pub fn remove_hardware_key(facade: &Facade, credential_id: String) -> Result<(), String> {
    facade
        .remove_hardware_key(credential_id)
        .map_err(|err| err.to_string())
}

/// Writes a plain backup of every local vault. The facade picks the path,
/// because this client has no file picker of its own — see
/// docs/adr/0002-client-strategy.md on why being able to leave comes first.
pub fn export_backup(facade: &Facade) -> Result<BackupExportReport, String> {
    facade
        .backup_export_file(String::new())
        .map_err(|err| err.to_string())
}

pub fn apple_passwords_preflight(
    facade: &Facade,
    path: String,
) -> Result<ApplePasswordsPreflight, String> {
    facade
        .apple_passwords_preflight_file(path)
        .map_err(|err| err.to_string())
}

pub fn import_apple_passwords(
    facade: &Facade,
    path: String,
    target_storage_id: String,
) -> Result<ApplePasswordsImportReport, String> {
    let report = facade
        .apple_passwords_import_file(
            path,
            BackupImportOptions {
                target_storage_id: Some(target_storage_id.clone()),
            },
        )
        .map_err(|err| err.to_string())?;

    // The Apple export always belongs to the personal vault. Keep the open
    // session aligned with the destination so closing Settings shows what was
    // just imported instead of the previously active shared vault.
    if facade.current_storage_id() == target_storage_id {
        let personal = facade
            .list_vaults()
            .map_err(|err| err.to_string())?
            .into_iter()
            .find(|vault| vault.kind == "personal")
            .ok_or_else(|| "personal vault not found after import".to_string())?;
        facade
            .set_current_vault(personal.id)
            .map_err(|err| err.to_string())?;
    }
    Ok(report)
}

/// Copy the database aside now, whatever the schedule says.
pub fn snapshot_now(facade: &Facade) -> Result<Snapshot, String> {
    facade.snapshot_create(None).map_err(|err| err.to_string())
}

/// Newest first.
pub fn snapshots(facade: &Facade) -> Result<Vec<Snapshot>, String> {
    facade.snapshot_list().map_err(|err| err.to_string())
}

/// Put a snapshot back. Leaves the vault locked, because the restored database
/// may have been written under a different password.
pub fn restore_snapshot(facade: &Facade, path: String) -> Result<SnapshotRestore, String> {
    facade.snapshot_restore(path).map_err(|err| err.to_string())
}

/// Walk every item and check it is still readable. Needs the vault unlocked.
pub fn verify(facade: &Facade) -> Result<VerifyReport, String> {
    facade.verify().map_err(|err| err.to_string())
}
