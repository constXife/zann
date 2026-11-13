//! The vault on this machine through the canonical native local service.

use zann_client_sqlite::local_vault::open_vault_at_file_location;

use std::sync::Arc;
use zann_client::app::local::LocalVaultService;

pub use zann_client::app::local::StorageSyncState;
use zann_client::app::local::{
    AppStatus, ApplePasswordsImportReport, ApplePasswordsPreflight, BackupExportReport,
    BackupImportOptions, HardwareKey, ItemCreate, ItemDetail, ItemHistoryDetail,
    ItemHistorySummary, ItemSummary, ItemUpdate, ItemsFilter, LocalError, Page, RememberedUnlock,
    Snapshot, SnapshotRestore, StorageLink, StorageSummary, VaultSummary, VerifyReport,
};
use zann_ui_core::ItemCounts;

use super::DatabaseLocation;
use crate::i18n::{t, t_args};

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

/// Why a sync failed, split only where the shell offers a different way out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncFailure {
    /// The server proves a different identity than the one this device
    /// pinned. Retrying cannot help; the only recovery is forgetting it.
    IdentityChanged,
    /// No connection syncs this server storage, so nothing it holds reaches
    /// the server. Connecting to `server_url` again with the same account
    /// takes the storage and its pending changes over.
    Disconnected {
        server_url: Option<String>,
        pending_changes: u64,
    },
    Other(String),
}

impl From<LocalError> for SyncFailure {
    fn from(error: LocalError) -> Self {
        match error {
            LocalError::Sync { kind, .. } if kind == SERVER_IDENTITY_CHANGED => {
                Self::IdentityChanged
            }
            error => Self::Other(error.to_string()),
        }
    }
}

impl std::fmt::Display for SyncFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdentityChanged => f.write_str(&t("errors.server_identity_changed")),
            Self::Disconnected {
                pending_changes: 0, ..
            } => f.write_str(&t("errors.server_disconnected")),
            Self::Disconnected {
                pending_changes, ..
            } => f.write_str(&t_args(
                "errors.server_disconnected_pending",
                &[("count", &pending_changes.to_string())],
            )),
            Self::Other(message) => f.write_str(message),
        }
    }
}

/// The stable code `zann-client` reports for a changed server identity.
const SERVER_IDENTITY_CHANGED: &str = "server_identity_changed";

/// Whether a server syncs the storage, refusing one whose connection is gone
/// before anything contacts a server: its changes would otherwise wait
/// unseen.
fn syncs(facade: &Facade, storage_id: String) -> Result<bool, SyncFailure> {
    let state = facade.storage_sync_state(storage_id)?;
    match state.link {
        StorageLink::Local => Ok(false),
        StorageLink::Connected => Ok(true),
        StorageLink::Disconnected => Err(SyncFailure::Disconnected {
            server_url: state.server_url,
            pending_changes: state.pending_changes,
        }),
    }
}

/// What the sync indicator shows about this storage.
pub fn sync_state(facade: &Facade, storage_id: String) -> Result<StorageSyncState, String> {
    facade
        .storage_sync_state(storage_id)
        .map_err(|err| err.to_string())
}

pub fn sync(facade: &Facade, storage_id: Option<String>) -> Result<(), SyncFailure> {
    if let Some(storage_id) = storage_id.clone() {
        syncs(facade, storage_id)?;
    }
    facade
        .remote_sync(storage_id)
        .map(|_| ())
        .map_err(SyncFailure::from)
}

/// A scheduled sync of the open storage, the one "Sync now" in Settings runs
/// for it, so a refusal names the storage its recovery acts on. `None` for a
/// local storage or a sync that changed nothing; otherwise the first page
/// again, for `query`. A server storage whose connection is gone is refused
/// as [`SyncFailure::Disconnected`].
pub fn sync_and_reload(
    facade: &Facade,
    storage_id: String,
    query: Option<String>,
) -> Result<Option<ItemsPage>, SyncFailure> {
    if !syncs(facade, storage_id.clone())? {
        return Ok(None);
    }
    let outcome = facade.remote_sync(Some(storage_id))?;
    if outcome.changes_committed == 0 {
        return Ok(None);
    }
    items(facade, None, query)
        .map(Some)
        .map_err(SyncFailure::Other)
}

/// The first sync of a newly connected server; the core then moves the
/// still-empty session to that server's personal vault.
pub fn sync_new_server(facade: &Facade, storage_id: String) -> Result<(), String> {
    sync(facade, Some(storage_id)).map_err(|failure| failure.to_string())?;
    facade
        .follow_preferred_storage()
        .map_err(|err| err.to_string())
}

/// Local changes in this storage that no server has confirmed yet.
pub fn pending_change_count(facade: &Facade, storage_id: String) -> Result<u64, String> {
    facade
        .pending_change_count(storage_id)
        .map_err(|err| err.to_string())
}

/// Forgets the server that syncs this storage, keeping every local item and
/// pending change. Returns the address it was pinned to, so the user can
/// connect there again.
pub fn forget_server(facade: &Facade, storage_id: String) -> Result<Option<String>, String> {
    facade
        .forget_server(storage_id)
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
        .enroll_hardware_key(label, &|| {})
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
            .find(|vault| vault.kind == zann_core::VaultKind::Personal)
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
