//! Synchronous local vault port for native composition roots.

use super::*;

pub trait LocalVaultService: Send + Sync {
    #[cfg(debug_assertions)]
    fn debug_create_kv_item(&self, path: String, key: String, value: String)
        -> LocalResult<String>;

    fn core_info(&self) -> String;
    fn unlock(&self, password: String) -> LocalResult<VaultStatus>;
    fn remembered_unlock(&self) -> LocalResult<RememberedUnlock>;
    fn unlock_remembered(&self) -> LocalResult<VaultStatus>;
    fn hardware_key_present(&self) -> LocalResult<bool>;
    /// Reports completion of Touch 1 before blocking for Touch 2.
    fn enroll_hardware_key(
        &self,
        label: String,
        on_credential_created: &dyn Fn(),
    ) -> LocalResult<HardwareKey>;
    fn remove_hardware_key(&self, credential_id: String) -> LocalResult<()>;
    fn remember_with_keystore(&self) -> LocalResult<()>;
    fn forget_remembered(&self) -> LocalResult<()>;
    /// Forgets the master key and cancels every `remote_sync` in flight.
    fn lock(&self) -> LocalResult<VaultStatus>;
    fn vault_status(&self) -> LocalResult<VaultStatus>;
    fn current_vault_id(&self) -> Option<String>;
    fn list_vaults(&self) -> LocalResult<Vec<VaultSummary>>;
    fn set_current_vault(&self, id: String) -> LocalResult<VaultStatus>;
    fn items_list(&self, filter: ItemsFilter, page: Page) -> LocalResult<ItemPage>;
    fn item_get(&self, id: String) -> LocalResult<ItemDetail>;
    fn item_create(&self, create: ItemCreate) -> LocalResult<ItemDetail>;
    fn item_update(&self, id: String, update: ItemUpdate) -> LocalResult<ItemDetail>;
    fn item_history_list(&self, id: String, limit: u32) -> LocalResult<Vec<ItemHistorySummary>>;
    fn item_history_get(&self, id: String, version: i64) -> LocalResult<ItemHistoryDetail>;
    fn item_history_restore(&self, id: String, version: i64) -> LocalResult<ItemDetail>;
    fn backup_import_file(
        &self,
        path: String,
        options: BackupImportOptions,
    ) -> LocalResult<BackupImportReport>;
    fn apple_passwords_preflight_file(&self, path: String) -> LocalResult<ApplePasswordsPreflight>;
    fn apple_passwords_import_file(
        &self,
        path: String,
        options: BackupImportOptions,
    ) -> LocalResult<ApplePasswordsImportReport>;
    fn backup_export_file(&self, path: String) -> LocalResult<BackupExportReport>;
    fn verify(&self) -> LocalResult<VerifyReport>;
    fn snapshot_create(&self, retention: Option<Retention>) -> LocalResult<Snapshot>;
    fn snapshot_create_if_due(
        &self,
        max_age_hours: u32,
        retention: Option<Retention>,
    ) -> LocalResult<Option<Snapshot>>;
    fn snapshot_list(&self) -> LocalResult<Vec<Snapshot>>;
    fn snapshot_restore_target(&self) -> String;
    fn snapshot_restore(&self, path: String) -> LocalResult<SnapshotRestore>;
    fn list_storages(&self) -> LocalResult<Vec<StorageSummary>>;
    fn set_current_storage(&self, id: String) -> LocalResult<()>;
    /// Moves an unlocked session whose storage holds no item to the storage
    /// a fresh start would open; a client calls it after a newly connected
    /// server's first sync.
    fn follow_preferred_storage(&self) -> LocalResult<()>;
    fn current_storage_id(&self) -> String;
    fn app_status(&self) -> LocalResult<AppStatus>;
    fn initialize_master_password(&self, password: String) -> LocalResult<VaultStatus>;
    fn remote_sync(&self, storage_id: Option<String>) -> LocalResult<LocalSyncOutcome>;
    fn sync_reset(&self, storage_id: Option<String>) -> LocalResult<()>;
    /// Local changes in this storage that no server has confirmed yet.
    fn pending_change_count(&self, storage_id: String) -> LocalResult<u64>;
    /// Forgets the server connection that syncs this storage, with its pinned
    /// identity and stored credentials, without contacting the server: the
    /// recovery from a server whose identity changed. The local projection,
    /// pending changes included, stays on this device. Returns the forgotten
    /// address, or `None` when no connection syncs this storage.
    fn forget_server(&self, storage_id: String) -> LocalResult<Option<String>>;
    #[allow(clippy::too_many_arguments)]
    fn import_legacy_account(
        &self,
        endpoint: String,
        connection_name: String,
        profile_name: String,
        storage_id: Option<String>,
        access_token: String,
        refresh_token: String,
        access_expires_at: Option<String>,
    ) -> LocalResult<()>;
    /// The remote application facade bound to this vault's client root and
    /// sync store, so login, sync and logout share one composition.
    fn remote_client(&self) -> LocalResult<crate::app::AppClient>;
}
