//! Synchronous local vault port for native composition roots.

use super::*;

/// Metadata-only durable sync notifications, delivered outside the async runtime
/// and after releasing selection locks. Consumers may read the committed cache.
pub type LocalSyncObserver = dyn Fn(crate::app::SyncProgress) + Send + Sync;

pub trait LocalVaultService: Send + Sync {
    fn passkey_query(
        &self,
        request: PasskeyRequest,
        sink: &mut dyn FnMut(PasskeyMatches) -> LocalResult<()>,
    ) -> LocalResult<()>;
    fn passkey_ceremony(
        &self,
        request: PasskeyRequest,
        scope: BrowserScope,
        selected: Option<String>,
        sink: &mut dyn FnMut(PasskeyResponse) -> LocalResult<()>,
    ) -> LocalResult<()>;

    /// Sink runs under the context read lease: lock/selection cannot complete
    /// before a bounded IPC response has finished or failed.
    fn browser_site_icons(
        &self,
        scope: BrowserScope,
        captures: std::collections::BTreeMap<String, Option<String>>,
        sink: &mut dyn FnMut(std::collections::BTreeMap<String, String>) -> LocalResult<()>,
    ) -> LocalResult<()>;
    fn browser_query(
        &self,
        context: BrowserContext,
        cursor: Option<BrowserCursor>,
        sink: &mut dyn FnMut(BrowserMatches) -> LocalResult<()>,
    ) -> LocalResult<()>;
    /// Only a matching, current, non-deleted login reaches this trusted sink.
    /// A daemon selects one secret field; the payload is never a wire DTO.
    fn browser_fill(
        &self,
        context: BrowserContext,
        item_id: String,
        sink: &mut dyn FnMut(&zann_core::EncryptedPayload) -> LocalResult<()>,
    ) -> LocalResult<()>;
    /// Create only a typed login in the exact selection observed by the popup.
    fn browser_save(
        &self,
        context: BrowserContext,
        scope: BrowserScope,
        login: CapturedLogin,
        sink: &mut dyn FnMut(String) -> LocalResult<()>,
    ) -> LocalResult<()>;
    #[cfg(debug_assertions)]
    fn debug_create_kv_item(&self, path: String, key: String, value: String)
        -> LocalResult<String>;

    fn core_info(&self) -> String;
    fn change_unlock_password(&self, current: String, replacement: String) -> LocalResult<()>;
    fn activate_connected_account(&self) -> LocalResult<bool>;
    fn enroll_account_key(&self, password: String) -> LocalResult<VaultStatus>;
    fn revoke_account_passkey(
        &self,
        credential_id: String,
        provider: std::sync::Arc<dyn crate::account_access::AccountCeremonyProvider>,
    ) -> LocalResult<zann_core::api::account_access::SecurityReceipt>;
    fn acknowledge_account_recovery(&self) -> LocalResult<()>;
    fn complete_account_passkey_login(
        &self,
        bootstrap: crate::session::PasskeyVaultBootstrap,
    ) -> LocalResult<VaultStatus>;
    fn prepare_server_recovery_code(&self) -> LocalResult<crate::app::AccountRecoveryCode>;
    fn activate_server_recovery_code(
        &self,
        candidate: &crate::app::AccountRecoveryCode,
        confirmation: String,
        disable_password: bool,
        provider: std::sync::Arc<dyn crate::account_access::AccountCeremonyProvider>,
    ) -> LocalResult<zann_core::api::account_access::SecurityReceipt>;
    fn account_security(&self) -> LocalResult<zann_core::api::account_access::AccountSecurity>;
    fn enroll_account_passkey(
        &self,
        name: String,
        mode: zann_core::api::account_access::PasskeyMode,
        authorization: crate::app::PasskeyEnrollmentAuthorization,
        provider: std::sync::Arc<dyn crate::account_access::AccountCeremonyProvider>,
    ) -> LocalResult<zann_core::api::account_access::SecurityReceipt>;
    fn unlock(&self, password: String) -> LocalResult<VaultStatus>;
    fn remembered_unlock(&self) -> LocalResult<RememberedUnlock>;
    fn unlock_remembered(&self) -> LocalResult<VaultStatus>;
    fn hardware_key_present(&self) -> LocalResult<bool>;
    fn idle_unlock_key_present(&self) -> LocalResult<bool>;
    /// Reports completion of Touch 1 before blocking for Touch 2.
    fn enroll_hardware_key(
        &self,
        label: String,
        on_credential_created: &dyn Fn(),
    ) -> LocalResult<HardwareKey>;
    fn remove_hardware_key(&self, credential_id: String) -> LocalResult<()>;
    fn remember_with_keystore(&self) -> LocalResult<()>;
    fn forget_remembered(&self) -> LocalResult<()>;
    /// Forgets the master key and cancels item reads and remote syncs in flight.
    fn lock(&self) -> LocalResult<VaultStatus>;
    fn vault_status(&self) -> LocalResult<VaultStatus>;
    fn current_vault_id(&self) -> Option<String>;
    fn list_vaults(&self) -> LocalResult<Vec<VaultSummary>>;
    fn set_current_vault(&self, id: String) -> LocalResult<VaultStatus>;
    fn items_list(&self, filter: ItemsFilter, page: Page) -> LocalResult<ItemPage>;
    fn item_get(&self, id: String) -> LocalResult<ItemDetail>;
    /// Reads a typed payload for local presentation without a JSON round trip.
    /// Cancellation drops pending reads; context changes refuse stale results.
    fn item_read(
        &self,
        id: String,
        operation: SessionOperation,
    ) -> LocalResult<zann_core::ItemDetail>;
    fn item_create(&self, create: ItemCreate) -> LocalResult<ItemDetail>;
    fn item_update(&self, id: String, update: ItemUpdate) -> LocalResult<ItemDetail>;
    fn item_history_list(&self, id: String, limit: u32) -> LocalResult<Vec<ItemHistorySummary>>;
    fn item_history_get(&self, id: String, version: i64) -> LocalResult<ItemHistoryDetail>;
    fn item_history_restore(&self, id: String, version: i64) -> LocalResult<ItemDetail>;
    /// Import exactly one explicitly identified backup storage into the selected destination.
    /// Source UUID belongs to the file; destination UUID belongs to this client root.
    fn backup_import_file(
        &self,
        path: String,
        source_storage_id: String,
        options: BackupImportOptions,
    ) -> LocalResult<BackupImportReport>;
    fn apple_passwords_preflight_file(&self, path: String) -> LocalResult<ApplePasswordsPreflight>;
    fn apple_passwords_import_file(
        &self,
        path: String,
        options: BackupImportOptions,
    ) -> LocalResult<ApplePasswordsImportReport>;
    fn passkey_targets(&self) -> LocalResult<Vec<PasskeyTargetSummary>>;
    fn passkey_preflight_file(
        &self,
        path: String,
        format: PasskeyExchangeFormat,
    ) -> LocalResult<PasskeyImportPreview>;
    fn passkey_import_file(
        &self,
        path: String,
        format: PasskeyExchangeFormat,
        target: PasskeyTarget,
        operation: SessionOperation,
    ) -> LocalResult<PasskeyImportReport>;
    fn passkey_export_cxf(
        &self,
        path: String,
        target: PasskeyTarget,
        authorization: ExportAuthorization,
    ) -> LocalResult<BackupExportReport>;
    fn backup_capabilities(&self) -> LocalResult<BackupCapabilities>;
    fn backup_begin(&self, operation: SessionOperation) -> LocalResult<BackupHandle>;
    fn backup_add_recipient(
        &self,
        handle: BackupHandle,
        recipient: BackupRecipient,
    ) -> LocalResult<BackupRecipientSummary>;
    fn backup_export_encrypted(
        &self,
        path: String,
        handle: BackupHandle,
    ) -> LocalResult<BackupExportReport>;
    fn backup_encrypted_recipients(&self, path: String)
        -> LocalResult<Vec<BackupRecipientSummary>>;
    fn backup_open_encrypted(
        &self,
        path: String,
        slot: u32,
        recipient: BackupRecipient,
        operation: SessionOperation,
    ) -> LocalResult<BackupHandle>;
    fn backup_inspect_encrypted(&self, handle: BackupHandle) -> LocalResult<BackupInspection>;
    fn backup_import_encrypted(
        &self,
        handle: BackupHandle,
        source_storage_id: String,
        options: BackupImportOptions,
    ) -> LocalResult<BackupImportReport>;
    fn backup_cancel(&self, handle: BackupHandle) -> LocalResult<()>;
    fn export_security(&self) -> LocalResult<ExportSecurity>;
    fn authorize_export(
        &self,
        proof: ExportStepUp,
        operation: SessionOperation,
    ) -> LocalResult<ExportAuthorization>;
    fn set_export_policy(
        &self,
        policy: ExportPolicy,
        authorization: ExportAuthorization,
    ) -> LocalResult<()>;
    fn backup_export_file(
        &self,
        path: String,
        authorization: ExportAuthorization,
    ) -> LocalResult<BackupExportReport>;
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
    /// Requires an unlocked session and verifies the target's cached vault keys,
    /// and chooses its preferred vault atomically; refusal preserves selection.
    fn set_current_storage(&self, id: String) -> LocalResult<()>;
    /// The selected server replica; an empty pre-sync session has none.
    fn current_storage_id(&self) -> Option<String>;
    fn app_status(&self) -> LocalResult<AppStatus>;
    fn setup_accounts(&self) -> LocalResult<Vec<SetupAccount>>;
    fn prepare_local_recovery(&self, scope: RecoveryScope) -> LocalResult<RecoveryPreview>;
    fn cancel_local_recovery(&self, id: String) -> LocalResult<()>;
    fn confirm_local_recovery(
        &self,
        id: String,
        discard_unsent: bool,
    ) -> LocalResult<RecoveryOutcome>;
    fn initialize_master_password(&self, password: String) -> LocalResult<VaultStatus>;
    fn remote_sync(
        &self,
        storage_id: Option<String>,
        progress: Option<&LocalSyncObserver>,
    ) -> LocalResult<LocalSyncOutcome>;
    fn sync_reset(&self, storage_id: Option<String>) -> LocalResult<()>;
    /// Whether a server connection syncs this storage (none does after
    /// [`Self::forget_server`] until the user connects again), with what a
    /// client shows about its sync.
    fn storage_sync_state(&self, storage_id: String) -> LocalResult<StorageSyncState>;
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
