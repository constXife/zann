//! Local application port projection; domain implementations live in focused modules.
use super::*;

impl LocalVaultService for LocalVault {
    fn passkey_targets(&self) -> LocalResult<Vec<PasskeyTargetSummary>> {
        LocalVault::passkey_targets(self)
    }
    fn passkey_preflight_file(
        &self,
        path: String,
        format: PasskeyExchangeFormat,
    ) -> LocalResult<PasskeyImportPreview> {
        LocalVault::passkey_preflight_file(self, path, format)
    }
    fn passkey_import_file(
        &self,
        path: String,
        format: PasskeyExchangeFormat,
        target: PasskeyTarget,
        operation: SessionOperation,
    ) -> LocalResult<PasskeyImportReport> {
        LocalVault::passkey_import_file(self, path, format, target, operation)
    }
    fn passkey_export_cxf(
        &self,
        path: String,
        target: PasskeyTarget,
        authorization: ExportAuthorization,
    ) -> LocalResult<BackupExportReport> {
        LocalVault::passkey_export_cxf(self, path, target, authorization)
    }

    fn backup_capabilities(&self) -> LocalResult<BackupCapabilities> {
        LocalVault::backup_capabilities(self)
    }
    fn browser_query(
        &self,
        context: BrowserContext,
        cursor: Option<BrowserCursor>,
        sink: &mut dyn FnMut(BrowserMatches) -> LocalResult<()>,
    ) -> LocalResult<()> {
        LocalVault::browser_query(self, context, cursor, sink)
    }
    fn browser_save(
        &self,
        context: BrowserContext,
        scope: BrowserScope,
        login: CapturedLogin,
        sink: &mut dyn FnMut(String) -> LocalResult<()>,
    ) -> LocalResult<()> {
        LocalVault::browser_save(self, context, scope, login, sink)
    }
    fn browser_fill(
        &self,
        context: BrowserContext,
        item_id: String,
        sink: &mut dyn FnMut(&EncryptedPayload) -> LocalResult<()>,
    ) -> LocalResult<()> {
        LocalVault::browser_fill(self, context, item_id, sink)
    }
    #[cfg(debug_assertions)]
    fn debug_create_kv_item(
        &self,
        path: String,
        key: String,
        value: String,
    ) -> LocalResult<String> {
        LocalVault::debug_create_kv_item(self, path, key, value)
    }

    fn core_info(&self) -> String {
        LocalVault::core_info(self)
    }
    fn change_unlock_password(&self, current: String, replacement: String) -> LocalResult<()> {
        LocalVault::change_unlock_password(self, current, replacement)
    }
    fn activate_connected_account(&self) -> LocalResult<bool> {
        LocalVault::activate_connected_account(self)
    }
    fn enroll_account_key(&self, password: String) -> LocalResult<VaultStatus> {
        LocalVault::enroll_account_key(self, password)
    }
    fn unlock(&self, password: String) -> LocalResult<VaultStatus> {
        LocalVault::unlock(self, password)
    }
    fn remembered_unlock(&self) -> LocalResult<RememberedUnlock> {
        LocalVault::remembered_unlock(self)
    }
    fn unlock_remembered(&self) -> LocalResult<VaultStatus> {
        LocalVault::unlock_remembered(self)
    }
    fn idle_unlock_key_present(&self) -> LocalResult<bool> {
        LocalVault::idle_unlock_key_present(self)
    }
    fn hardware_key_present(&self) -> LocalResult<bool> {
        LocalVault::hardware_key_present(self)
    }
    fn enroll_hardware_key(
        &self,
        label: String,
        on_credential_created: &dyn Fn(),
    ) -> LocalResult<HardwareKey> {
        LocalVault::enroll_hardware_key(self, label, on_credential_created)
    }
    fn remove_hardware_key(&self, credential_id: String) -> LocalResult<()> {
        LocalVault::remove_hardware_key(self, credential_id)
    }
    fn remember_with_keystore(&self) -> LocalResult<()> {
        LocalVault::remember_with_keystore(self)
    }
    fn forget_remembered(&self) -> LocalResult<()> {
        LocalVault::forget_remembered(self)
    }
    fn lock(&self) -> LocalResult<VaultStatus> {
        LocalVault::lock(self)
    }
    fn vault_status(&self) -> LocalResult<VaultStatus> {
        LocalVault::vault_status(self)
    }
    fn current_vault_id(&self) -> Option<String> {
        LocalVault::current_vault_id(self)
    }
    fn list_vaults(&self) -> LocalResult<Vec<VaultSummary>> {
        LocalVault::list_vaults(self)
    }
    fn set_current_vault(&self, id: String) -> LocalResult<VaultStatus> {
        LocalVault::set_current_vault(self, id)
    }
    fn items_list(&self, filter: ItemsFilter, page: Page) -> LocalResult<ItemPage> {
        LocalVault::items_list(self, filter, page)
    }
    fn item_get(&self, id: String) -> LocalResult<ItemDetail> {
        LocalVault::item_get(self, id)
    }
    fn item_read(
        &self,
        id: String,
        operation: SessionOperation,
    ) -> LocalResult<zann_core::ItemDetail> {
        LocalVault::item_read(self, id, operation)
    }

    fn item_create(&self, create: ItemCreate) -> LocalResult<ItemDetail> {
        LocalVault::item_create(self, create)
    }
    fn item_update(&self, id: String, update: ItemUpdate) -> LocalResult<ItemDetail> {
        LocalVault::item_update(self, id, update)
    }
    fn item_history_list(&self, id: String, limit: u32) -> LocalResult<Vec<ItemHistorySummary>> {
        LocalVault::item_history_list(self, id, limit)
    }
    fn item_history_get(&self, id: String, version: i64) -> LocalResult<ItemHistoryDetail> {
        LocalVault::item_history_get(self, id, version)
    }
    fn item_history_restore(&self, id: String, version: i64) -> LocalResult<ItemDetail> {
        LocalVault::item_history_restore(self, id, version)
    }
    fn backup_import_file(
        &self,
        path: String,
        source_storage_id: String,
        options: BackupImportOptions,
    ) -> LocalResult<BackupImportReport> {
        LocalVault::backup_import_file(self, path, source_storage_id, options)
    }
    fn apple_passwords_preflight_file(&self, path: String) -> LocalResult<ApplePasswordsPreflight> {
        LocalVault::apple_passwords_preflight_file(self, path)
    }
    fn apple_passwords_import_file(
        &self,
        path: String,
        options: BackupImportOptions,
    ) -> LocalResult<ApplePasswordsImportReport> {
        LocalVault::apple_passwords_import_file(self, path, options)
    }
    fn backup_begin(&self, operation: SessionOperation) -> LocalResult<BackupHandle> {
        LocalVault::backup_begin(self, operation)
    }
    fn backup_add_recipient(
        &self,
        handle: BackupHandle,
        recipient: BackupRecipient,
    ) -> LocalResult<BackupRecipientSummary> {
        LocalVault::backup_add_recipient(self, handle, recipient)
    }
    fn backup_export_encrypted(
        &self,
        path: String,
        handle: BackupHandle,
    ) -> LocalResult<BackupExportReport> {
        LocalVault::backup_export_encrypted(self, path, handle)
    }
    fn backup_encrypted_recipients(
        &self,
        path: String,
    ) -> LocalResult<Vec<BackupRecipientSummary>> {
        LocalVault::backup_encrypted_recipients(self, path)
    }
    fn backup_open_encrypted(
        &self,
        path: String,
        slot: u32,
        recipient: BackupRecipient,
        operation: SessionOperation,
    ) -> LocalResult<BackupHandle> {
        LocalVault::backup_open_encrypted(self, path, slot, recipient, operation)
    }
    fn backup_inspect_encrypted(&self, handle: BackupHandle) -> LocalResult<BackupInspection> {
        LocalVault::backup_inspect_encrypted(self, handle)
    }
    fn backup_import_encrypted(
        &self,
        handle: BackupHandle,
        source_storage_id: String,
        options: BackupImportOptions,
    ) -> LocalResult<BackupImportReport> {
        LocalVault::backup_import_encrypted(self, handle, source_storage_id, options)
    }
    fn backup_cancel(&self, handle: BackupHandle) -> LocalResult<()> {
        LocalVault::backup_cancel(self, handle)
    }
    fn export_security(&self) -> LocalResult<ExportSecurity> {
        LocalVault::export_security(self)
    }
    fn authorize_export(
        &self,
        proof: ExportStepUp,
        operation: SessionOperation,
    ) -> LocalResult<ExportAuthorization> {
        LocalVault::authorize_export(self, proof, operation)
    }
    fn set_export_policy(
        &self,
        policy: ExportPolicy,
        authorization: ExportAuthorization,
    ) -> LocalResult<()> {
        LocalVault::set_export_policy(self, policy, authorization)
    }
    fn backup_export_file(
        &self,
        path: String,
        authorization: ExportAuthorization,
    ) -> LocalResult<BackupExportReport> {
        LocalVault::backup_export_file(self, path, authorization)
    }
    fn verify(&self) -> LocalResult<VerifyReport> {
        LocalVault::verify(self)
    }
    fn snapshot_create(&self, retention: Option<Retention>) -> LocalResult<Snapshot> {
        LocalVault::snapshot_create(self, retention)
    }
    fn snapshot_create_if_due(
        &self,
        max_age_hours: u32,
        retention: Option<Retention>,
    ) -> LocalResult<Option<Snapshot>> {
        LocalVault::snapshot_create_if_due(self, max_age_hours, retention)
    }
    fn snapshot_list(&self) -> LocalResult<Vec<Snapshot>> {
        LocalVault::snapshot_list(self)
    }
    fn snapshot_restore_target(&self) -> String {
        LocalVault::snapshot_restore_target(self)
    }
    fn snapshot_restore(&self, path: String) -> LocalResult<SnapshotRestore> {
        LocalVault::snapshot_restore(self, path)
    }
    fn list_storages(&self) -> LocalResult<Vec<StorageSummary>> {
        LocalVault::list_storages(self)
    }
    fn set_current_storage(&self, id: String) -> LocalResult<()> {
        LocalVault::set_current_storage(self, id)
    }

    fn current_storage_id(&self) -> Option<String> {
        LocalVault::current_storage_id(self)
    }
    fn setup_accounts(&self) -> LocalResult<Vec<SetupAccount>> {
        LocalVault::setup_accounts(self)
    }
    fn prepare_local_recovery(&self, scope: RecoveryScope) -> LocalResult<RecoveryPreview> {
        LocalVault::prepare_local_recovery(self, scope)
    }
    fn cancel_local_recovery(&self, id: String) -> LocalResult<()> {
        LocalVault::cancel_local_recovery(self, id)
    }
    fn confirm_local_recovery(
        &self,
        id: String,
        discard_unsent: bool,
    ) -> LocalResult<RecoveryOutcome> {
        LocalVault::confirm_local_recovery(self, id, discard_unsent)
    }
    fn app_status(&self) -> LocalResult<AppStatus> {
        LocalVault::app_status(self)
    }
    fn initialize_master_password(&self, password: String) -> LocalResult<VaultStatus> {
        LocalVault::initialize_master_password(self, password)
    }
    fn remote_sync(
        &self,
        storage_id: Option<String>,
        progress: Option<&LocalSyncObserver>,
    ) -> LocalResult<LocalSyncOutcome> {
        LocalVault::remote_sync(self, storage_id, progress)
    }
    fn sync_reset(&self, storage_id: Option<String>) -> LocalResult<()> {
        LocalVault::sync_reset(self, storage_id)
    }
    fn storage_sync_state(&self, storage_id: String) -> LocalResult<StorageSyncState> {
        LocalVault::storage_sync_state(self, storage_id)
    }
    fn pending_change_count(&self, storage_id: String) -> LocalResult<u64> {
        LocalVault::pending_change_count(self, storage_id)
    }
    fn forget_server(&self, storage_id: String) -> LocalResult<Option<String>> {
        LocalVault::forget_server(self, storage_id)
    }
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
    ) -> LocalResult<()> {
        LocalVault::import_legacy_account(
            self,
            endpoint,
            connection_name,
            profile_name,
            storage_id,
            access_token,
            refresh_token,
            access_expires_at,
        )
    }
    fn remote_client(&self) -> LocalResult<AppClient> {
        self.app_client()
    }
}
