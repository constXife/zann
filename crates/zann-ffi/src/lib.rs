use std::path::Path;
use std::sync::Arc;
use zann_client::app::local::LocalVaultService;
use zann_client_sqlite::local_vault as native;

mod records;
pub use records::*;
mod sync_progress;
pub use sync_progress::*;
mod auto_sync;
pub use auto_sync::*;
mod conversions;
mod session;
pub use session::*;
mod browser;
mod item_detail;
mod item_editor;
pub use browser::*;
pub use item_detail::*;
pub use item_editor::*;
mod presentation;
pub use presentation::*;
mod catalogue;
pub use catalogue::*;
mod connect_flow;
pub use connect_flow::*;
mod generator;
pub use generator::*;
mod platform;
pub use platform::*;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("browser integration: {message}")]
    Browser {
        kind: BrowserErrorKindFfi,
        message: String,
    },
    #[error("vault is locked")]
    Locked,
    #[error("operation cancelled")]
    Cancelled,
    #[error("operation deadline exceeded")]
    DeadlineExceeded,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("service error: {0}")]
    Service(String),
    #[error("unimplemented: {0}")]
    Unimplemented(String),
    #[error("unlock {kind}: {message}")]
    Unlock { kind: String, message: String },
    #[error("sync {kind}: {message}")]
    Sync { kind: String, message: String },
    #[error("session {kind:?}: {message}")]
    Session {
        kind: SessionErrorKindFfi,
        message: String,
    },
    #[error("oidc {kind:?}: {message}")]
    Oidc {
        kind: OidcErrorKindFfi,
        message: String,
    },
    #[error("draft {kind:?}: {message}")]
    Draft {
        kind: DraftErrorKindFfi,
        translation_key: String,
        message: String,
    },
    #[error("generator {kind:?}: {message}")]
    Generator {
        kind: GeneratorErrorKindFfi,
        translation_key: Option<String>,
        message: String,
    },
}

pub type CoreResult<T> = Result<T, CoreError>;

impl From<zann_client::app::local::LocalError> for CoreError {
    fn from(error: zann_client::app::local::LocalError) -> Self {
        use zann_client::app::local::LocalError;
        match error {
            LocalError::Backup { kind, message, .. } => Self::Service(format!("{kind}: {message}")),
            LocalError::BrowserPolicy(_) | LocalError::BrowserDelivery(_) => {
                Self::Service(error.to_string())
            }
            LocalError::Locked => Self::Locked,
            LocalError::Cancelled => Self::Cancelled,
            LocalError::DeadlineExceeded => Self::DeadlineExceeded,
            LocalError::ItemRead(source) => Self::Service(source.to_string()),
            LocalError::InvalidPayload(source) => Self::InvalidArgument(source.to_string()),
            LocalError::InvalidArgument(message) => Self::InvalidArgument(message),
            LocalError::Service(message) => Self::Service(message),
            LocalError::Unimplemented(message) => Self::Unimplemented(message),
            LocalError::Unlock { kind, message, .. } => Self::Unlock { kind, message },
            LocalError::Sync { kind, message } => Self::Sync { kind, message },
        }
    }
}
/// Delivered between Touch 1 and Touch 2 on the blocking caller thread.
#[uniffi::export(callback_interface)]
pub trait HardwareEnrollmentProgress: Send + Sync {
    fn credential_created(&self);
}

#[derive(uniffi::Object)]
pub struct CoreFacade {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    daemon: std::sync::Mutex<Option<zann_daemon::Daemon>>,
    inner: Arc<native::LocalVault>,
}
#[uniffi::export]
impl CoreFacade {
    pub fn core_info(&self) -> String {
        self.inner.core_info()
    }
    pub fn unlock(&self, password: String) -> CoreResult<VaultStatus> {
        self.inner
            .unlock(password)
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn remembered_unlock(&self) -> CoreResult<RememberedUnlockFfi> {
        self.inner
            .remembered_unlock()
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn unlock_remembered(&self) -> CoreResult<VaultStatus> {
        self.inner
            .unlock_remembered()
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn hardware_key_present(&self) -> CoreResult<bool> {
        self.inner.hardware_key_present().map_err(Into::into)
    }
    pub fn enroll_hardware_key(
        &self,
        label: String,
        progress: Box<dyn HardwareEnrollmentProgress>,
    ) -> CoreResult<HardwareKeyFfi> {
        self.inner
            .enroll_hardware_key(label, &|| progress.credential_created())
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn remove_hardware_key(&self, credential_id: String) -> CoreResult<()> {
        self.inner
            .remove_hardware_key(credential_id)
            .map_err(Into::into)
    }
    pub fn remember_with_keystore(&self) -> CoreResult<()> {
        self.inner.remember_with_keystore().map_err(Into::into)
    }
    pub fn forget_remembered(&self) -> CoreResult<()> {
        self.inner.forget_remembered().map_err(Into::into)
    }
    pub fn lock(&self) -> CoreResult<VaultStatus> {
        self.inner
            .lock()
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn vault_status(&self) -> CoreResult<VaultStatus> {
        self.inner
            .vault_status()
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn current_vault_id(&self) -> Option<String> {
        self.inner.current_vault_id()
    }
    pub fn list_vaults(&self) -> CoreResult<Vec<VaultSummaryFfi>> {
        self.inner
            .list_vaults()
            .map(|value| value.into_iter().map(|value| value.into()).collect())
            .map_err(Into::into)
    }
    pub fn set_current_vault(&self, id: String) -> CoreResult<VaultStatus> {
        self.inner
            .set_current_vault(id)
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn items_list(&self, filter: ItemsFilter, page: Page) -> CoreResult<ItemPage> {
        self.inner
            .items_list(filter.into(), page.into())
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn item_get(&self, id: String) -> CoreResult<ItemDetail> {
        self.inner
            .item_get(id)
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn item_create(&self, create: ItemCreate) -> CoreResult<ItemDetail> {
        self.inner
            .item_create(create.into())
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn item_update(&self, id: String, update: ItemUpdate) -> CoreResult<ItemDetail> {
        self.inner
            .item_update(id, update.into())
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn item_history_list(
        &self,
        id: String,
        limit: u32,
    ) -> CoreResult<Vec<ItemHistorySummaryFfi>> {
        self.inner
            .item_history_list(id, limit)
            .map(|value| value.into_iter().map(|value| value.into()).collect())
            .map_err(Into::into)
    }
    pub fn item_history_get(&self, id: String, version: i64) -> CoreResult<ItemHistoryDetailFfi> {
        self.inner
            .item_history_get(id, version)
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn item_history_restore(&self, id: String, version: i64) -> CoreResult<ItemDetail> {
        self.inner
            .item_history_restore(id, version)
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn backup_import_file(
        &self,
        path: String,
        options: BackupImportOptions,
    ) -> CoreResult<BackupImportReport> {
        self.inner
            .backup_import_file(path, options.into())
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn apple_passwords_preflight_file(
        &self,
        path: String,
    ) -> CoreResult<ApplePasswordsPreflightFfi> {
        self.inner
            .apple_passwords_preflight_file(path)
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn apple_passwords_import_file(
        &self,
        path: String,
        options: BackupImportOptions,
    ) -> CoreResult<ApplePasswordsImportReportFfi> {
        self.inner
            .apple_passwords_import_file(path, options.into())
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn backup_export_file(&self, path: String) -> CoreResult<BackupExportReport> {
        self.inner
            .backup_export_file(path)
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn verify(&self) -> CoreResult<VerifyReportFfi> {
        self.inner
            .verify()
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn snapshot_create(&self, retention: Option<RetentionFfi>) -> CoreResult<SnapshotFfi> {
        self.inner
            .snapshot_create(retention.map(|value| value.into()))
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn snapshot_create_if_due(
        &self,
        max_age_hours: u32,
        retention: Option<RetentionFfi>,
    ) -> CoreResult<Option<SnapshotFfi>> {
        self.inner
            .snapshot_create_if_due(max_age_hours, retention.map(|value| value.into()))
            .map(|value| value.map(|value| value.into()))
            .map_err(Into::into)
    }
    pub fn snapshot_list(&self) -> CoreResult<Vec<SnapshotFfi>> {
        self.inner
            .snapshot_list()
            .map(|value| value.into_iter().map(|value| value.into()).collect())
            .map_err(Into::into)
    }
    pub fn snapshot_restore_target(&self) -> String {
        self.inner.snapshot_restore_target()
    }
    pub fn snapshot_restore(&self, path: String) -> CoreResult<SnapshotRestoreFfi> {
        self.inner
            .snapshot_restore(path)
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn list_storages(&self) -> CoreResult<Vec<StorageSummaryFfi>> {
        self.inner
            .list_storages()
            .map(|value| value.into_iter().map(|value| value.into()).collect())
            .map_err(Into::into)
    }
    pub fn set_current_storage(&self, id: String) -> CoreResult<()> {
        self.inner.set_current_storage(id).map_err(Into::into)
    }
    pub fn current_storage_id(&self) -> Option<String> {
        self.inner.current_storage_id()
    }
    pub fn app_status(&self) -> CoreResult<AppStatusFfi> {
        self.inner
            .app_status()
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn initialize_master_password(&self, password: String) -> CoreResult<VaultStatus> {
        self.inner
            .initialize_master_password(password)
            .map(|value| value.into())
            .map_err(Into::into)
    }
    pub fn sync_reset(&self, storage_id: Option<String>) -> CoreResult<()> {
        self.inner.sync_reset(storage_id).map_err(Into::into)
    }
    /// Whether a server connection syncs this storage (none does after
    /// `forget_server` until the user connects again), with what a client
    /// shows about its sync.
    pub fn storage_sync_state(&self, storage_id: String) -> CoreResult<StorageSyncStateFfi> {
        self.inner
            .storage_sync_state(storage_id)
            .map(Into::into)
            .map_err(Into::into)
    }
    /// Local changes in this storage that no server has confirmed yet.
    pub fn pending_change_count(&self, storage_id: String) -> CoreResult<u64> {
        self.inner
            .pending_change_count(storage_id)
            .map_err(Into::into)
    }
    /// Forgets the server connection that syncs this storage, with its pinned
    /// identity and stored credentials, without contacting the server: the
    /// recovery from a sync refused as `server_identity_changed`. Local items
    /// and pending changes stay. Returns the forgotten address, or `None`
    /// when no connection syncs this storage.
    pub fn forget_server(&self, storage_id: String) -> CoreResult<Option<String>> {
        self.inner.forget_server(storage_id).map_err(Into::into)
    }
    pub fn remote_session(&self) -> CoreResult<Arc<RemoteSession>> {
        RemoteSession::new(self.inner.remote_client()?).map(Arc::new)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn import_legacy_account(
        &self,
        endpoint: String,
        connection_name: String,
        profile_name: String,
        storage_id: Option<String>,
        access_token: String,
        refresh_token: String,
        access_expires_at: Option<String>,
    ) -> CoreResult<()> {
        self.inner
            .import_legacy_account(
                endpoint,
                connection_name,
                profile_name,
                storage_id,
                access_token,
                refresh_token,
                access_expires_at,
            )
            .map_err(Into::into)
    }
}

impl CoreFacade {
    #[cfg(debug_assertions)]
    pub fn debug_create_kv_item(
        &self,
        path: String,
        key: String,
        value: String,
    ) -> CoreResult<String> {
        self.inner
            .debug_create_kv_item(path, key, value)
            .map_err(Into::into)
    }
}
/// Opens the local vault at `db_path`, an absolute native path such as a
/// file inside the app container, with the shell's own OS secret storage.
/// The parent directory is created owner-only if missing.
#[uniffi::export]
pub fn create_core(
    db_path: String,
    keystore: Arc<dyn PlatformKeystore>,
    secret_store: Arc<dyn PlatformSecretStore>,
) -> CoreResult<Arc<CoreFacade>> {
    let ports = native::LocalVaultPorts::with_platform_secrets(
        platform::keystore(keystore),
        platform::secret_store(secret_store),
    );
    let inner = native::open_vault_at_path(Path::new(&db_path), ports)?;
    Ok(Arc::new(CoreFacade {
        inner,
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        daemon: std::sync::Mutex::new(None),
    }))
}
uniffi::setup_scaffolding!("zann_ffi");

#[cfg(feature = "test-support")]
mod test_support;
