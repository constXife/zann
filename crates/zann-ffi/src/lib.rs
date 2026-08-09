use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::runtime::Runtime;
use uuid::Uuid;
use zann_client::state::ClientState;
use zann_core::{ItemCounts, ItemListParams, ItemsService, VaultsService};
use zann_crypto::crypto::SecretKey;
use zann_crypto::secrets::{FieldKind, FieldValue};
use zann_crypto::vault_crypto;
use zann_crypto::EncryptedPayload;
use zann_db::local::{LocalItemRepo, LocalStorage, LocalStorageRepo, LocalVaultRepo};
use zann_db::services::LocalServices;
use zann_db::{connect_sqlite_with_max, migrate_local, SqlitePool};
use zann_keystore::{default_keystore, RememberedUnlock, UnlockError, UnlockSource};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("vault is locked")]
    Locked,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("service error: {0}")]
    Service(String),
    #[error("unimplemented: {0}")]
    Unimplemented(String),
}

pub type CoreResult<T> = Result<T, CoreError>;

/// `BackupError` already carries a stable `kind`; keep it rather than
/// flattening everything into one string, so the UI can still translate.
impl From<zann_app::BackupError> for CoreError {
    fn from(err: zann_app::BackupError) -> Self {
        match err.kind.as_str() {
            "backup_failed" => CoreError::Service(err.message),
            _ => CoreError::Service(format!("{}: {}", err.kind, err.message)),
        }
    }
}

impl From<zann_app::SnapshotError> for CoreError {
    fn from(err: zann_app::SnapshotError) -> Self {
        CoreError::Service(format!("{}: {}", err.kind, err.message))
    }
}

impl From<zann_app::Snapshot> for SnapshotFfi {
    fn from(snapshot: zann_app::Snapshot) -> Self {
        Self {
            path: snapshot.path.display().to_string(),
            identity_path: snapshot
                .identity_path
                .map(|path| path.display().to_string()),
            created_at: snapshot.created_at,
            size_bytes: snapshot.size_bytes,
        }
    }
}

impl From<zann_app::VerifyError> for CoreError {
    fn from(err: zann_app::VerifyError) -> Self {
        CoreError::Service(format!("{}: {}", err.kind, err.message))
    }
}

impl From<zann_app::VerifyReport> for VerifyReportFfi {
    fn from(report: zann_app::VerifyReport) -> Self {
        Self {
            database_ok: report.database_ok,
            vaults_checked: report.vaults_checked,
            vaults_skipped: report.vaults_skipped,
            items_checked: report.items_checked,
            items_ok: report.items_ok,
            problems: report
                .problems
                .into_iter()
                .map(|problem| VerifyProblemFfi {
                    kind: problem.kind,
                    vault_name: problem.vault_name,
                    item_path: problem.item_path,
                    detail: problem.detail,
                })
                .collect(),
        }
    }
}

impl From<RetentionFfi> for zann_app::RetentionPolicy {
    fn from(retention: RetentionFfi) -> Self {
        Self {
            max_count: retention.max_count.map(|count| count as usize),
            max_age_days: retention.max_age_days,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VaultStatus {
    pub unlocked: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VaultSummaryFfi {
    pub id: String,
    pub name: String,
    pub is_default: bool,
    pub item_count: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemsFilter {
    pub query: Option<String>,
    pub include_deleted: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Page {
    pub limit: u32,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemSummary {
    pub id: String,
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub deleted: bool,
}

impl zann_ui_core::ItemLike for ItemSummary {
    fn title(&self) -> &str {
        &self.title
    }

    fn type_id(&self) -> &str {
        &self.type_id
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn is_deleted(&self) -> bool {
        self.deleted
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemCountsFfi {
    pub all: u64,
    pub trash: u64,
    pub by_type: Vec<ItemTypeCount>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemTypeCount {
    pub type_id: String,
    pub count: u64,
}

impl From<&ItemCountsFfi> for zann_ui_core::ItemCounts {
    fn from(counts: &ItemCountsFfi) -> Self {
        Self {
            all: counts.all,
            trash: counts.trash,
            by_type: counts
                .by_type
                .iter()
                .map(|entry| (entry.type_id.clone(), entry.count))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemPage {
    pub items: Vec<ItemSummary>,
    pub next_cursor: Option<String>,
    pub total_count: u64,
    pub counts: ItemCountsFfi,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemDetail {
    pub id: String,
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub payload_json: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemUpdate {
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub payload_json: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct BackupImportOptions {
    /// Storage to import into. `None` — or the string `"local"` — means the
    /// local-only storage. A remote storage is not supported here yet: that
    /// path still needs the token and HTTP machinery that has not moved into
    /// `zann-app`, and it reports `Unimplemented` rather than importing into
    /// the wrong place.
    pub target_storage_id: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct BackupExportReport {
    pub path: String,
    pub storages_count: u64,
    pub vaults_count: u64,
    pub items_count: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct BackupImportReport {
    pub imported_items: u64,
    pub skipped_existing: u64,
    pub skipped_missing_storage: u64,
    pub skipped_missing_vault: u64,
    pub skipped_deleted: u64,
}

/// A point-in-time copy of the vault database. Still encrypted — unlike the
/// plaintext JSON an export produces — so it is only good for going back, not
/// for leaving.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SnapshotFfi {
    pub path: String,
    /// The KDF salt this copy needs to be opened. A database copy without it
    /// cannot be unlocked by any password, so a client offering to restore must
    /// keep the two together.
    pub identity_path: Option<String>,
    /// RFC 3339.
    pub created_at: String,
    pub size_bytes: u64,
}

/// One fault found by [`CoreFacade::verify`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct VerifyProblemFfi {
    /// `database`, `vault_key_unusable`, `checksum_mismatch` or
    /// `decrypt_failed`. Stable identifier for the UI to translate; the detail
    /// text is not.
    pub kind: String,
    pub vault_name: Option<String>,
    pub item_path: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VerifyReportFfi {
    pub database_ok: bool,
    pub vaults_checked: u64,
    pub vaults_skipped: u64,
    pub items_checked: u64,
    pub items_ok: u64,
    pub problems: Vec<VerifyProblemFfi>,
}

/// How many snapshots to keep. `None` on either field disables that limit.
#[derive(Debug, Clone, Copy, uniffi::Record)]
pub struct RetentionFfi {
    pub max_count: Option<u32>,
    pub max_age_days: Option<i64>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct StorageSummaryFfi {
    pub id: String,
    pub name: String,
    pub kind: String, // "local" or "remote"
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AppStatusFfi {
    pub initialized: bool, // master password has been set (vaults exist)
    pub locked: bool,
    pub storages_count: u64,
    pub has_local_vault: bool,
}

/// One enrolled authenticator, as the UI needs to show it. The wrapped master
/// key is deliberately absent: clients list and label keys, they do not handle
/// key material.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HardwareKeyFfi {
    pub label: String,
    pub credential_id: String,
    pub enrolled_at: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RememberedUnlockFfi {
    /// Whether this device can unlock without the master password.
    pub armed: bool,
    /// "keystore" or "hardware_key".
    pub source: String,
    pub hardware_keys: Vec<HardwareKeyFfi>,
    /// Whether hardware keys work on this platform at all.
    pub hardware_supported: bool,
}

#[derive(uniffi::Object)]
pub struct CoreFacade {
    runtime: Runtime,
    pool: SqlitePool,
    storage_id: Mutex<Uuid>,
    vault_id: Mutex<Option<Uuid>>,
    master_key: Mutex<Option<Arc<SecretKey>>>,
    identity: IdentityConfig,
    /// The vault directory. The remembered unlock is persisted there in its own
    /// file, so every client on this machine sees the same enrolments.
    root: PathBuf,
}

impl CoreFacade {
    fn services_with_key<'a>(&'a self, master_key: &'a SecretKey) -> LocalServices<'a> {
        LocalServices::new(&self.pool, master_key)
    }

    fn master_key(&self) -> CoreResult<Arc<SecretKey>> {
        self.master_key
            .lock()
            .expect("lock poisoned")
            .clone()
            .ok_or(CoreError::Locked)
    }

    fn backup_ctx(&self) -> CoreResult<zann_app::BackupCtx> {
        Ok(zann_app::BackupCtx::new(
            self.pool.clone(),
            self.master_key()?,
            self.root.clone(),
        ))
    }

    fn vault_id(&self) -> CoreResult<Uuid> {
        self.vault_id
            .lock()
            .expect("lock poisoned")
            .ok_or(CoreError::Locked)
    }

    fn storage_id(&self) -> Uuid {
        *self.storage_id.lock().expect("lock poisoned")
    }

    fn runtime_block_on<F, T>(&self, future: F) -> CoreResult<T>
    where
        F: std::future::Future<Output = Result<T, zann_core::ServiceError>>,
    {
        self.runtime
            .block_on(future)
            .map_err(|err| CoreError::Service(err.to_string()))
    }

    /// Everything an unlock does once the master key exists, whatever produced
    /// it. Note the vault-key decryption below doubles as the check that the key
    /// is the right one, so a key recovered from a stale wrapped copy fails here
    /// exactly like a wrong password.
    fn finish_unlock(&self, master_key: Arc<SecretKey>) -> CoreResult<VaultStatus> {
        let repo = LocalVaultRepo::new(&self.pool);
        let storage_id = self.storage_id();
        let vaults = self
            .runtime
            .block_on(repo.list_by_storage(storage_id))
            .map_err(|err| CoreError::Service(err.to_string()))?;
        let vault_id = if vaults.is_empty() {
            let services = LocalServices::new(&self.pool, master_key.as_ref());
            let vault = self.runtime_block_on(services.ensure_default_local_personal())?;
            vault.id
        } else {
            let verify = vaults.first().expect("vaults not empty");
            vault_crypto::decrypt_vault_key(master_key.as_ref(), verify.id, &verify.vault_key_enc)
                .map_err(|_| CoreError::InvalidArgument("invalid password".to_string()))?;
            let item_repo = LocalItemRepo::new(&self.pool);
            let mut selected = vaults
                .iter()
                .find(|vault| vault.is_default)
                .map(|vault| (vault.id, 0usize))
                .or_else(|| vaults.first().map(|vault| (vault.id, 0usize)))
                .expect("vaults not empty");
            for vault in &vaults {
                let count = self
                    .runtime
                    .block_on(item_repo.count_by_vault(storage_id, vault.id))
                    .map_err(|err| CoreError::Service(err.to_string()))?;
                if count as usize > selected.1 {
                    selected = (vault.id, count as usize);
                }
            }
            selected.0
        };
        *self.master_key.lock().expect("lock poisoned") = Some(master_key);
        *self.vault_id.lock().expect("lock poisoned") = Some(vault_id);
        Ok(VaultStatus { unlocked: true })
    }

    #[cfg(debug_assertions)]
    pub fn debug_create_kv_item(
        &self,
        path: String,
        key: String,
        value: String,
    ) -> CoreResult<String> {
        let master_key = self.master_key()?;
        let vault_id = self.vault_id()?;
        let services = self.services_with_key(master_key.as_ref());
        let mut payload = EncryptedPayload::new("kv");
        payload.fields.insert(
            "key".to_string(),
            FieldValue {
                kind: FieldKind::Text,
                value: key,
                meta: None,
            },
        );
        payload.fields.insert(
            "value".to_string(),
            FieldValue {
                kind: FieldKind::Text,
                value,
                meta: None,
            },
        );
        let item_id = self.runtime_block_on(services.put_item(
            self.storage_id(),
            vault_id,
            path,
            "kv".to_string(),
            payload,
        ))?;
        Ok(item_id.to_string())
    }
}

#[uniffi::export]
impl CoreFacade {
    pub fn core_info(&self) -> String {
        format!("zann-core {}", env!("CARGO_PKG_VERSION"))
    }

    pub fn unlock(&self, password: String) -> CoreResult<VaultStatus> {
        let master_key = Arc::new(derive_master_key(&password, &self.identity)?);
        self.finish_unlock(master_key)
    }

    // -- Remembered unlock -------------------------------------------------
    //
    // The policy lives in `zann-keystore`; this is the boundary that keeps the
    // master key on this side of it. Clients ask for an unlock, they never see
    // or supply key material.

    pub fn remembered_unlock(&self) -> CoreResult<RememberedUnlockFfi> {
        let remembered = self.load_remembered()?;
        Ok(RememberedUnlockFfi {
            armed: remembered.is_armed(),
            source: match remembered.unlock_source {
                UnlockSource::Keystore => "keystore".to_string(),
                UnlockSource::HardwareKey => "hardware_key".to_string(),
            },
            hardware_keys: remembered
                .hardware_keys
                .iter()
                .map(|entry| HardwareKeyFfi {
                    label: entry.label.clone(),
                    credential_id: entry.credential_id.clone(),
                    enrolled_at: entry.enrolled_at.clone(),
                })
                .collect(),
            hardware_supported: cfg!(any(target_os = "linux", target_os = "macos")),
        })
    }

    /// Unlock using whichever source this device has armed. Blocks on a touch
    /// when that source is a hardware key.
    pub fn unlock_remembered(&self) -> CoreResult<VaultStatus> {
        let remembered = self.load_remembered()?;
        let master_key = match remembered.unlock_source {
            UnlockSource::Keystore => remembered.unlock_with_keystore(default_keystore().as_ref()),
            UnlockSource::HardwareKey => remembered.unlock_with_hardware_key(),
        }
        .map_err(unlock_error)?;
        self.finish_unlock(Arc::new(SecretKey::from_bytes(master_key)))
    }

    /// Whether an enrolled authenticator is connected. Silent: no touch, so
    /// this is safe to poll for auto-lock.
    pub fn hardware_key_present(&self) -> CoreResult<bool> {
        Ok(self.load_remembered()?.connected_hardware_key().is_some())
    }

    /// Enrol the connected authenticator against the open vault. Two touches.
    pub fn enroll_hardware_key(&self, label: String) -> CoreResult<HardwareKeyFfi> {
        let master_key = self.master_key()?;
        let mut remembered = self.load_remembered()?;
        // The policy crate stays clock-free, so the timestamp is stamped here
        // rather than trusted from a caller.
        let entry = remembered
            .enroll_hardware_key(
                master_key.as_bytes(),
                &label,
                chrono::Utc::now().to_rfc3339(),
            )
            .map_err(unlock_error)?;
        remembered.unlock_source = UnlockSource::HardwareKey;
        self.save_remembered(&remembered)?;
        Ok(HardwareKeyFfi {
            label: entry.label,
            credential_id: entry.credential_id,
            enrolled_at: entry.enrolled_at,
        })
    }

    pub fn remove_hardware_key(&self, credential_id: String) -> CoreResult<()> {
        let mut remembered = self.load_remembered()?;
        remembered.remove_hardware_key(&credential_id);
        self.save_remembered(&remembered)
    }

    /// Remember the unlock in the OS credential store instead.
    pub fn remember_with_keystore(&self) -> CoreResult<()> {
        let master_key = self.master_key()?;
        let mut remembered = self.load_remembered()?;
        remembered
            .remember_with_keystore(default_keystore().as_ref(), master_key.as_bytes())
            .map_err(unlock_error)?;
        self.save_remembered(&remembered)
    }

    /// Stop remembering entirely. Enrolled authenticators are left alone: they
    /// carry their own copies and removing them is a separate, explicit act.
    pub fn forget_remembered(&self) -> CoreResult<()> {
        let mut remembered = self.load_remembered()?;
        remembered
            .forget_keystore(default_keystore().as_ref())
            .map_err(unlock_error)?;
        self.save_remembered(&remembered)
    }

    pub fn lock(&self) -> CoreResult<VaultStatus> {
        *self.master_key.lock().expect("lock poisoned") = None;
        *self.vault_id.lock().expect("lock poisoned") = None;
        Ok(VaultStatus { unlocked: false })
    }

    pub fn vault_status(&self) -> CoreResult<VaultStatus> {
        let unlocked = self.master_key.lock().expect("lock poisoned").is_some();
        Ok(VaultStatus { unlocked })
    }

    pub fn current_vault_id(&self) -> Option<String> {
        self.vault_id
            .lock()
            .expect("lock poisoned")
            .map(|id| id.to_string())
    }

    pub fn list_vaults(&self) -> CoreResult<Vec<VaultSummaryFfi>> {
        let repo = LocalVaultRepo::new(&self.pool);
        let item_repo = LocalItemRepo::new(&self.pool);
        let storage_id = self.storage_id();
        let vaults = self
            .runtime
            .block_on(repo.list_by_storage(storage_id))
            .map_err(|err| CoreError::Service(err.to_string()))?;
        let mut result = Vec::with_capacity(vaults.len());
        for vault in vaults {
            let count = self
                .runtime
                .block_on(item_repo.count_by_vault(storage_id, vault.id))
                .map_err(|err| CoreError::Service(err.to_string()))?;
            result.push(VaultSummaryFfi {
                id: vault.id.to_string(),
                name: vault.name,
                is_default: vault.is_default,
                item_count: count as u64,
            });
        }
        Ok(result)
    }

    pub fn set_current_vault(&self, id: String) -> CoreResult<VaultStatus> {
        if self.master_key.lock().expect("lock poisoned").is_none() {
            return Err(CoreError::Locked);
        }
        let vault_id = Uuid::parse_str(&id)
            .map_err(|_| CoreError::InvalidArgument("invalid vault id".to_string()))?;
        let repo = LocalVaultRepo::new(&self.pool);
        let vaults = self
            .runtime
            .block_on(repo.list_by_storage(self.storage_id()))
            .map_err(|err| CoreError::Service(err.to_string()))?;
        if !vaults.iter().any(|vault| vault.id == vault_id) {
            return Err(CoreError::InvalidArgument("vault not found".to_string()));
        }
        *self.vault_id.lock().expect("lock poisoned") = Some(vault_id);
        Ok(VaultStatus { unlocked: true })
    }

    pub fn items_list(&self, filter: ItemsFilter, page: Page) -> CoreResult<ItemPage> {
        let master_key = self.master_key()?;
        let vault_id = self.vault_id()?;
        let services = self.services_with_key(master_key.as_ref());
        let params = ItemListParams {
            query: filter.query,
            limit: Some(page.limit),
            cursor: page.cursor,
            include_deleted: filter.include_deleted,
        };
        let result =
            self.runtime_block_on(services.list_items(self.storage_id(), vault_id, params))?;
        Ok(ItemPage {
            items: result
                .items
                .into_iter()
                .map(|item| ItemSummary {
                    id: item.id.to_string(),
                    title: item.name,
                    path: item.path,
                    type_id: item.type_id,
                    deleted: item.deleted_at.is_some(),
                })
                .collect(),
            next_cursor: result.next_cursor,
            total_count: result.total_count as u64,
            counts: map_counts(result.counts),
        })
    }

    pub fn item_get(&self, id: String) -> CoreResult<ItemDetail> {
        let master_key = self.master_key()?;
        let _vault_id = self.vault_id()?;
        let services = self.services_with_key(master_key.as_ref());
        let item_id = Uuid::parse_str(&id)
            .map_err(|_| CoreError::InvalidArgument("invalid item id".to_string()))?;
        let item = self.runtime_block_on(services.get_item(self.storage_id(), item_id))?;
        let payload_json = serde_json::to_string(&item.payload)
            .map_err(|err| CoreError::Service(err.to_string()))?;
        Ok(ItemDetail {
            id: item.id.to_string(),
            title: item.name,
            path: item.path,
            type_id: item.type_id,
            payload_json,
        })
    }

    pub fn item_update(&self, id: String, update: ItemUpdate) -> CoreResult<ItemDetail> {
        let master_key = self.master_key()?;
        let _vault_id = self.vault_id()?;
        let services = self.services_with_key(master_key.as_ref());
        let item_id = Uuid::parse_str(&id)
            .map_err(|_| CoreError::InvalidArgument("invalid item id".to_string()))?;
        let payload: EncryptedPayload = serde_json::from_str(&update.payload_json)
            .map_err(|err| CoreError::InvalidArgument(err.to_string()))?;
        self.runtime
            .block_on(services.update_item_by_id(
                self.storage_id(),
                item_id,
                update.path,
                update.type_id,
                payload,
            ))
            .map_err(|err| CoreError::Service(err.to_string()))?;
        self.item_get(id)
    }

    /// Import a plain backup. Pass an empty `path` and it fails rather than
    /// guessing: unlike export there is no sensible default to fall back on.
    pub fn backup_import_file(
        &self,
        path: String,
        options: BackupImportOptions,
    ) -> CoreResult<BackupImportReport> {
        let ctx = self.backup_ctx()?;
        let path = path.trim();
        if path.is_empty() {
            return Err(CoreError::InvalidArgument(
                "backup path is empty".to_string(),
            ));
        }
        let outcome = self.runtime.block_on(zann_app::backup::plain_import(
            &ctx,
            PathBuf::from(path),
            options.target_storage_id,
        ))?;
        match outcome {
            zann_app::ImportOutcome::Done(report) => Ok(BackupImportReport {
                imported_items: report.imported_items as u64,
                skipped_existing: report.skipped_existing as u64,
                skipped_missing_storage: report.skipped_missing_storage as u64,
                skipped_missing_vault: report.skipped_missing_vault as u64,
                skipped_deleted: report.skipped_deleted as u64,
            }),
            zann_app::ImportOutcome::NeedsRemote(_) => Err(CoreError::Unimplemented(
                "backup import into a remote storage".to_string(),
            )),
        }
    }

    /// Export every local vault to a plain backup file. An empty `path` writes
    /// to the vault directory's default location, which is what a client with
    /// no file picker of its own wants.
    pub fn backup_export_file(&self, path: String) -> CoreResult<BackupExportReport> {
        let ctx = self.backup_ctx()?;
        let path = path.trim();
        let target = if path.is_empty() {
            ctx.default_export_path()
        } else {
            PathBuf::from(path)
        };
        let report = self
            .runtime
            .block_on(zann_app::backup::plain_export(&ctx, target))?;
        Ok(BackupExportReport {
            path: report.path,
            storages_count: report.storages_count as u64,
            vaults_count: report.vaults_count as u64,
            items_count: report.items_count as u64,
        })
    }

    /// Walk every vault and item this key can open, checking the database
    /// structure, every stored checksum and every payload's decryption.
    ///
    /// Needs the key, unlike a snapshot: proving a payload is still readable
    /// means reading it.
    pub fn verify(&self) -> CoreResult<VerifyReportFfi> {
        let master_key = self.master_key()?;
        let report = self
            .runtime
            .block_on(zann_app::verify::run(&self.pool, master_key))?;
        Ok(report.into())
    }

    /// Copy the vault database to `<root>/snapshots/`, then apply retention.
    ///
    /// No master key is required, and deliberately so: this copies a file that
    /// is already readable on disk and stays encrypted in the copy, so
    /// demanding an unlock would suggest a protection that is not there.
    pub fn snapshot_create(&self, retention: Option<RetentionFfi>) -> CoreResult<SnapshotFfi> {
        let policy = retention.map(Into::into).unwrap_or_default();
        let snapshot = self
            .runtime
            .block_on(zann_app::snapshot::create(&self.pool, &self.root, &policy))?;
        Ok(snapshot.into())
    }

    /// Take one only if the newest has aged past `max_age_hours`. Returns
    /// `None` when a recent enough snapshot already exists, so a client can call
    /// this on every start without thinking about it.
    pub fn snapshot_create_if_due(
        &self,
        max_age_hours: u32,
        retention: Option<RetentionFfi>,
    ) -> CoreResult<Option<SnapshotFfi>> {
        let policy = retention.map(Into::into).unwrap_or_default();
        let max_age = std::time::Duration::from_secs(u64::from(max_age_hours) * 3600);
        let snapshot = self.runtime.block_on(zann_app::snapshot::create_if_due(
            &self.pool, &self.root, max_age, &policy,
        ))?;
        Ok(snapshot.map(Into::into))
    }

    /// Newest first.
    pub fn snapshot_list(&self) -> CoreResult<Vec<SnapshotFfi>> {
        Ok(zann_app::snapshot::list(&self.root)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Where a snapshot has to be copied back to. Restoring is not done here:
    /// the database is open, and swapping the file under a live pool is how a
    /// working vault becomes a corrupt one. Clients show both paths and say to
    /// close every client first.
    pub fn snapshot_restore_target(&self) -> String {
        zann_app::snapshot::restore_target(&self.root)
            .display()
            .to_string()
    }

    pub fn list_storages(&self) -> CoreResult<Vec<StorageSummaryFfi>> {
        let repo = LocalStorageRepo::new(&self.pool);
        let storages = self
            .runtime
            .block_on(repo.list())
            .map_err(|err| CoreError::Service(err.to_string()))?;
        Ok(storages
            .into_iter()
            .map(|s| StorageSummaryFfi {
                id: s.id.to_string(),
                name: s.name,
                kind: if s.kind == zann_core::StorageKind::LocalOnly {
                    "local"
                } else {
                    "remote"
                }
                .to_string(),
            })
            .collect())
    }

    pub fn set_current_storage(&self, id: String) -> CoreResult<()> {
        let storage_id = Uuid::parse_str(&id)
            .map_err(|_| CoreError::InvalidArgument("invalid storage id".to_string()))?;
        let repo = LocalStorageRepo::new(&self.pool);
        let storages = self
            .runtime
            .block_on(repo.list())
            .map_err(|err| CoreError::Service(err.to_string()))?;
        if !storages.iter().any(|s| s.id == storage_id) {
            return Err(CoreError::InvalidArgument("storage not found".to_string()));
        }
        *self.storage_id.lock().expect("lock poisoned") = storage_id;
        *self.vault_id.lock().expect("lock poisoned") = None; // Clear selected vault
        Ok(())
    }

    pub fn current_storage_id(&self) -> String {
        self.storage_id().to_string()
    }

    pub fn app_status(&self) -> CoreResult<AppStatusFfi> {
        let storage_repo = LocalStorageRepo::new(&self.pool);
        let vault_repo = LocalVaultRepo::new(&self.pool);

        let storages = self
            .runtime
            .block_on(storage_repo.list())
            .map_err(|err| CoreError::Service(err.to_string()))?;

        let storages_count = storages.len() as u64;

        // Check if any vaults exist (indicates master password was set)
        let mut has_local_vault = false;
        let mut initialized = false;

        for storage in &storages {
            let vaults = self
                .runtime
                .block_on(vault_repo.list_by_storage(storage.id))
                .map_err(|err| CoreError::Service(err.to_string()))?;
            if !vaults.is_empty() {
                initialized = true;
                if storage.kind == zann_core::StorageKind::LocalOnly {
                    has_local_vault = true;
                }
            }
        }

        let locked = self.master_key.lock().expect("lock poisoned").is_none();

        Ok(AppStatusFfi {
            initialized,
            locked,
            storages_count,
            has_local_vault,
        })
    }

    pub fn initialize_master_password(&self, password: String) -> CoreResult<VaultStatus> {
        if password.len() < 8 {
            return Err(CoreError::InvalidArgument(
                "password must be at least 8 characters".to_string(),
            ));
        }

        // Check if already initialized
        let status = self.app_status()?;
        if status.initialized {
            return Err(CoreError::InvalidArgument(
                "vault already initialized".to_string(),
            ));
        }

        // Derive master key from password
        let master_key = Arc::new(derive_master_key(&password, &self.identity)?);

        // Create local storage if none exists
        let storage_repo = LocalStorageRepo::new(&self.pool);
        let storages = self
            .runtime
            .block_on(storage_repo.list())
            .map_err(|err| CoreError::Service(err.to_string()))?;

        let storage_id = if storages.is_empty() {
            let new_storage = LocalStorage {
                id: Uuid::now_v7(),
                kind: zann_core::StorageKind::LocalOnly,
                name: "Local".to_string(),
                server_url: None,
                server_name: None,
                server_fingerprint: None,
                account_subject: None,
                personal_vaults_enabled: true,
                auth_method: None,
            };
            self.runtime
                .block_on(storage_repo.upsert(&new_storage))
                .map_err(|err| CoreError::Service(err.to_string()))?;
            *self.storage_id.lock().expect("lock poisoned") = new_storage.id;
            new_storage.id
        } else {
            self.storage_id()
        };

        // Create the default vault
        let services = LocalServices::new(&self.pool, master_key.as_ref());
        let vault = self.runtime_block_on(services.ensure_default_local_personal())?;

        // Store master key and vault id
        *self.master_key.lock().expect("lock poisoned") = Some(master_key);
        *self.vault_id.lock().expect("lock poisoned") = Some(vault.id);
        *self.storage_id.lock().expect("lock poisoned") = storage_id;

        Ok(VaultStatus { unlocked: true })
    }

    pub fn remote_sync(&self, storage_id: Option<String>) -> CoreResult<()> {
        let master_key = self.master_key()?;
        let root = client_root_path()?;
        let state = ClientState::new(self.pool.clone(), root);
        let response = self
            .runtime
            .block_on(zann_client::sync::remote_sync(
                storage_id,
                &state,
                master_key.as_ref(),
            ))
            .map_err(CoreError::Service)?;
        if response.ok {
            Ok(())
        } else {
            let message = response
                .error
                .as_ref()
                .map(|err| err.message.clone())
                .unwrap_or_else(|| "remote sync failed".to_string());
            Err(CoreError::Service(message))
        }
    }
}

#[uniffi::export]
pub fn create_core(db_url: String) -> CoreResult<Arc<CoreFacade>> {
    let runtime = Runtime::new().map_err(|err| CoreError::InvalidArgument(err.to_string()))?;
    let pool = runtime
        .block_on(connect_sqlite_with_max(&db_url, 5))
        .map_err(|err| CoreError::Service(err.to_string()))?;
    runtime
        .block_on(migrate_local(&pool))
        .map_err(|err| CoreError::Service(err.to_string()))?;
    let identity = load_or_create_identity_config(&db_url)?;
    let storage_id = resolve_storage_id(&runtime, &pool)?;
    Ok(Arc::new(CoreFacade {
        runtime,
        pool,
        storage_id: Mutex::new(storage_id),
        vault_id: Mutex::new(None),
        master_key: Mutex::new(None),
        identity,
        root: local_root_from_db_url(&db_url),
    }))
}

impl CoreFacade {
    fn load_remembered(&self) -> CoreResult<RememberedUnlock> {
        RememberedUnlock::load(&self.root).map_err(unlock_error)
    }

    fn save_remembered(&self, remembered: &RememberedUnlock) -> CoreResult<()> {
        remembered.save(&self.root).map_err(unlock_error)
    }
}

/// Unlock failures keep their identifier so every client shows the same message
/// for the same cause.
fn unlock_error(err: UnlockError) -> CoreError {
    match err {
        UnlockError::NotRemembered => CoreError::InvalidArgument(err.kind().to_string()),
        other => CoreError::Service(format!("{}: {other}", other.kind())),
    }
}

fn client_root_path() -> CoreResult<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Ok(PathBuf::from(home).join(".zann"))
}

fn map_counts(counts: ItemCounts) -> ItemCountsFfi {
    let mut by_type: Vec<ItemTypeCount> = counts
        .by_type
        .into_iter()
        .map(|(type_id, count)| ItemTypeCount {
            type_id,
            count: count as u64,
        })
        .collect();
    by_type.sort_by(|a, b| a.type_id.cmp(&b.type_id));
    ItemCountsFfi {
        all: counts.all as u64,
        trash: counts.trash as u64,
        by_type,
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct IdentityConfig {
    kdf_salt: String,
    kdf_params: zann_core::api::auth::KdfParams,
    #[serde(default)]
    salt_fingerprint: Option<String>,
    #[serde(default)]
    first_seen_at: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

fn load_or_create_identity_config(db_url: &str) -> CoreResult<IdentityConfig> {
    let root = local_root_from_db_url(db_url);
    let path = root.join("config.json");
    let mut config = match std::fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str::<Value>(&contents).map_err(|err| {
            CoreError::Service(format!(
                "failed to parse config.json at {}: {}",
                path.display(),
                err
            ))
        })?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Value::Object(serde_json::Map::new())
        }
        Err(err) => return Err(CoreError::Service(err.to_string())),
    };

    let identity = config
        .get("identity")
        .and_then(|value| serde_json::from_value::<IdentityConfig>(value.clone()).ok());
    if let Some(identity) = identity {
        return Ok(identity);
    }

    std::fs::create_dir_all(&root).map_err(|err| CoreError::Service(err.to_string()))?;
    let salt = SecretKey::generate();
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt.as_bytes());
    let identity = IdentityConfig {
        kdf_salt: salt_b64,
        kdf_params: default_local_kdf_params(),
        salt_fingerprint: None,
        first_seen_at: None,
        email: None,
    };
    let identity_value =
        serde_json::to_value(&identity).map_err(|err| CoreError::Service(err.to_string()))?;
    if let Value::Object(map) = &mut config {
        map.insert("identity".to_string(), identity_value);
    } else {
        config = serde_json::json!({ "identity": identity_value });
    }
    let json =
        serde_json::to_string_pretty(&config).map_err(|err| CoreError::Service(err.to_string()))?;
    std::fs::write(&path, json).map_err(|err| CoreError::Service(err.to_string()))?;
    Ok(identity)
}

fn derive_master_key(password: &str, identity: &IdentityConfig) -> CoreResult<SecretKey> {
    if identity.kdf_params.algorithm != "argon2id" {
        return Err(CoreError::InvalidArgument(
            "unsupported kdf algorithm".to_string(),
        ));
    }
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&identity.kdf_salt)
        .map_err(|_| CoreError::InvalidArgument("invalid kdf salt".to_string()))?;
    let params = argon2::Params::new(
        identity.kdf_params.memory_kb,
        identity.kdf_params.iterations,
        identity.kdf_params.parallelism,
        Some(32),
    )
    .map_err(|err| CoreError::InvalidArgument(err.to_string()))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|err| CoreError::InvalidArgument(err.to_string()))?;
    Ok(SecretKey::from_bytes(key))
}

fn default_local_kdf_params() -> zann_core::api::auth::KdfParams {
    zann_core::api::auth::KdfParams {
        algorithm: "argon2id".to_string(),
        iterations: 3,
        memory_kb: 65536,
        parallelism: 4,
    }
}

fn local_root_from_db_url(db_url: &str) -> PathBuf {
    if let Some(path) = db_url.strip_prefix("sqlite://") {
        if let Some(parent) = Path::new(path).parent() {
            return parent.to_path_buf();
        }
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".zann")
}

fn resolve_storage_id(runtime: &Runtime, pool: &SqlitePool) -> CoreResult<Uuid> {
    let repo = LocalStorageRepo::new(pool);
    let vault_repo = LocalVaultRepo::new(pool);
    let item_repo = LocalItemRepo::new(pool);
    let storages = runtime
        .block_on(repo.list())
        .map_err(|err| CoreError::Service(err.to_string()))?;
    if storages.is_empty() {
        return Ok(Uuid::nil());
    }

    let mut selected = (storages[0].id, 0usize);
    for storage in &storages {
        let vaults = runtime
            .block_on(vault_repo.list_by_storage(storage.id))
            .map_err(|err| CoreError::Service(err.to_string()))?;
        let mut total = 0usize;
        for vault in vaults {
            let count = runtime
                .block_on(item_repo.count_by_vault(storage.id, vault.id))
                .map_err(|err| CoreError::Service(err.to_string()))?;
            total = total.saturating_add(count as usize);
        }
        if total > selected.1 {
            selected = (storage.id, total);
        }
    }

    if selected.1 == 0 {
        if let Some(local) = storages
            .iter()
            .find(|storage| storage.kind == zann_core::StorageKind::LocalOnly)
        {
            return Ok(local.id);
        }
    }

    Ok(selected.0)
}

uniffi::setup_scaffolding!("zann_ffi");
