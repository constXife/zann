use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::SqliteSyncStoreFactory;
use tokio::runtime::Runtime;
use uuid::Uuid;
use zann_client::app::{
    AccountKeyCheck, AppClient, ClientId, ClientPaths, ConfigIdentity, CredentialSecret,
    LegacySessionImport, SessionClient, SessionOperation,
};
use zann_client::config::{CredentialStore, LegacyCredentialSource};
use zann_core::{ItemCounts as DomainItemCounts, ItemListParams, ItemsService};
use zann_crypto::crypto::SecretKey;
#[cfg(debug_assertions)]
use zann_crypto::secrets::{FieldKind, FieldValue};
use zann_crypto::vault_crypto;
use zann_crypto::EncryptedPayload;
use zann_db::local::{
    HistorySyncStatus, LocalItemHistoryRepo, LocalItemRepo, LocalStorageRepo, LocalVaultRepo,
    PendingChangeRepo, SyncCursorRepo,
};
use zann_db::services::LocalServices;
use zann_db::SqliteFileLocation;
use zann_db::{connect_sqlite_file_with_max, migrate_local, SqlitePool};
use zann_keystore::{RememberedUnlock as RememberedUnlockStore, UnlockError, UnlockSource};

use zann_client::app::local::*;

pub struct LocalVault {
    keystore: Arc<dyn Keystore>,
    authenticator: Arc<dyn HardwareAuthenticator>,
    credentials: Arc<dyn CredentialStore>,
    legacy_credentials: Arc<dyn LegacyCredentialSource>,
    runtime: Runtime,
    /// Behind a lock because a snapshot restore replaces the database under it.
    /// `SqlitePool` is a handle, so reads take a clone rather than hold the lock
    /// across a query.
    pool: Mutex<SqlitePool>,
    /// Kept as an exact native path so the pool can be opened again after a restore.
    database_path: PathBuf,
    storage_id: Mutex<Option<Uuid>>,
    vault_id: Mutex<Option<Uuid>>,
    master_key: Mutex<Option<Arc<SecretKey>>>,
    /// Cancelled on lock, so no sync keeps the master key past it.
    syncs: in_flight::InFlightSyncs,
    /// The vault directory. The remembered unlock is persisted there in its own
    /// file, so every client on this machine sees the same enrolments.
    root: PathBuf,
}

impl Drop for LocalVault {
    /// Closes every pooled connection before the vault is gone. SQLite
    /// checkpoints the WAL into the database file as each connection closes,
    /// so a close that outlived the vault would write into a file that may
    /// already have been replaced or copied over. The close runs on a fresh
    /// thread, which holds no async runtime of its own, so dropping the vault
    /// is safe inside one too.
    fn drop(&mut self) {
        let pool = match self.pool.get_mut() {
            Ok(pool) => pool.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let runtime = &self.runtime;
        std::thread::scope(|scope| {
            scope.spawn(|| runtime.block_on(pool.close()));
        });
    }
}

impl LocalVault {
    fn pool(&self) -> SqlitePool {
        self.pool.lock().expect("lock poisoned").clone()
    }

    /// Connect again after the database file was replaced, and re-read what was
    /// read from it at start-up.
    fn reopen_pool(&self) -> LocalResult<()> {
        let location = SqliteFileLocation::from_path(&self.database_path)
            .map_err(|err| LocalError::Service(err.to_string()))?;
        let pool = self
            .runtime
            .block_on(connect_sqlite_file_with_max(&location, 5))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        self.runtime
            .block_on(migrate_local(&pool))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        let storage_id = resolve_storage_id(&self.runtime, &pool)?;
        *self.pool.lock().expect("lock poisoned") = pool;
        *self.storage_id.lock().expect("lock poisoned") = storage_id;
        Ok(())
    }

    fn master_key(&self) -> LocalResult<Arc<SecretKey>> {
        self.master_key
            .lock()
            .expect("lock poisoned")
            .clone()
            .ok_or(LocalError::Locked)
    }

    fn backup_ctx(&self) -> LocalResult<crate::maintenance::BackupCtx> {
        Ok(crate::maintenance::BackupCtx::new(
            self.pool(),
            self.master_key()?,
            self.root.clone(),
        ))
    }

    fn vault_id(&self) -> LocalResult<Uuid> {
        self.vault_id
            .lock()
            .expect("lock poisoned")
            .ok_or_else(|| LocalError::InvalidArgument("select a vault".to_string()))
    }

    fn storage_id(&self) -> LocalResult<Uuid> {
        self.storage_id
            .lock()
            .expect("lock poisoned")
            .ok_or_else(|| LocalError::InvalidArgument("no server storage selected".to_string()))
    }

    fn runtime_block_on<F, T>(&self, future: F) -> LocalResult<T>
    where
        F: std::future::Future<Output = Result<T, zann_core::ServiceError>>,
    {
        self.runtime
            .block_on(future)
            .map_err(|err| LocalError::Service(err.to_string()))
    }

    /// Everything an unlock does once the master key exists, whatever produced
    /// it. Note the vault-key decryption below doubles as the check that the key
    /// is the right one, so a key recovered from a stale wrapped copy fails here
    /// exactly like a wrong password.
    fn finish_unlock(&self, master_key: Arc<SecretKey>) -> LocalResult<VaultStatus> {
        let pool = self.pool();
        let repo = LocalVaultRepo::new(&pool);
        let list = |storage_id| {
            self.runtime
                .block_on(repo.list_by_storage(storage_id))
                .map_err(|err| LocalError::Service(err.to_string()))
        };
        let storage_id = match *self.storage_id.lock().expect("lock poisoned") {
            Some(id) => Some(id),
            None => resolve_storage_id(&self.runtime, &pool)?,
        };
        let vaults = match storage_id {
            Some(id) => list(id)?,
            None => Vec::new(),
        };
        let vault_id = if let Some(verify) = vaults.first() {
            vault_crypto::decrypt_vault_key(master_key.as_ref(), verify.id, &verify.vault_key_enc)
                .map_err(|_| LocalError::InvalidArgument("invalid password".to_string()))?;
            preferred_vault(
                &self.runtime,
                &pool,
                storage_id.expect("storage with vaults"),
                &vaults,
            )?
        } else {
            self.check_key_for_new_device(&master_key)?;
            None
        };
        *self.storage_id.lock().expect("lock poisoned") = storage_id;
        *self.master_key.lock().expect("lock poisoned") = Some(master_key);
        *self.vault_id.lock().expect("lock poisoned") = vault_id;
        Ok(VaultStatus { unlocked: true })
    }

    #[cfg(debug_assertions)]
    pub fn debug_create_kv_item(
        &self,
        path: String,
        key: String,
        value: String,
    ) -> LocalResult<String> {
        let master_key = self.master_key()?;
        let vault_id = self.vault_id()?;
        let pool = self.pool();
        let services = LocalServices::new(&pool, master_key.as_ref());
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
            self.storage_id()?,
            vault_id,
            path,
            "kv".to_string(),
            payload,
        ))?;
        Ok(item_id.to_string())
    }
}
impl LocalVault {
    fn app_client(&self) -> LocalResult<AppClient> {
        let factory = Arc::new(
            SqliteSyncStoreFactory::new(&self.database_path)
                .map_err(|error| LocalError::Service(error.to_string()))?,
        );
        let client_id =
            ClientId::new("desktop").map_err(|error| LocalError::Service(error.to_string()))?;
        let client = AppClient::new(
            ClientPaths::new(&self.root),
            self.credentials.clone(),
            SessionClient::new(client_id),
            factory,
        );
        client
            .initialize(self.legacy_credentials.as_ref())
            .map_err(|error| LocalError::Service(error.to_string()))?;
        Ok(client)
    }

    /// The KDF identity in Config v2, the only place it is kept.
    fn kdf_identity(&self) -> LocalResult<Option<ConfigIdentity>> {
        self.app_client()?
            .kdf_identity()
            .map_err(|error| LocalError::Service(error.to_string()))
    }
}
impl LocalVault {
    fn load_remembered(&self) -> LocalResult<RememberedUnlockStore> {
        RememberedUnlockStore::load(&self.root).map_err(unlock_error)
    }

    fn save_remembered(&self, remembered: &RememberedUnlockStore) -> LocalResult<()> {
        remembered.save(&self.root).map_err(unlock_error)
    }
}

/// Opens a legacy `sqlite:` URI with the desktop ports.
pub fn open_vault(db_url: String) -> LocalResult<Arc<LocalVault>> {
    let location = SqliteFileLocation::from_uri(&db_url)
        .map_err(|err| LocalError::InvalidArgument(err.to_string()))?;
    LocalVault::open(location, LocalVaultPorts::system_default())
}

/// Opens a location already parsed and resolved by the native composition
/// root, with the desktop ports.
pub fn open_vault_at_file_location(location: &SqliteFileLocation) -> LocalResult<Arc<LocalVault>> {
    LocalVault::open(location.clone(), LocalVaultPorts::system_default())
}

impl LocalVault {
    /// Compose a vault with platform-provided ports. No hardware or OS-store
    /// discovery occurs during construction.
    pub fn open(location: SqliteFileLocation, ports: LocalVaultPorts) -> LocalResult<Arc<Self>> {
        let LocalVaultPorts {
            keystore,
            authenticator,
            credentials,
            legacy_credentials,
        } = ports;
        let runtime = Runtime::new().map_err(|err| LocalError::InvalidArgument(err.to_string()))?;
        let root = location.root().to_path_buf();
        let database_path = location.path().to_path_buf();
        // The client root holds the config and credentials journal; the sync
        // store refuses a database in a directory others can read.
        crate::maintenance::secure_file::ensure_private_dir(&root)
            .map_err(|err| LocalError::Service(err.to_string()))?;
        let pool = runtime
            .block_on(connect_sqlite_file_with_max(&location, 5))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        runtime
            .block_on(migrate_local(&pool))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        let storage_id = resolve_storage_id(&runtime, &pool)?;
        Ok(Arc::new(LocalVault {
            keystore,
            authenticator,
            credentials,
            legacy_credentials,
            runtime,
            pool: Mutex::new(pool),
            database_path,
            storage_id: Mutex::new(storage_id),
            vault_id: Mutex::new(None),
            master_key: Mutex::new(None),
            syncs: in_flight::InFlightSyncs::default(),
            root,
        }))
    }
}

fn chrono_datetime_from_rfc3339(
    value: &str,
) -> std::result::Result<chrono::DateTime<chrono::Utc>, String> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|datetime| datetime.with_timezone(&chrono::Utc))
        .map_err(|err| err.to_string())
}

fn unlock_error(err: UnlockError) -> LocalError {
    LocalError::Unlock {
        kind: err.kind().to_string(),
        message: err.to_string(),
        source: Box::new(err),
    }
}

fn map_counts(counts: DomainItemCounts) -> ItemCountsView {
    let mut by_type: Vec<ItemTypeCount> = counts
        .by_type
        .into_iter()
        .map(|(type_id, count)| ItemTypeCount {
            type_id,
            count: count as u64,
        })
        .collect();
    by_type.sort_by(|a, b| a.type_id.cmp(&b.type_id));
    ItemCountsView {
        all: counts.all as u64,
        trash: counts.trash as u64,
        by_type,
    }
}

/// `BackupError` already carries a stable `kind`; keep it rather than
/// flattening everything into one string, so the UI can still translate.
impl From<crate::maintenance::BackupError> for LocalError {
    fn from(err: crate::maintenance::BackupError) -> Self {
        LocalError::Backup {
            kind: err.kind.clone(),
            message: err.message.clone(),
            source: Box::new(err),
        }
    }
}

impl From<crate::maintenance::SnapshotError> for LocalError {
    fn from(err: crate::maintenance::SnapshotError) -> Self {
        LocalError::Service(format!("{}: {}", err.kind, err.message))
    }
}

impl From<crate::maintenance::Snapshot> for Snapshot {
    fn from(snapshot: crate::maintenance::Snapshot) -> Self {
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

impl From<crate::maintenance::VerifyError> for LocalError {
    fn from(err: crate::maintenance::VerifyError) -> Self {
        LocalError::Service(format!("{}: {}", err.kind, err.message))
    }
}

impl From<crate::maintenance::VerifyReport> for VerifyReport {
    fn from(report: crate::maintenance::VerifyReport) -> Self {
        Self {
            database_ok: report.database_ok,
            vaults_checked: report.vaults_checked,
            vaults_skipped: report.vaults_skipped,
            items_checked: report.items_checked,
            items_ok: report.items_ok,
            problems: report
                .problems
                .into_iter()
                .map(|problem| VerifyProblem {
                    kind: problem.kind,
                    vault_name: problem.vault_name,
                    item_path: problem.item_path,
                    detail: problem.detail,
                })
                .collect(),
        }
    }
}

impl From<Retention> for crate::maintenance::RetentionPolicy {
    fn from(retention: Retention) -> Self {
        Self {
            max_count: retention.max_count.map(|count| count as usize),
            max_age_days: retention.max_age_days,
        }
    }
}

mod enrollment;
mod in_flight;
mod ports;
pub use ports::*;
mod unlock;

mod session;

mod items;

mod maintenance;

mod identity;
use identity::*;

mod selection;
use selection::*;

impl LocalVaultService for LocalVault {
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
    fn unlock(&self, password: String) -> LocalResult<VaultStatus> {
        LocalVault::unlock(self, password)
    }
    fn remembered_unlock(&self) -> LocalResult<RememberedUnlock> {
        LocalVault::remembered_unlock(self)
    }
    fn unlock_remembered(&self) -> LocalResult<VaultStatus> {
        LocalVault::unlock_remembered(self)
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
        options: BackupImportOptions,
    ) -> LocalResult<BackupImportReport> {
        LocalVault::backup_import_file(self, path, options)
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
    fn backup_export_file(&self, path: String) -> LocalResult<BackupExportReport> {
        LocalVault::backup_export_file(self, path)
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

    fn current_storage_id(&self) -> LocalResult<String> {
        LocalVault::current_storage_id(self)
    }
    fn app_status(&self) -> LocalResult<AppStatus> {
        LocalVault::app_status(self)
    }
    fn initialize_master_password(&self, password: String) -> LocalResult<VaultStatus> {
        LocalVault::initialize_master_password(self, password)
    }
    fn remote_sync(&self, storage_id: Option<String>) -> LocalResult<LocalSyncOutcome> {
        LocalVault::remote_sync(self, storage_id)
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

/// Prepare the explicitly selected native database before remote session setup.
pub async fn initialize_database(location: &SqliteFileLocation) -> LocalResult<()> {
    let pool = connect_sqlite_file_with_max(location, 5)
        .await
        .map_err(|err| LocalError::Service(err.to_string()))?;
    migrate_local(&pool)
        .await
        .map_err(|err| LocalError::Service(err.to_string()))
}

#[cfg(test)]
mod compatibility_tests {
    use serde::Deserialize;
    use zann_client::app::ConfigKdfParams;

    use crate::test_support::CanonicalTempDir;

    use super::*;

    const FIXTURE_JSON: &str = include_str!("../../../tests/fixtures/crypto/v1_local_vault.json");

    #[derive(Deserialize)]
    struct Fixture {
        synthetic_only: bool,
        kdf: KdfFixture,
    }

    #[derive(Deserialize)]
    struct KdfFixture {
        password: String,
        salt_base64: String,
        params: KdfParamsFixture,
        expected_key_hex: String,
    }

    #[derive(Deserialize)]
    struct KdfParamsFixture {
        algorithm: String,
        iterations: u32,
        memory_kb: u32,
        parallelism: u32,
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "fixture hex must have pairs");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).expect("fixture hex must be UTF-8");
                u8::from_str_radix(pair, 16).expect("valid fixture hex")
            })
            .collect()
    }

    #[test]
    fn canonical_master_key_kdf_matches_golden_vector() {
        let fixture: Fixture = serde_json::from_str(FIXTURE_JSON).expect("valid crypto fixture");
        assert!(fixture.synthetic_only);
        let identity = ConfigIdentity {
            kdf_salt: fixture.kdf.salt_base64,
            kdf_params: ConfigKdfParams {
                algorithm: fixture.kdf.params.algorithm,
                iterations: fixture.kdf.params.iterations,
                memory_kb: fixture.kdf.params.memory_kb,
                parallelism: fixture.kdf.params.parallelism,
            },
            salt_fingerprint: None,
            first_seen_at: None,
            email: None,
        };

        let key = derive_master_key(&fixture.kdf.password, &identity).expect("derive master key");
        assert_eq!(
            key.as_bytes().as_slice(),
            decode_hex(&fixture.kdf.expected_key_hex)
        );
    }

    #[test]
    fn client_state_uses_the_explicit_database_root() {
        let temp = CanonicalTempDir::new("tempdir");
        let root = temp.path().join("custom-client-root");
        std::fs::create_dir_all(&root).expect("create client root");
        let db_path = root.join("local.sqlite");
        let core =
            open_vault_at_path(&db_path, LocalVaultPorts::system_default()).expect("create core");

        assert_eq!(core.root, root);
    }

    #[test]
    fn filesystem_path_keeps_sqlite_uri_delimiters_literal() {
        let temp = CanonicalTempDir::new("tempdir");
        let root = temp.path().join("literal # ? % root");
        std::fs::create_dir_all(&root).expect("create client root");
        let db_path = root.join("local # ? %.sqlite");

        let core = open_vault_at_path(&db_path, LocalVaultPorts::system_default())
            .expect("create core at exact path");

        assert_eq!(core.root, root);
        assert!(db_path.exists(), "SQLite must create the exact path");
        core.seed_offline_fixture(format!("pw-{}", Uuid::now_v7()))
            .expect("initialize at exact path");
        assert!(
            core.root.join("client-config.json").exists(),
            "identity config must remain adjacent to the exact database path"
        );
    }

    #[test]
    fn percent_encoded_legacy_uri_keeps_database_and_client_root_together() {
        let temp = CanonicalTempDir::new("tempdir");
        let root = temp.path().join("encoded root");
        std::fs::create_dir_all(&root).expect("create encoded root");
        let db_path = root.join("local # ? %.sqlite");
        let encoded = db_path
            .to_str()
            .expect("UTF-8 test path")
            .replace('%', "%25")
            .replace(' ', "%20")
            .replace('#', "%23")
            .replace('?', "%3F");
        let uri = format!("sqlite:{encoded}?mode=rwc&cache=private");

        let core = open_vault(uri).expect("create core from encoded durable URI");

        assert_eq!(core.root, root);
        assert!(
            db_path.exists(),
            "URI and config root must name one database"
        );
        core.seed_offline_fixture(format!("pw-{}", Uuid::now_v7()))
            .expect("initialize at encoded path");
        assert!(root.join("client-config.json").exists());
    }

    #[test]
    fn ffi_legacy_uri_rejects_non_durable_database() {
        for uri in [
            "sqlite::memory:",
            "sqlite://?mode=memory",
            "sqlite://:memory:",
            "sqlite:",
        ] {
            assert!(
                matches!(
                    open_vault(uri.to_string()),
                    Err(LocalError::InvalidArgument(_))
                ),
                "{uri} must fail closed"
            );
        }
    }

    #[test]
    fn legacy_entry_point_rejects_ambiguous_raw_paths() {
        let error = match open_vault("relative # ? %.sqlite".to_string()) {
            Ok(_) => panic!("legacy public entry point must accept URIs only"),
            Err(error) => error,
        };
        assert!(matches!(error, LocalError::InvalidArgument(_)));
    }

    #[test]
    fn production_local_service_does_not_stringify_paths_into_sqlite_uris() {
        let source = include_str!("local_vault.rs");
        for forbidden in [
            ["format!(\"sqlite", "://"].concat(),
            ["connect_sqlite_", "path_with_max"].concat(),
            ["connect_sqlite_", "with_max"].concat(),
            ["SqliteConnectOptions::", "from_str"].concat(),
            ["strip_prefix(\"sqlite", "://\")"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "FFI must delegate parsing and resolution to SqliteFileLocation"
            );
        }
    }
}

#[cfg(feature = "test-support")]
mod test_support;
