#![cfg(feature = "config")]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zann_client::config::v2::{ClientNamespace, ConnectionMetadata, DesktopBackupSettings};
use zann_client::config::{
    ActiveCredentialAfterRemoval, ClientId, ClientPaths, ConfigError, ConfigRepository, ConfigV2,
    ConnectionId, CredentialActivation, CredentialBundle, CredentialId, CredentialKind,
    CredentialPortError, CredentialSecret, CredentialStore, CredentialTransactionWarning,
    LegacyCredentialAccountSemantics, LegacyCredentialLocator, LegacyCredentialSource,
    MasterKeyFingerprintBindingOutcome,
};

const EMPTY_V1: &str = include_str!("../../../tests/fixtures/client-config/v1/empty.json");
const NULLABLE_IDENTITY_V1: &str =
    include_str!("../../../tests/fixtures/client-config/v1/local-identity-nullable.json");
const CLI_KEYRING_V1: &str =
    include_str!("../../../tests/fixtures/client-config/v1/cli-keyring.json");
const MALFORMED_V1: &str = include_str!("../../../tests/fixtures/client-config/v1/malformed.json");

#[derive(Default)]
struct MemoryCredentials {
    values: Mutex<BTreeMap<String, String>>,
    successful_writes: Mutex<BTreeMap<String, usize>>,
    write_attempt: AtomicUsize,
    fail_on_attempt: AtomicUsize,
    failed_once: AtomicBool,
}

impl MemoryCredentials {
    fn fail_once_on(attempt: usize) -> Self {
        Self {
            fail_on_attempt: AtomicUsize::new(attempt),
            ..Self::default()
        }
    }

    fn value(&self, id: &CredentialId) -> Option<String> {
        self.values
            .lock()
            .expect("credential map lock")
            .get(id.as_str())
            .cloned()
    }

    fn write_count(&self, id: &CredentialId) -> usize {
        self.successful_writes
            .lock()
            .expect("write count lock")
            .get(id.as_str())
            .copied()
            .unwrap_or(0)
    }

    fn len(&self) -> usize {
        self.values.lock().expect("credential map lock").len()
    }
}

impl CredentialStore for MemoryCredentials {
    fn put(
        &self,
        credential_id: &CredentialId,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialPortError> {
        let attempt = self.write_attempt.fetch_add(1, Ordering::SeqCst) + 1;
        if attempt == self.fail_on_attempt.load(Ordering::SeqCst)
            && !self.failed_once.swap(true, Ordering::SeqCst)
        {
            return Err(CredentialPortError::new(
                "injected credential write failure",
            ));
        }
        self.values
            .lock()
            .map_err(|_| CredentialPortError::new("credential map lock poisoned"))?
            .insert(
                credential_id.as_str().to_string(),
                secret.expose_secret().to_string(),
            );
        *self
            .successful_writes
            .lock()
            .map_err(|_| CredentialPortError::new("write count lock poisoned"))?
            .entry(credential_id.as_str().to_string())
            .or_insert(0) += 1;
        Ok(())
    }

    fn get(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        self.values
            .lock()
            .map_err(|_| CredentialPortError::new("credential map lock poisoned"))?
            .get(credential_id.as_str())
            .cloned()
            .map(CredentialSecret::new)
            .transpose()
            .map_err(|error| CredentialPortError::new(error.to_string()))
    }

    fn delete(&self, credential_id: &CredentialId) -> Result<(), CredentialPortError> {
        self.values
            .lock()
            .map_err(|_| CredentialPortError::new("credential map lock poisoned"))?
            .remove(credential_id.as_str());
        Ok(())
    }
}

#[derive(Default)]
struct MemoryLegacyCredentials {
    values: BTreeMap<LegacyCredentialLocator, String>,
}

impl MemoryLegacyCredentials {
    fn with(mut self, locator: LegacyCredentialLocator, secret: &str) -> Self {
        self.values.insert(locator, secret.to_string());
        self
    }
}

impl LegacyCredentialSource for MemoryLegacyCredentials {
    fn get(
        &self,
        locator: &LegacyCredentialLocator,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        self.values
            .get(locator)
            .cloned()
            .map(CredentialSecret::new)
            .transpose()
            .map_err(|error| CredentialPortError::new(error.to_string()))
    }
}

#[derive(Default)]
struct CountingLegacyCredentials {
    reads: AtomicUsize,
}

impl LegacyCredentialSource for CountingLegacyCredentials {
    fn get(
        &self,
        _locator: &LegacyCredentialLocator,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
}

struct WindowsLegacyCredentials {
    reads: AtomicUsize,
    verifies_exact_identity: bool,
}

impl WindowsLegacyCredentials {
    fn verified() -> Self {
        Self {
            reads: AtomicUsize::new(0),
            verifies_exact_identity: true,
        }
    }

    fn unverified() -> Self {
        Self {
            reads: AtomicUsize::new(0),
            verifies_exact_identity: false,
        }
    }
}

impl LegacyCredentialSource for WindowsLegacyCredentials {
    fn account_semantics(&self) -> LegacyCredentialAccountSemantics {
        LegacyCredentialAccountSemantics::WindowsCaseInsensitive
    }

    fn verifies_exact_account_identity(&self) -> bool {
        self.verifies_exact_identity
    }

    fn get(
        &self,
        _locator: &LegacyCredentialLocator,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
}

#[derive(Default)]
struct OversizedLegacyCredentials {
    reads: AtomicUsize,
}

impl LegacyCredentialSource for OversizedLegacyCredentials {
    fn get(
        &self,
        _locator: &LegacyCredentialLocator,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        CredentialSecret::new("x".repeat(64 * 1024 + 1))
            .map(Some)
            .map_err(|error| CredentialPortError::new(error.to_string()))
    }
}

struct MutatingCredentials {
    inner: MemoryCredentials,
    legacy_path: PathBuf,
    replacement: String,
    mutated: AtomicBool,
    written_ids: Mutex<Vec<CredentialId>>,
}

impl MutatingCredentials {
    fn new(legacy_path: PathBuf, replacement: &str) -> Self {
        Self {
            inner: MemoryCredentials::default(),
            legacy_path,
            replacement: replacement.to_string(),
            mutated: AtomicBool::new(false),
            written_ids: Mutex::new(Vec::new()),
        }
    }

    fn ids(&self) -> Vec<CredentialId> {
        self.written_ids.lock().expect("written ids lock").clone()
    }
}

impl CredentialStore for MutatingCredentials {
    fn put(
        &self,
        credential_id: &CredentialId,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialPortError> {
        self.inner.put(credential_id, secret)?;
        self.written_ids
            .lock()
            .map_err(|_| CredentialPortError::new("written ids lock poisoned"))?
            .push(credential_id.clone());
        if !self.mutated.swap(true, Ordering::SeqCst) {
            fs::write(&self.legacy_path, self.replacement.as_bytes())
                .map_err(|error| CredentialPortError::new(format!("mutate legacy: {error}")))?;
        }
        Ok(())
    }

    fn get(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        self.inner.get(credential_id)
    }

    fn delete(&self, credential_id: &CredentialId) -> Result<(), CredentialPortError> {
        self.inner.delete(credential_id)
    }
}

struct PanicCredentialPorts;

impl CredentialStore for PanicCredentialPorts {
    fn put(
        &self,
        _credential_id: &CredentialId,
        _secret: &CredentialSecret,
    ) -> Result<(), CredentialPortError> {
        panic!("credential store must not run while claiming an existing migration")
    }

    fn get(
        &self,
        _credential_id: &CredentialId,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        panic!("credential store must not run while claiming an existing migration")
    }

    fn delete(&self, _credential_id: &CredentialId) -> Result<(), CredentialPortError> {
        panic!("credential store must not run while claiming an existing migration")
    }
}

impl LegacyCredentialSource for PanicCredentialPorts {
    fn get(
        &self,
        _locator: &LegacyCredentialLocator,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        panic!("legacy credential source must not run while claiming an existing migration")
    }
}

type VerifiedCallback = Box<dyn FnOnce(&CredentialId) + Send>;
type DeleteCallback = Box<dyn FnOnce(&CredentialId) + Send>;
type StoreCallback = Box<dyn FnOnce() + Send>;

#[derive(Default)]
struct FaultCredentialStore {
    values: Mutex<BTreeMap<String, String>>,
    puts: AtomicUsize,
    reads: AtomicUsize,
    deletes: AtomicUsize,
    validations: AtomicUsize,
    fail_validate_on: AtomicUsize,
    collide_validate_on: AtomicUsize,
    fail_put: AtomicBool,
    write_then_fail_put: AtomicBool,
    fail_readback: AtomicBool,
    fail_delete: AtomicBool,
    after_verified: Mutex<Option<VerifiedCallback>>,
    before_delete: Mutex<Option<DeleteCallback>>,
    deleted_ids: Mutex<Vec<String>>,
}

impl FaultCredentialStore {
    fn set_after_verified(&self, callback: impl FnOnce(&CredentialId) + Send + 'static) {
        *self.after_verified.lock().expect("verified callback lock") = Some(Box::new(callback));
    }

    fn set_fail_put(&self) {
        self.fail_put.store(true, Ordering::SeqCst);
    }

    fn set_write_then_fail_put(&self) {
        self.write_then_fail_put.store(true, Ordering::SeqCst);
    }

    fn set_fail_validate_on(&self, attempt: usize) {
        self.fail_validate_on.store(attempt, Ordering::SeqCst);
    }

    fn set_collide_validate_on(&self, attempt: usize) {
        self.collide_validate_on.store(attempt, Ordering::SeqCst);
    }

    fn set_fail_readback(&self) {
        self.fail_readback.store(true, Ordering::SeqCst);
    }

    fn set_fail_delete(&self, fail: bool) {
        self.fail_delete.store(fail, Ordering::SeqCst);
    }

    fn set_before_delete(&self, callback: impl FnOnce(&CredentialId) + Send + 'static) {
        *self.before_delete.lock().expect("delete callback lock") = Some(Box::new(callback));
    }

    fn len(&self) -> usize {
        self.values.lock().expect("fault store lock").len()
    }

    fn contains(&self, credential_id: &CredentialId) -> bool {
        self.values
            .lock()
            .expect("fault store lock")
            .contains_key(credential_id.as_str())
    }

    fn deleted(&self, credential_id: &CredentialId) -> bool {
        self.deleted_ids
            .lock()
            .expect("deleted ids lock")
            .iter()
            .any(|candidate| candidate == credential_id.as_str())
    }

    fn call_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.validations.load(Ordering::SeqCst),
            self.reads.load(Ordering::SeqCst),
            self.puts.load(Ordering::SeqCst),
            self.deletes.load(Ordering::SeqCst),
        )
    }
}

impl CredentialStore for FaultCredentialStore {
    fn validate(
        &self,
        credential_id: &CredentialId,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialPortError> {
        let attempt = self.validations.fetch_add(1, Ordering::SeqCst) + 1;
        if attempt == self.fail_validate_on.load(Ordering::SeqCst) {
            return Err(CredentialPortError::new("injected validation failure"));
        }
        if attempt == self.collide_validate_on.load(Ordering::SeqCst) {
            self.values
                .lock()
                .map_err(|_| CredentialPortError::new("fault store lock poisoned"))?
                .insert(
                    credential_id.as_str().to_string(),
                    format!("foreign:{}", secret.expose_secret()),
                );
        }
        Ok(())
    }

    fn put(
        &self,
        credential_id: &CredentialId,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialPortError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        if self.fail_put.swap(false, Ordering::SeqCst) {
            return Err(CredentialPortError::new("injected put failure"));
        }
        self.values
            .lock()
            .map_err(|_| CredentialPortError::new("fault store lock poisoned"))?
            .insert(
                credential_id.as_str().to_string(),
                secret.expose_secret().to_string(),
            );
        if self.write_then_fail_put.swap(false, Ordering::SeqCst) {
            return Err(CredentialPortError::new(
                "injected durable write with ambiguous failure",
            ));
        }
        Ok(())
    }

    fn get(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let value = self
            .values
            .lock()
            .map_err(|_| CredentialPortError::new("fault store lock poisoned"))?
            .get(credential_id.as_str())
            .cloned();
        if value.is_some() && self.fail_readback.swap(false, Ordering::SeqCst) {
            return Err(CredentialPortError::new("injected readback failure"));
        }
        if value.is_some() {
            let callback = self
                .after_verified
                .lock()
                .map_err(|_| CredentialPortError::new("verified callback lock poisoned"))?
                .take();
            if let Some(callback) = callback {
                callback(credential_id);
            }
        }
        value
            .map(CredentialSecret::new)
            .transpose()
            .map_err(|error| CredentialPortError::new(error.to_string()))
    }

    fn delete(&self, credential_id: &CredentialId) -> Result<(), CredentialPortError> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        if let Some(callback) = self
            .before_delete
            .lock()
            .map_err(|_| CredentialPortError::new("delete callback lock poisoned"))?
            .take()
        {
            callback(credential_id);
        }
        if self.fail_delete.load(Ordering::SeqCst) {
            return Err(CredentialPortError::new("injected delete failure"));
        }
        self.values
            .lock()
            .map_err(|_| CredentialPortError::new("fault store lock poisoned"))?
            .remove(credential_id.as_str());
        self.deleted_ids
            .lock()
            .map_err(|_| CredentialPortError::new("deleted ids lock poisoned"))?
            .push(credential_id.as_str().to_string());
        Ok(())
    }
}

#[derive(Default)]
struct PreflightMutatingCredentialStore {
    inner: FaultCredentialStore,
    before_validation: Mutex<Option<StoreCallback>>,
    validated_ids: Mutex<Vec<String>>,
    put_ids: Mutex<Vec<String>>,
}

impl PreflightMutatingCredentialStore {
    fn set_before_validation(&self, callback: impl FnOnce() + Send + 'static) {
        *self
            .before_validation
            .lock()
            .expect("preflight callback lock") = Some(Box::new(callback));
    }

    fn validated_ids(&self) -> Vec<String> {
        self.validated_ids
            .lock()
            .expect("validated ids lock")
            .clone()
    }

    fn put_ids(&self) -> Vec<String> {
        self.put_ids.lock().expect("put ids lock").clone()
    }

    fn clear_observed_ids(&self) {
        self.validated_ids
            .lock()
            .expect("validated ids lock")
            .clear();
        self.put_ids.lock().expect("put ids lock").clear();
    }
}

impl CredentialStore for PreflightMutatingCredentialStore {
    fn validate(
        &self,
        credential_id: &CredentialId,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialPortError> {
        if let Some(callback) = self
            .before_validation
            .lock()
            .map_err(|_| CredentialPortError::new("preflight callback lock poisoned"))?
            .take()
        {
            callback();
        }
        self.validated_ids
            .lock()
            .map_err(|_| CredentialPortError::new("validated ids lock poisoned"))?
            .push(credential_id.as_str().to_string());
        self.inner.validate(credential_id, secret)
    }

    fn put(
        &self,
        credential_id: &CredentialId,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialPortError> {
        self.put_ids
            .lock()
            .map_err(|_| CredentialPortError::new("put ids lock poisoned"))?
            .push(credential_id.as_str().to_string());
        self.inner.put(credential_id, secret)
    }

    fn get(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        self.inner.get(credential_id)
    }

    fn delete(&self, credential_id: &CredentialId) -> Result<(), CredentialPortError> {
        self.inner.delete(credential_id)
    }
}

fn client_id(name: &str) -> ClientId {
    ClientId::new(name).expect("valid test client id")
}

fn repository(temp: &TempDir) -> ConfigRepository {
    ConfigRepository::new(ClientPaths::new(temp.path()))
}

fn write_legacy(temp: &TempDir, contents: &str) -> Vec<u8> {
    let bytes = contents.as_bytes().to_vec();
    fs::write(temp.path().join("config.json"), &bytes).expect("write legacy fixture");
    bytes
}

fn initialize_empty(repo: &ConfigRepository) {
    repo.initialize(
        &client_id("test"),
        &MemoryCredentials::default(),
        &MemoryLegacyCredentials::default(),
    )
    .expect("initialize empty config");
}

fn locator(connection: &str, profile: &str, kind: CredentialKind) -> LegacyCredentialLocator {
    LegacyCredentialLocator {
        connection_name: connection.to_string(),
        profile_name: profile.to_string(),
        kind,
    }
}

fn canonical_config_bytes(config: &ConfigV2) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(config).expect("serialize canonical config");
    bytes.push(b'\n');
    bytes
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn add_test_connection(repo: &ConfigRepository) -> ConnectionId {
    let connection_id = ConnectionId::deterministic("main", "https://example.test");
    repo.upsert_connection(
        connection_id.clone(),
        ConnectionMetadata::new("main", "https://example.test"),
    )
    .expect("insert test connection");
    connection_id
}

fn add_bound_test_connection(repo: &ConfigRepository) -> ConnectionId {
    let connection_id = ConnectionId::deterministic("bound", "https://example.test/");
    let mut metadata = ConnectionMetadata::new("bound", "HTTPS://EXAMPLE.TEST:443");
    metadata.server_id = Some("server-1".to_string());
    metadata.server_fingerprint = Some("fingerprint-1".to_string());
    metadata.storage_id = Some("storage-1".to_string());
    repo.upsert_connection(connection_id.clone(), metadata)
        .expect("insert bound test connection");
    connection_id
}

fn master_key_binding_fixture(
    expected_master_key_fp: Option<&str>,
) -> (
    TempDir,
    ConfigRepository,
    ConnectionId,
    FaultCredentialStore,
) {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = ConnectionId::deterministic("binding", "https://binding.test/");
    let mut metadata = ConnectionMetadata::new("binding", "HTTPS://BINDING.TEST:443");
    metadata.server_id = Some("server-binding".to_string());
    metadata.server_fingerprint = Some("pin-binding".to_string());
    metadata.storage_id = Some("storage-binding".to_string());
    metadata.expected_master_key_fp = expected_master_key_fp.map(str::to_string);
    repo.upsert_connection(connection_id.clone(), metadata)
        .expect("insert binding connection");
    let store = FaultCredentialStore::default();
    repo.replace_credential_bundle(
        1,
        &connection_id,
        "profile",
        bundle(Some("access"), Some("refresh"), None)
            .with_access_expires_at(Some("2026-08-16T12:00:00Z".to_string())),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("insert binding profile");
    (temp, repo, connection_id, store)
}

fn rewrite_primary_json(
    repo: &ConfigRepository,
    update: impl FnOnce(&mut serde_json::Value),
) -> Vec<u8> {
    let path = repo.paths().config();
    let mut raw: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read config for rewrite"))
            .expect("parse config for rewrite");
    raw["revision"] = json!(raw["revision"].as_u64().expect("numeric revision") + 1);
    update(&mut raw);
    let config: ConfigV2 = serde_json::from_value(raw).expect("typed rewritten config");
    let bytes = canonical_config_bytes(&config);
    fs::write(&path, &bytes).expect("write rewritten config");
    bytes
}

fn assert_master_key_binding_anchor_conflict(
    expected_field: &'static str,
    prepare: impl FnOnce(&mut serde_json::Value, &ConnectionId),
    change: impl FnOnce(&mut serde_json::Value, &ConnectionId),
) {
    let (_temp, repo, connection_id, store) = master_key_binding_fixture(None);
    rewrite_primary_json(&repo, |raw| prepare(raw, &connection_id));
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "profile")
        .expect("binding anchor");
    rewrite_primary_json(&repo, |raw| change(raw, &connection_id));
    let primary_before = fs::read(repo.paths().config()).expect("primary before conflict");
    let backup_before = fs::read(repo.paths().backup()).expect("backup before conflict");
    let calls_before = store.call_counts();
    assert!(matches!(
        repo.bind_expected_master_key_fingerprint_if_profile_matches(&anchor, "0123456789ab")
            .expect_err("binding-relevant change must conflict"),
        ConfigError::CredentialProfileAnchorConflict { field, .. } if field == expected_field
    ));
    assert_eq!(
        fs::read(repo.paths().config()).expect("primary"),
        primary_before
    );
    assert_eq!(
        fs::read(repo.paths().backup()).expect("backup"),
        backup_before
    );
    assert_eq!(store.call_counts(), calls_before);
}

fn bundle(access: Option<&str>, refresh: Option<&str>, service: Option<&str>) -> CredentialBundle {
    CredentialBundle::new(
        access.map(|value| CredentialSecret::new(value).expect("access secret")),
        refresh.map(|value| CredentialSecret::new(value).expect("refresh secret")),
        service.map(|value| CredentialSecret::new(value).expect("service secret")),
    )
}

fn profile_credentials(
    config: &ConfigV2,
    connection_id: &ConnectionId,
    profile_name: &str,
) -> BTreeMap<CredentialKind, CredentialId> {
    config
        .connections
        .get(connection_id)
        .expect("connection")
        .credential_profiles()
        .get(profile_name)
        .expect("credential profile")
        .credentials()
        .clone()
}

struct PreparedRestore {
    _temp: TempDir,
    repo: ConfigRepository,
    source_primary: Vec<u8>,
    source_backup: Vec<u8>,
    target_primary: ConfigV2,
    target_backup: ConfigV2,
    target_primary_bytes: Vec<u8>,
    target_backup_bytes: Vec<u8>,
    journal: Vec<u8>,
}

fn prepared_restore() -> PreparedRestore {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = ConnectionId::deterministic("restore", "https://restore.test");
    repo.upsert_connection(
        connection_id.clone(),
        ConnectionMetadata::new("restore", "https://restore.test"),
    )
    .expect("revision one");
    repo.update_connection(&connection_id, |metadata| {
        metadata.name = "restore renamed".to_string();
        Ok(())
    })
    .expect("revision two");

    let source_primary = fs::read(repo.paths().config()).expect("source primary");
    let source_backup = fs::read(repo.paths().backup()).expect("source backup");
    let target_backup: ConfigV2 =
        serde_json::from_slice(&source_primary).expect("target backup config");
    let mut target_primary: ConfigV2 =
        serde_json::from_slice(&source_backup).expect("target primary config");
    target_primary.revision = target_backup.revision.max(target_primary.revision) + 1;
    let target_primary_bytes = canonical_config_bytes(&target_primary);
    let target_backup_bytes = canonical_config_bytes(&target_backup);
    let journal = serde_json::to_vec_pretty(&json!({
        "journal_version": 1,
        "source_primary_digest": digest(&source_primary),
        "source_backup_digest": digest(&source_backup),
        "target_primary": target_primary.clone(),
        "target_backup": target_backup.clone(),
    }))
    .expect("restore journal");

    PreparedRestore {
        _temp: temp,
        repo,
        source_primary,
        source_backup,
        target_primary,
        target_backup,
        target_primary_bytes,
        target_backup_bytes,
        journal,
    }
}

#[test]
fn creates_an_empty_v2_without_implicit_paths() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    let snapshot = repo
        .initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect("initialize");

    assert_eq!(snapshot.config().schema_version, 2);
    assert_eq!(snapshot.revision(), 0);
    assert!(snapshot.config().connections.is_empty());
    let migration = snapshot.config().migration.as_ref().expect("absence guard");
    assert_eq!(migration.source_format, "legacy-v1");
    assert!(migration.claimed_clients.contains(&client_id("cli")));
    assert!(repo.paths().config().exists());
    assert!(repo.paths().lock().exists());
    assert!(!repo.paths().backup().exists());
    assert_eq!(repo.paths().local_db(), temp.path().join("local.sqlite"));
    assert_eq!(
        repo.paths().desktop_settings(),
        temp.path().join("desktop.json")
    );
    assert_eq!(
        repo.paths().remembered_unlock(),
        temp.path().join("unlock.json")
    );
    assert_eq!(
        ClientPaths::with_local_db(temp.path(), temp.path().join("custom.sqlite")).local_db(),
        temp.path().join("custom.sqlite")
    );
}

#[test]
fn empty_initialization_guards_against_late_legacy_writers() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    let initialized = repo
        .initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect("initialize without legacy files");
    let before = fs::read(repo.paths().config()).expect("initial primary");

    write_legacy(&temp, r#"{"contexts":{}}"#);
    assert!(matches!(
        repo.snapshot()
            .expect_err("late legacy writer must diverge"),
        ConfigError::LegacyDiverged { .. }
    ));
    assert!(matches!(
        repo.upsert_connection(
            ConnectionId::deterministic("late", "https://late.test"),
            ConnectionMetadata::new("late", "https://late.test"),
        )
        .expect_err("mutation must also reject late legacy writer"),
        ConfigError::LegacyDiverged { .. }
    ));
    assert_eq!(
        fs::read(repo.paths().config()).expect("unchanged primary"),
        before
    );
    assert_eq!(initialized.revision(), 0);
}

#[test]
fn migrates_nullable_identity_and_keeps_legacy_bytes_unchanged() {
    let temp = TempDir::new().expect("tempdir");
    let original = write_legacy(&temp, NULLABLE_IDENTITY_V1);
    let repo = repository(&temp);
    let snapshot = repo
        .initialize(
            &client_id("cosmic"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect("migrate");

    let identity = snapshot.config().identity.as_ref().expect("identity");
    assert_eq!(identity.email, None);
    assert_eq!(identity.salt_fingerprint, None);
    assert_eq!(
        fs::read(repo.paths().legacy_config()).expect("read legacy"),
        original
    );
    assert!(snapshot.config().migration.is_some());
}

#[test]
fn migrates_inline_secrets_and_never_publishes_them() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{
          "current_context":"main",
          "contexts":{"main":{"addr":"https://example.test","tokens":{"login":{
            "access_token":"inline-access",
            "refresh_token":"inline-refresh",
            "service_account_token":"inline-service",
            "access_expires_at":"2030-01-01T00:00:00Z"
          }},"current_token":"login"}}
        }"#,
    );
    let store = MemoryCredentials::default();
    let repo = repository(&temp);
    let snapshot = repo
        .initialize(
            &client_id("desktop"),
            &store,
            &MemoryLegacyCredentials::default(),
        )
        .expect("migrate inline secrets");

    let connection = snapshot
        .config()
        .connections
        .values()
        .next()
        .expect("connection");
    let profile = connection
        .credential_profiles()
        .get("login")
        .expect("profile");
    assert_eq!(profile.credentials().len(), 3);
    assert_eq!(
        store.value(&profile.credentials()[&CredentialKind::Access]),
        Some("inline-access".to_string())
    );
    let canonical = fs::read_to_string(repo.paths().config()).expect("canonical config");
    for forbidden in [
        "inline-access",
        "inline-refresh",
        "inline-service",
        "access_token",
        "refresh_token",
        "service_account_token",
    ] {
        assert!(!canonical.contains(forbidden), "leaked {forbidden}");
    }
}

#[test]
fn migrated_credentials_are_repository_bound_in_a_shared_store() {
    let legacy = r#"{
      "current_context":"main",
      "contexts":{"main":{"addr":"https://example.test","tokens":{"login":{
        "access_token":"shared-inline-secret"
      }},"current_token":"login"}}
    }"#;
    let first_root = TempDir::new().expect("first tempdir");
    let second_root = TempDir::new().expect("second tempdir");
    write_legacy(&first_root, legacy);
    write_legacy(&second_root, legacy);
    let first_repo = repository(&first_root);
    let second_repo = repository(&second_root);
    let store = MemoryCredentials::default();

    let first = first_repo
        .initialize(
            &client_id("cli"),
            &store,
            &MemoryLegacyCredentials::default(),
        )
        .expect("migrate first repository");
    let second = second_repo
        .initialize(
            &client_id("cli"),
            &store,
            &MemoryLegacyCredentials::default(),
        )
        .expect("migrate second repository");
    let connection_id = ConnectionId::deterministic("main", "https://example.test");
    let first_id = profile_credentials(first.config(), &connection_id, "login")
        [&CredentialKind::Access]
        .clone();
    let second_id = profile_credentials(second.config(), &connection_id, "login")
        [&CredentialKind::Access]
        .clone();
    assert_ne!(first_id, second_id);
    assert_eq!(
        store.value(&first_id).as_deref(),
        Some("shared-inline-secret")
    );
    assert_eq!(
        store.value(&second_id).as_deref(),
        Some("shared-inline-secret")
    );

    first_repo
        .replace_credential_bundle(
            first.revision(),
            &connection_id,
            "login",
            bundle(Some("first-root-rotated"), None, None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect("rotate only first repository");
    first_repo
        .update_connection(&connection_id, |metadata| {
            metadata.name = "rotate first backup".to_string();
            Ok(())
        })
        .expect("drop first repository legacy generation");
    first_repo
        .reconcile_credentials(&store)
        .expect("settle first repository credentials");

    assert_eq!(store.value(&first_id), None);
    assert_eq!(
        store.value(&second_id).as_deref(),
        Some("shared-inline-secret")
    );
    assert_eq!(
        second_repo
            .snapshot()
            .expect("second remains valid")
            .revision(),
        0
    );
}

#[test]
fn typed_profile_identifiers_may_contain_token_words() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{"main":{"addr":"https://example.test","tokens":{"prod-token":{"access_token":"secret"}},"current_token":"prod-token"}}}"#,
    );
    let repo = repository(&temp);
    let snapshot = repo
        .initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect("typed token-like profile name");
    assert!(snapshot
        .config()
        .connections
        .values()
        .next()
        .expect("connection")
        .credential_profiles()
        .contains_key("prod-token"));
}

#[test]
fn migrates_cli_keyring_source_and_namespaces_vaults() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(&temp, CLI_KEYRING_V1);
    let source = MemoryLegacyCredentials::default()
        .with(
            locator("cli", "manual", CredentialKind::Access),
            "keyring-access",
        )
        .with(
            locator("cli", "manual", CredentialKind::ServiceAccount),
            "keyring-service",
        );
    let store = MemoryCredentials::default();
    let repo = repository(&temp);
    let snapshot = repo
        .initialize(&client_id("cli"), &store, &source)
        .expect("migrate keyring config");

    let (connection_id, connection) = snapshot
        .config()
        .connections
        .first_key_value()
        .expect("connection");
    let profile = &connection.credential_profiles()["manual"];
    assert_eq!(profile.credentials().len(), 2);
    assert_eq!(
        store.value(&profile.credentials()[&CredentialKind::Access]),
        Some("keyring-access".to_string())
    );
    let ClientNamespace::CliV1(cli_namespace) =
        snapshot.config().clients[&client_id("cli")].namespace()
    else {
        panic!("CLI namespace schema");
    };
    assert_eq!(
        cli_namespace.default_vault_by_connection[connection_id],
        "vault-cli"
    );
}

#[test]
fn refuses_a_dangling_cli_profile_without_a_credential_source() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(&temp, CLI_KEYRING_V1);
    let repo = repository(&temp);
    let error = repo
        .initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect_err("missing keyring credential must fail");

    assert!(matches!(error, ConfigError::MissingCredential { .. }));
    assert!(!repo.paths().config().exists());
}

#[test]
fn migrates_registered_namespaces_and_defers_unknown_legacy_values() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{
          "storage":{
            "backup_dir":"/safe",
            "backup_retention_days":30,
            "future_storage":{"payload":"must-not-copy"}
          },
          "future_top":{"payload":"raw-token"}
        }"#,
    );
    let repo = repository(&temp);
    let snapshot = repo
        .initialize(
            &client_id("cosmic"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect("migrate storage");

    let ClientNamespace::DesktopV1(desktop) =
        snapshot.config().clients[&client_id("desktop")].namespace()
    else {
        panic!("desktop namespace schema");
    };
    let backup = desktop.backup.as_ref().expect("migrated backup settings");
    assert_eq!(backup.backup_dir.as_deref(), Some("/safe"));
    assert_eq!(backup.backup_retention_days, Some(30));
    let deferred = &snapshot
        .config()
        .migration
        .as_ref()
        .expect("migration stamp")
        .deferred_legacy_fields;
    assert!(deferred.contains("$.future_top"));
    assert!(deferred.contains("$.storage.future_storage"));
    let canonical = fs::read_to_string(repo.paths().config()).expect("canonical config");
    assert!(!canonical.contains("raw-token"));
    assert!(!canonical.contains("must-not-copy"));
}

#[test]
fn conflicting_inline_and_external_secret_never_publishes() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{"main":{"addr":"https://example.test","tokens":{"p":{"access_token":"inline"}}}}}"#,
    );
    let source = MemoryLegacyCredentials::default()
        .with(locator("main", "p", CredentialKind::Access), "external");
    let repo = repository(&temp);
    let error = repo
        .initialize(&client_id("cli"), &MemoryCredentials::default(), &source)
        .expect_err("conflict");

    assert!(matches!(error, ConfigError::CredentialConflict { .. }));
    assert!(!repo.paths().config().exists());
}

#[test]
fn malformed_or_unknown_credential_legacy_never_publishes() {
    for contents in [
        MALFORMED_V1,
        r#"{"contexts":{"main":{"addr":"https://example.test","tokens":{"p":{"access_token":"inline","note":"unknown credential-adjacent data"}}}}}"#,
    ] {
        let temp = TempDir::new().expect("tempdir");
        write_legacy(&temp, contents);
        let repo = repository(&temp);
        let error = repo
            .initialize(
                &client_id("test"),
                &MemoryCredentials::default(),
                &MemoryLegacyCredentials::default(),
            )
            .expect_err("unsafe input");
        assert!(matches!(
            error,
            ConfigError::Malformed { .. } | ConfigError::UnknownLegacyCredentialField { .. }
        ));
        assert!(!repo.paths().config().exists());
    }
}

#[test]
fn credential_failure_is_safely_retryable_with_deterministic_ids() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{"main":{"addr":"https://example.test","tokens":{"p":{
          "access_token":"access","refresh_token":"refresh"
        }}}}}"#,
    );
    let store = MemoryCredentials::fail_once_on(2);
    let repo = repository(&temp);
    let first_error = repo
        .initialize(
            &client_id("desktop"),
            &store,
            &MemoryLegacyCredentials::default(),
        )
        .expect_err("injected failure");
    assert!(matches!(first_error, ConfigError::CredentialStore { .. }));
    assert!(!repo.paths().config().exists());

    let snapshot = repo
        .initialize(
            &client_id("desktop"),
            &store,
            &MemoryLegacyCredentials::default(),
        )
        .expect("retry migration");
    let profile = &snapshot
        .config()
        .connections
        .values()
        .next()
        .expect("connection")
        .credential_profiles()["p"];
    let access_id = &profile.credentials()[&CredentialKind::Access];
    assert_eq!(store.write_count(access_id), 1);
    assert_eq!(store.value(access_id), Some("access".to_string()));
}

#[test]
fn future_schema_is_never_downgraded_or_recovered_from_legacy() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(&temp, EMPTY_V1);
    let repo = repository(&temp);
    fs::write(
        repo.paths().config(),
        r#"{"schema_version":99,"revision":1,"connections":{},"clients":{}}"#,
    )
    .expect("write future config");

    let error = repo.snapshot().expect_err("future config");
    assert!(matches!(error, ConfigError::FutureSchema { found: 99, .. }));
}

#[test]
fn sequential_and_concurrent_mutations_have_monotonic_revisions() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let first_id = ConnectionId::deterministic("first", "https://first.test");
    assert_eq!(
        repo.upsert_connection(
            first_id.clone(),
            ConnectionMetadata::new("first", "https://first.test"),
        )
        .expect("upsert")
        .revision(),
        1
    );
    let stale = repo
        .update_connection_if_revision(0, &first_id, |connection| {
            connection.address = "https://stale.test".to_string();
            Ok(())
        })
        .expect_err("stale snapshot must not overwrite the latest revision");
    assert!(matches!(
        stale,
        ConfigError::RevisionConflict {
            expected: 0,
            actual: 1
        }
    ));
    assert_eq!(repo.snapshot().expect("snapshot").revision(), 1);
    assert_eq!(
        repo.set_active_connection(&client_id("cli"), Some(first_id.clone()))
            .expect("set active")
            .revision(),
        2
    );
    assert_eq!(
        repo.set_cli_default_vault(&first_id, "default".to_string())
            .expect("CLI vault")
            .revision(),
        3
    );

    let workers = 8;
    let barrier = Arc::new(Barrier::new(workers));
    let mut threads = Vec::new();
    for index in 0..workers {
        let barrier = Arc::clone(&barrier);
        let paths = repo.paths().clone();
        threads.push(thread::spawn(move || {
            barrier.wait();
            let name = format!("concurrent-{index}");
            let address = format!("https://{index}.test");
            ConfigRepository::new(paths)
                .upsert_connection(
                    ConnectionId::deterministic(&name, &address),
                    ConnectionMetadata::new(name, address),
                )
                .expect("concurrent upsert");
        }));
    }
    for worker in threads {
        worker.join().expect("worker join");
    }

    let snapshot = repo.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision(), 3 + workers as u64);
    assert_eq!(snapshot.config().connections.len(), workers + 1);
}

#[test]
fn restores_only_a_valid_v2_backup_and_advances_revision() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = ConnectionId::deterministic("main", "https://example.test");
    repo.upsert_connection(
        connection_id.clone(),
        ConnectionMetadata::new("main", "https://example.test"),
    )
    .expect("upsert");
    repo.update_connection(&connection_id, |connection| {
        connection.name = "changed display name".to_string();
        Ok(())
    })
    .expect("update");
    fs::write(repo.paths().config(), "{corrupt").expect("corrupt primary");

    let restored = repo.restore_backup().expect("restore backup");
    assert_eq!(restored.revision(), 3);
    assert_eq!(
        restored.config().connections[&connection_id]
            .metadata()
            .address,
        "https://example.test"
    );
    let stale = repo
        .upsert_connection_if_revision(
            2,
            ConnectionId::deterministic("stale", "https://stale.test"),
            ConnectionMetadata::new("stale", "https://stale.test"),
        )
        .expect_err("pre-recovery revision must never become current again");
    assert!(matches!(
        stale,
        ConfigError::RevisionConflict {
            expected: 2,
            actual: 3
        }
    ));
}

#[test]
fn changed_legacy_source_is_reported_after_migration() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(&temp, NULLABLE_IDENTITY_V1);
    let repo = repository(&temp);
    repo.initialize(
        &client_id("cosmic"),
        &MemoryCredentials::default(),
        &MemoryLegacyCredentials::default(),
    )
    .expect("migrate");
    fs::write(repo.paths().legacy_config(), EMPTY_V1).expect("change legacy");

    let error = repo.snapshot().expect_err("legacy divergence");
    assert!(matches!(error, ConfigError::LegacyDiverged { .. }));
}

#[test]
fn known_hosts_trust_conflict_never_publishes() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{"main":{"addr":"https://example.test/","server_fingerprint":"sha256:config"}}}"#,
    );
    fs::write(
        temp.path().join("known_hosts.json"),
        r#"{"https://example.test":"sha256:known-hosts"}"#,
    )
    .expect("known hosts");
    let repo = repository(&temp);
    let error = repo
        .initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect_err("trust conflict");

    assert!(matches!(error, ConfigError::TrustConflict { .. }));
    assert!(!repo.paths().config().exists());
}

#[test]
fn missing_primary_with_backup_requires_explicit_recovery_and_skips_aba_revision() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    repo.upsert_connection(
        ConnectionId::deterministic("lost", "https://lost.test"),
        ConnectionMetadata::new("lost", "https://lost.test"),
    )
    .expect("revision one");
    fs::remove_file(repo.paths().config()).expect("remove primary");

    let error = repo
        .initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect_err("backup requires explicit recovery");
    assert!(matches!(
        error,
        ConfigError::RecoveryRequired { revision: 0, .. }
    ));
    assert!(!repo.paths().config().exists());

    let restored = repo.restore_backup().expect("explicit restore");
    assert_eq!(restored.revision(), 2);
    let stale = repo
        .upsert_connection_if_revision(
            1,
            ConnectionId::deterministic("stale", "https://stale.test"),
            ConnectionMetadata::new("stale", "https://stale.test"),
        )
        .expect_err("lost revision must not be reused");
    assert!(matches!(
        stale,
        ConfigError::RevisionConflict {
            expected: 1,
            actual: 2
        }
    ));
}

#[test]
fn missing_primary_propagates_malformed_and_future_backup_errors() {
    for (contents, future) in [
        ("{broken", false),
        (
            r#"{"schema_version":99,"revision":7,"connections":{},"clients":{}}"#,
            true,
        ),
    ] {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        fs::create_dir_all(temp.path()).expect("config root");
        fs::write(repo.paths().backup(), contents).expect("write backup");
        let error = repo
            .initialize(
                &client_id("cli"),
                &MemoryCredentials::default(),
                &MemoryLegacyCredentials::default(),
            )
            .expect_err("invalid backup must propagate");
        if future {
            assert!(matches!(error, ConfigError::FutureSchema { found: 99, .. }));
        } else {
            assert!(matches!(error, ConfigError::Malformed { .. }));
        }
        assert!(!repo.paths().config().exists());
    }
}

#[test]
fn changed_legacy_during_credential_write_retries_with_a_new_credential_id() {
    let temp = TempDir::new().expect("tempdir");
    let initial = r#"{"contexts":{"main":{"addr":"https://example.test","tokens":{"p":{"access_token":"old-secret"}}}}}"#;
    let replacement = r#"{"contexts":{"main":{"addr":"https://example.test","tokens":{"p":{"access_token":"new-secret"}}}}}"#;
    write_legacy(&temp, initial);
    let store = MutatingCredentials::new(temp.path().join("config.json"), replacement);
    let repo = repository(&temp);

    let error = repo
        .initialize(
            &client_id("desktop"),
            &store,
            &MemoryLegacyCredentials::default(),
        )
        .expect_err("legacy changed during credential write");
    assert!(matches!(error, ConfigError::LegacyDiverged { .. }));
    assert!(!repo.paths().config().exists());

    let snapshot = repo
        .initialize(
            &client_id("desktop"),
            &store,
            &MemoryLegacyCredentials::default(),
        )
        .expect("retry changed legacy");
    let ids = store.ids();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
    let published_id = &snapshot
        .config()
        .connections
        .values()
        .next()
        .expect("connection")
        .credential_profiles()["p"]
        .credentials()[&CredentialKind::Access];
    assert_eq!(published_id, &ids[1]);
    assert_eq!(
        store.inner.value(published_id),
        Some("new-secret".to_string())
    );
}

#[test]
fn existing_migration_is_claimed_atomically_by_each_client_without_credentials() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"current_context":"main","contexts":{"main":{"addr":"https://example.test","tokens":{"p":{"access_token":"access"}},"current_token":"p"}}}"#,
    );
    let repo = repository(&temp);
    let first = repo
        .initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect("first migration");
    assert_eq!(first.revision(), 0);
    assert!(first
        .config()
        .migration
        .as_ref()
        .expect("migration")
        .claimed_clients
        .contains(&client_id("cli")));
    let main_id = first.config().clients[&client_id("cli")]
        .active_connection()
        .cloned()
        .expect("main active");

    let other_id = ConnectionId::deterministic("other", "https://other.test");
    repo.upsert_connection(
        other_id.clone(),
        ConnectionMetadata::new("other", "https://other.test"),
    )
    .expect("other connection");
    repo.set_active_connection(&client_id("desktop"), Some(other_id.clone()))
        .expect("pre-existing desktop choice");
    let desktop = repo
        .initialize(
            &client_id("desktop"),
            &PanicCredentialPorts,
            &PanicCredentialPorts,
        )
        .expect("claim desktop");
    assert_eq!(desktop.revision(), 3);
    assert_eq!(
        desktop.config().clients[&client_id("desktop")].active_connection(),
        Some(&other_id)
    );

    let clients = ["cosmic", "tauri"];
    let barrier = Arc::new(Barrier::new(clients.len()));
    let mut workers = Vec::new();
    for name in clients {
        let barrier = Arc::clone(&barrier);
        let paths = repo.paths().clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            ConfigRepository::new(paths)
                .initialize(
                    &client_id(name),
                    &PanicCredentialPorts,
                    &PanicCredentialPorts,
                )
                .expect("concurrent client claim");
        }));
    }
    for worker in workers {
        worker.join().expect("claim worker");
    }
    let claimed = repo.snapshot().expect("claimed snapshot");
    assert_eq!(claimed.revision(), 5);
    let migration = claimed.config().migration.as_ref().expect("migration");
    for name in ["cli", "desktop", "cosmic", "tauri"] {
        assert!(migration.claimed_clients.contains(&client_id(name)));
    }
    assert_eq!(
        claimed.config().clients[&client_id("cosmic")].active_connection(),
        Some(&main_id)
    );
    let repeated = repo
        .initialize(
            &client_id("cosmic"),
            &PanicCredentialPorts,
            &PanicCredentialPorts,
        )
        .expect("idempotent repeated claim");
    assert_eq!(repeated.revision(), 5);
}

#[test]
fn later_client_claim_uses_immutable_legacy_connection_id_after_renames() {
    let temp = TempDir::new().expect("tempdir");
    let legacy_address = "https://example.test";
    write_legacy(
        &temp,
        r#"{"current_context":"main","contexts":{"main":{"addr":"https://example.test","tokens":{"p":{"access_token":"access"}},"current_token":"p"}}}"#,
    );
    let repo = repository(&temp);
    let first = repo
        .initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect("initial migration");
    let main_id = ConnectionId::deterministic("main", legacy_address);
    assert_eq!(
        first.config().clients[&client_id("cli")].active_connection(),
        Some(&main_id)
    );

    repo.update_connection(&main_id, |metadata| {
        metadata.name = "duplicate display".to_string();
        Ok(())
    })
    .expect("rename migrated connection");
    let duplicate_id = ConnectionId::deterministic("other", "https://other.test");
    repo.upsert_connection(
        duplicate_id,
        ConnectionMetadata::new("duplicate display", "https://other.test"),
    )
    .expect("duplicate display name is harmless");

    let desktop = repo
        .initialize(
            &client_id("desktop"),
            &PanicCredentialPorts,
            &PanicCredentialPorts,
        )
        .expect("claim desktop from immutable legacy identity");
    assert_eq!(
        desktop.config().clients[&client_id("desktop")].active_connection(),
        Some(&main_id)
    );
}

#[test]
fn structural_legacy_errors_are_preflighted_before_any_credential_put() {
    for contents in [
        r#"{"current_context":"missing","contexts":{"main":{"addr":"https://example.test","tokens":{"p":{"access_token":"secret"}}}}}"#,
        r#"{"contexts":{"main":{"addr":"https://example.test","tokens":{"p":{"access_token":"secret"}},"current_token":"missing"}}}"#,
        r#"{"contexts":{"main":{"addr":"https://example.test","tokens":{"first":{"access_token":"secret"},"missing":{}}}}}"#,
    ] {
        let temp = TempDir::new().expect("tempdir");
        write_legacy(&temp, contents);
        let store = MemoryCredentials::default();
        let repo = repository(&temp);
        let error = repo
            .initialize(
                &client_id("cli"),
                &store,
                &MemoryLegacyCredentials::default(),
            )
            .expect_err("invalid legacy structure");
        assert!(matches!(
            error,
            ConfigError::InvalidConfig { .. } | ConfigError::MissingCredential { .. }
        ));
        assert_eq!(store.len(), 0);
        assert!(!repo.paths().config().exists());
    }
}

#[test]
fn unmatched_known_host_identifiers_are_typed_not_scanned_as_secret_keys() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(&temp, EMPTY_V1);
    fs::write(
        temp.path().join("known_hosts.json"),
        r#"{"https://prod-token":"sha256:fingerprint"}"#,
    )
    .expect("known hosts");
    let repo = repository(&temp);
    let snapshot = repo
        .initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect("migrate unmatched known host");
    assert_eq!(
        snapshot.config().legacy_known_hosts["https://prod-token"],
        "sha256:fingerprint"
    );
}

#[test]
fn restore_with_valid_primary_rotates_a_reversible_predecessor() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = ConnectionId::deterministic("main", "https://one.test");
    repo.upsert_connection(
        connection_id.clone(),
        ConnectionMetadata::new("main", "https://one.test"),
    )
    .expect("revision one");
    repo.update_connection(&connection_id, |connection| {
        connection.name = "renamed".to_string();
        Ok(())
    })
    .expect("revision two");

    let rolled_back = repo
        .restore_backup()
        .expect("rollback to revision one data");
    assert_eq!(rolled_back.revision(), 3);
    assert_eq!(
        rolled_back.config().connections[&connection_id]
            .metadata()
            .name,
        "main"
    );
    let rolled_forward = repo
        .restore_backup()
        .expect("toggle back to revision two data");
    assert_eq!(rolled_forward.revision(), 4);
    assert_eq!(
        rolled_forward.config().connections[&connection_id]
            .metadata()
            .name,
        "renamed"
    );
}

#[cfg(unix)]
#[test]
fn unix_config_paths_are_private_and_reject_symlinks_or_non_regular_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = TempDir::new().expect("tempdir");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).expect("loosen root");
    let repo = repository(&temp);
    initialize_empty(&repo);
    assert_eq!(
        fs::metadata(temp.path())
            .expect("root metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(repo.paths().lock())
            .expect("lock metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let target = temp.path().join("target.json");
    fs::write(&target, "{}").expect("target");
    fs::remove_file(repo.paths().config()).expect("remove primary");
    symlink(&target, repo.paths().config()).expect("primary symlink");
    assert!(matches!(
        repo.snapshot().expect_err("primary symlink"),
        ConfigError::UnsafePath { .. }
    ));

    let backup_temp = TempDir::new().expect("backup tempdir");
    let backup_repo = repository(&backup_temp);
    fs::write(backup_temp.path().join("target.json"), "{}").expect("backup target");
    symlink(
        backup_temp.path().join("target.json"),
        backup_repo.paths().backup(),
    )
    .expect("backup symlink");
    assert!(matches!(
        backup_repo
            .initialize(
                &client_id("cli"),
                &MemoryCredentials::default(),
                &MemoryLegacyCredentials::default(),
            )
            .expect_err("backup symlink"),
        ConfigError::UnsafePath { .. }
    ));

    let lock_temp = TempDir::new().expect("lock tempdir");
    let lock_repo = repository(&lock_temp);
    fs::write(lock_temp.path().join("target.lock"), "").expect("lock target");
    symlink(
        lock_temp.path().join("target.lock"),
        lock_repo.paths().lock(),
    )
    .expect("lock symlink");
    assert!(matches!(
        lock_repo
            .initialize(
                &client_id("cli"),
                &MemoryCredentials::default(),
                &MemoryLegacyCredentials::default(),
            )
            .expect_err("lock symlink"),
        ConfigError::UnsafePath { .. }
    ));

    let journal_temp = TempDir::new().expect("journal tempdir");
    let journal_repo = repository(&journal_temp);
    fs::write(journal_temp.path().join("target-journal.json"), "{}").expect("journal target");
    symlink(
        journal_temp.path().join("target-journal.json"),
        journal_repo.paths().restore_journal(),
    )
    .expect("journal symlink");
    assert!(matches!(
        journal_repo
            .initialize(
                &client_id("cli"),
                &MemoryCredentials::default(),
                &MemoryLegacyCredentials::default(),
            )
            .expect_err("journal symlink"),
        ConfigError::UnsafePath { .. }
    ));

    let directory_temp = TempDir::new().expect("directory tempdir");
    let directory_repo = repository(&directory_temp);
    fs::create_dir(directory_repo.paths().config()).expect("primary directory");
    assert!(matches!(
        directory_repo.snapshot().expect_err("primary directory"),
        ConfigError::UnsafePath { .. }
    ));
}

#[test]
fn canonical_v2_rejects_unknown_fields_at_every_registered_boundary() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let mut top: serde_json::Value =
        serde_json::from_slice(&fs::read(repo.paths().config()).expect("read primary"))
            .expect("parse primary");
    top.as_object_mut()
        .expect("top object")
        .insert("future_top".to_string(), json!({"payload":"raw-token"}));
    fs::write(
        repo.paths().config(),
        serde_json::to_vec(&top).expect("serialize unknown top field"),
    )
    .expect("write unknown top field");
    assert!(matches!(
        repo.snapshot().expect_err("unknown top field"),
        ConfigError::Malformed { .. }
    ));

    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = ConnectionId::deterministic("strict", "https://strict.test");
    repo.upsert_connection(
        connection_id.clone(),
        ConnectionMetadata::new("strict", "https://strict.test"),
    )
    .expect("upsert");
    let mut nested: serde_json::Value =
        serde_json::from_slice(&fs::read(repo.paths().config()).expect("read primary"))
            .expect("parse primary");
    nested["connections"][connection_id.as_str()]["metadata"]
        .as_object_mut()
        .expect("metadata object")
        .insert("future_field".to_string(), json!(true));
    fs::write(
        repo.paths().config(),
        serde_json::to_vec(&nested).expect("serialize nested unknown"),
    )
    .expect("write nested unknown");
    assert!(matches!(
        repo.snapshot().expect_err("unknown metadata field"),
        ConfigError::Malformed { .. }
    ));

    let temp = TempDir::new().expect("tempdir");
    write_legacy(&temp, NULLABLE_IDENTITY_V1);
    let repo = repository(&temp);
    repo.initialize(
        &client_id("cli"),
        &MemoryCredentials::default(),
        &MemoryLegacyCredentials::default(),
    )
    .expect("migrate identity");
    let mut kdf: serde_json::Value =
        serde_json::from_slice(&fs::read(repo.paths().config()).expect("read primary"))
            .expect("parse primary");
    kdf["identity"]["kdf_params"]
        .as_object_mut()
        .expect("KDF object")
        .insert("future_field".to_string(), json!(1));
    fs::write(
        repo.paths().config(),
        serde_json::to_vec(&kdf).expect("serialize unknown KDF field"),
    )
    .expect("write unknown KDF field");
    assert!(matches!(
        repo.snapshot().expect_err("unknown KDF field"),
        ConfigError::Malformed { .. }
    ));

    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    fs::write(
        repo.paths().config(),
        r#"{"schema_version":2,"revision":0,"connections":{},"clients":{"cli":{"namespace":{"kind":"desktop_v1","settings":{}}}}}"#,
    )
    .expect("write mismatched namespace");
    assert!(matches!(
        repo.snapshot().expect_err("mismatched client namespace"),
        ConfigError::InvalidConfig { .. }
    ));
}

#[test]
fn typed_namespace_patches_preserve_other_registered_settings() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let first = ConnectionId::deterministic("first", "https://first.test");
    let second = ConnectionId::deterministic("second", "https://second.test");
    repo.upsert_connection(
        first.clone(),
        ConnectionMetadata::new("first", "https://first.test"),
    )
    .expect("first connection");
    repo.upsert_connection(
        second.clone(),
        ConnectionMetadata::new("second", "https://second.test"),
    )
    .expect("second connection");
    repo.set_cli_default_vault(&first, "vault-one".to_string())
        .expect("first vault");
    repo.set_cli_default_vault(&second, "vault-two".to_string())
        .expect("second vault");
    repo.remove_cli_default_vault(&first)
        .expect("remove first vault");
    repo.set_desktop_backup_settings(Some(DesktopBackupSettings {
        backup_dir: Some("/backup/one".to_string()),
        backup_retention_days: Some(7),
        backup_max_count: Some(3),
    }))
    .expect("desktop backup");
    let snapshot = repo.snapshot().expect("snapshot");
    let ClientNamespace::CliV1(cli) = snapshot.config().clients[&client_id("cli")].namespace()
    else {
        panic!("CLI schema");
    };
    assert!(!cli.default_vault_by_connection.contains_key(&first));
    assert_eq!(cli.default_vault_by_connection[&second], "vault-two");
    let ClientNamespace::DesktopV1(desktop) =
        snapshot.config().clients[&client_id("desktop")].namespace()
    else {
        panic!("desktop schema");
    };
    assert_eq!(
        desktop
            .backup
            .as_ref()
            .expect("backup")
            .backup_retention_days,
        Some(7)
    );
}

#[test]
fn arbitrary_nonmigration_credential_references_are_rejected() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    let connection_id = ConnectionId::deterministic("raw", "https://raw.test");
    let credential_id = format!("cred_{}", "a".repeat(64));
    fs::write(
        repo.paths().config(),
        format!(
            r#"{{"schema_version":2,"revision":0,"connections":{{"{connection_id}":{{"metadata":{{"name":"raw","address":"https://raw.test"}},"credential_profiles":{{"profile":{{"credentials":{{"access":"{credential_id}"}}}}}},"active_credential":"profile"}}}},"clients":{{}},"legacy_known_hosts":{{}}}}"#
        ),
    )
    .expect("write raw config");
    assert!(matches!(
        repo.snapshot()
            .expect_err("unverified credential reference"),
        ConfigError::InvalidConfig { .. }
    ));

    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    let missing = ConnectionId::deterministic("missing", "https://missing.test");
    fs::write(
        repo.paths().config(),
        format!(
            r#"{{"schema_version":2,"revision":0,"connections":{{}},"clients":{{"cli":{{"active_connection":"{missing}","namespace":{{"kind":"cli_v1","settings":{{}}}}}}}}}}"#
        ),
    )
    .expect("write dangling client reference");
    assert!(matches!(
        repo.snapshot().expect_err("dangling active connection"),
        ConfigError::InvalidConfig { .. }
    ));

    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    fs::write(
        repo.paths().config(),
        format!(
            r#"{{"schema_version":2,"revision":0,"connections":{{"{connection_id}":{{"metadata":{{"name":"raw","address":"https://raw.test"}},"active_credential":"missing"}}}},"clients":{{}},"migration":{{"source_format":"legacy-v1","source_digest":"sha256:{}"}}}}"#,
            "0".repeat(64)
        ),
    )
    .expect("write dangling profile reference");
    assert!(matches!(
        repo.snapshot().expect_err("dangling active credential"),
        ConfigError::InvalidConfig { .. }
    ));
}

#[test]
fn metadata_mutations_preserve_credentials_and_cannot_retarget_binding() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{"main":{"addr":"https://example.test","tokens":{"p":{"access_token":"secret"}},"current_token":"p"}}}"#,
    );
    let repo = repository(&temp);
    let snapshot = repo
        .initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect("migrate");
    let connection_id = snapshot
        .config()
        .connections
        .first_key_value()
        .expect("connection")
        .0
        .clone();
    let credentials =
        serde_json::to_value(snapshot.config().connections[&connection_id].credential_profiles())
            .expect("credential subtree");

    for field in ["address", "server_fingerprint", "storage_id"] {
        let before = fs::read(repo.paths().config()).expect("primary before retarget");
        let revision = repo.snapshot().expect("snapshot").revision();
        let error = repo
            .update_connection(&connection_id, |metadata| {
                match field {
                    "address" => metadata.address = "https://attacker.test".to_string(),
                    "server_fingerprint" => {
                        metadata.server_fingerprint = Some("sha256:attacker".to_string())
                    }
                    "storage_id" => metadata.storage_id = Some("attacker-storage".to_string()),
                    _ => unreachable!(),
                }
                Ok(())
            })
            .expect_err("binding retarget must fail");
        assert!(matches!(
            error,
            ConfigError::BindingChangeRequiresRebind { .. }
        ));
        assert_eq!(
            fs::read(repo.paths().config()).expect("unchanged primary"),
            before
        );
        assert_eq!(
            repo.snapshot().expect("unchanged revision").revision(),
            revision
        );
    }

    let renamed = repo
        .update_connection(&connection_id, |metadata| {
            metadata.name = "renamed display".to_string();
            metadata.needs_salt_update = true;
            Ok(())
        })
        .expect("safe metadata update");
    assert_eq!(
        serde_json::to_value(renamed.config().connections[&connection_id].credential_profiles())
            .expect("credential subtree after rename"),
        credentials
    );
}

#[test]
fn canonical_url_aliases_share_one_trust_binding() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let first_id = ConnectionId::deterministic("first", "https://EXAMPLE.test:443/");
    let mut first = ConnectionMetadata::new("first", "https://EXAMPLE.test:443/");
    first.server_id = Some("server-one".to_string());
    first.server_fingerprint = Some("sha256:one".to_string());
    repo.upsert_connection(first_id, first)
        .expect("pinned first alias");

    let before = fs::read(repo.paths().config()).expect("primary before alias");
    let missing_id = ConnectionId::deterministic("missing", "https://example.test");
    let error = repo
        .upsert_connection(
            missing_id,
            ConnectionMetadata::new("missing", "https://example.test"),
        )
        .expect_err("unpinned alias must not bypass pin");
    assert!(matches!(error, ConfigError::InvalidConfig { .. }));
    assert_eq!(fs::read(repo.paths().config()).expect("unchanged"), before);

    let conflict_id = ConnectionId::deterministic("conflict", "https://example.test:443/a/../");
    let mut conflict = ConnectionMetadata::new("conflict", "https://example.test:443/a/../");
    conflict.server_id = Some("server-one".to_string());
    conflict.server_fingerprint = Some("sha256:two".to_string());
    assert!(matches!(
        repo.upsert_connection(conflict_id, conflict)
            .expect_err("conflicting alias pin"),
        ConfigError::InvalidConfig { .. }
    ));

    let dotted_id = ConnectionId::deterministic("dotted", "https://example.test.");
    assert!(matches!(
        repo.upsert_connection(
            dotted_id,
            ConnectionMetadata::new("dotted", "https://example.test."),
        )
        .expect_err("DNS trailing dot must not bypass an existing pin"),
        ConfigError::InvalidConfig { .. }
    ));

    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let mut base = ConnectionMetadata::new("base", "https://example.test/base");
    base.server_fingerprint = Some("sha256:base".to_string());
    repo.upsert_connection(
        ConnectionId::deterministic("base", "https://example.test/base"),
        base,
    )
    .expect("pinned base path");
    assert!(matches!(
        repo.upsert_connection(
            ConnectionId::deterministic("base-alias", "https://example.test/base/"),
            ConnectionMetadata::new("base alias", "https://example.test/base/"),
        )
        .expect_err("trailing slash must not bypass base-path pin"),
        ConfigError::InvalidConfig { .. }
    ));

    let before = fs::read(repo.paths().config()).expect("primary before encoded path");
    assert!(matches!(
        repo.upsert_connection(
            ConnectionId::deterministic("encoded", "https://encoded.test/%62ase"),
            ConnectionMetadata::new("encoded", "https://encoded.test/%62ase"),
        )
        .expect_err("percent-encoded base path must fail closed"),
        ConfigError::InvalidConfig { .. }
    ));
    assert_eq!(fs::read(repo.paths().config()).expect("unchanged"), before);
}

#[test]
fn legacy_aliases_are_backfilled_to_one_trust_binding_before_publish() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{
          "first":{"addr":"https://EXAMPLE.test:443/"},
          "second":{"addr":"https://example.test","server_id":"server","server_fingerprint":"sha256:pin"}
        }}"#,
    );
    let repo = repository(&temp);
    let snapshot = repo
        .initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect("migrate aliases");
    assert_eq!(snapshot.config().connections.len(), 2);
    for connection in snapshot.config().connections.values() {
        assert_eq!(connection.metadata().server_id.as_deref(), Some("server"));
        assert_eq!(
            connection.metadata().server_fingerprint.as_deref(),
            Some("sha256:pin")
        );
    }
}

#[test]
fn duplicate_json_keys_are_rejected_before_typed_parsing_or_credentials() {
    let connection_id = ConnectionId::deterministic("duplicate", "https://duplicate.test");
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    fs::write(
        repo.paths().config(),
        format!(
            r#"{{"schema_version":2,"revision":0,"connections":{{"{connection_id}":{{"metadata":{{"name":"one","address":"https://duplicate.test"}}}},"{connection_id}":{{"metadata":{{"name":"two","address":"https://duplicate.test"}}}}}},"clients":{{}}}}"#
        ),
    )
    .expect("duplicate canonical map key");
    assert!(matches!(
        repo.snapshot().expect_err("duplicate connection id"),
        ConfigError::Malformed { .. }
    ));

    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    let credential_id = format!("cred_{}", "b".repeat(64));
    fs::write(
        repo.paths().config(),
        format!(
            r#"{{"schema_version":2,"revision":0,"connections":{{"{connection_id}":{{"metadata":{{"name":"x","address":"https://duplicate.test"}},"credential_profiles":{{"p":{{"credentials":{{"access":"{credential_id}","access":"{credential_id}"}}}}}}}}}},"clients":{{}}}}"#
        ),
    )
    .expect("duplicate credential kind");
    assert!(matches!(
        repo.snapshot().expect_err("duplicate credential kind"),
        ConfigError::Malformed { .. }
    ));

    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{"main":{"addr":"https://one.test","tokens":{"p":{"access_token":"secret"}}},"main":{"addr":"https://two.test"}}}"#,
    );
    let store = MemoryCredentials::default();
    let repo = repository(&temp);
    assert!(matches!(
        repo.initialize(
            &client_id("cli"),
            &store,
            &MemoryLegacyCredentials::default(),
        )
        .expect_err("duplicate legacy context"),
        ConfigError::Malformed { .. }
    ));
    assert_eq!(store.len(), 0);
    assert!(!repo.paths().config().exists());

    let temp = TempDir::new().expect("tempdir");
    fs::write(
        temp.path().join("known_hosts.json"),
        r#"{"https://duplicate.test":"sha256:one","https://duplicate.test":"sha256:two"}"#,
    )
    .expect("duplicate known host");
    let repo = repository(&temp);
    assert!(matches!(
        repo.initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect_err("duplicate known host"),
        ConfigError::Malformed { .. }
    ));
    assert!(!repo.paths().config().exists());
}

#[test]
fn legacy_kdf_unknowns_and_out_of_policy_values_fail_before_credential_io() {
    for kdf_params in [
        r#"{"algorithm":"argon2id","iterations":3,"memory_kb":65536,"parallelism":4,"future":true}"#,
        r#"{"algorithm":"argon2id","iterations":11,"memory_kb":65536,"parallelism":4}"#,
    ] {
        let temp = TempDir::new().expect("tempdir");
        write_legacy(
            &temp,
            &format!(
                r#"{{"identity":{{"kdf_salt":"salt","kdf_params":{kdf_params}}},"contexts":{{"main":{{"addr":"https://example.test","tokens":{{"p":{{"access_token":"secret"}}}}}}}}}}"#
            ),
        );
        let store = MemoryCredentials::default();
        let source = CountingLegacyCredentials::default();
        let repo = repository(&temp);
        let error = repo
            .initialize(&client_id("cli"), &store, &source)
            .expect_err("invalid KDF policy");
        assert!(matches!(
            error,
            ConfigError::Malformed { .. } | ConfigError::InvalidConfig { .. }
        ));
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
        assert_eq!(store.len(), 0);
        assert!(!repo.paths().config().exists());
    }
}

#[test]
fn semantic_and_json_budgets_fail_before_external_ports() {
    let mut profiles = String::new();
    for index in 0..=128 {
        if index != 0 {
            profiles.push(',');
        }
        profiles.push_str(&format!(r#""p{index}":{{}}"#));
    }
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        &format!(
            r#"{{"contexts":{{"main":{{"addr":"https://example.test","tokens":{{{profiles}}}}}}}}}"#
        ),
    );
    let store = MemoryCredentials::default();
    let source = CountingLegacyCredentials::default();
    let repo = repository(&temp);
    assert!(matches!(
        repo.initialize(&client_id("cli"), &store, &source)
            .expect_err("profile budget"),
        ConfigError::InvalidConfig { .. }
    ));
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    assert_eq!(store.len(), 0);

    let mut too_many_nodes = String::from("{");
    for index in 0..25_001 {
        if index != 0 {
            too_many_nodes.push(',');
        }
        too_many_nodes.push_str(&format!(r#""n{index}":0"#));
    }
    too_many_nodes.push('}');
    let temp = TempDir::new().expect("tempdir");
    write_legacy(&temp, &too_many_nodes);
    let repo = repository(&temp);
    assert!(matches!(
        repo.initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect_err("JSON node budget"),
        ConfigError::Malformed { .. }
    ));

    let mut near_limit = String::from("{");
    for index in 0..1_024 {
        if index != 0 {
            near_limit.push(',');
        }
        let suffix = format!("_{index}");
        let key = format!("{}{}", "k".repeat(4_088 - suffix.len()), suffix);
        near_limit.push('"');
        near_limit.push_str(&key);
        near_limit.push_str("\":0");
    }
    near_limit.push_str(
        r#","contexts":{"main":{"addr":"https://example.test","tokens":{"p":{"access_token":"inline"}}}}}"#,
    );
    assert!(near_limit.len() < 4 * 1024 * 1024);
    let temp = TempDir::new().expect("tempdir");
    write_legacy(&temp, &near_limit);
    let store = MemoryCredentials::default();
    let source = CountingLegacyCredentials::default();
    let repo = repository(&temp);
    assert!(matches!(
        repo.initialize(&client_id("cli"), &store, &source)
            .expect_err("pretty canonical candidate must remain bounded"),
        ConfigError::ConfigTooLarge { .. }
    ));
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    assert_eq!(store.len(), 0);
    assert!(!repo.paths().config().exists());
}

#[test]
fn oversized_external_credentials_fail_before_credential_store_io() {
    assert!(CredentialSecret::new("").is_err());
    assert!(CredentialSecret::new("x".repeat(64 * 1024)).is_ok());
    assert!(CredentialSecret::new("x".repeat(64 * 1024 + 1)).is_err());

    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{"main":{"addr":"https://example.test","tokens":{"p":{}}}}}"#,
    );
    let repo = repository(&temp);
    let store = MemoryCredentials::default();
    let source = OversizedLegacyCredentials::default();
    let error = repo
        .initialize(&client_id("cli"), &store, &source)
        .expect_err("oversized external credential");
    assert!(matches!(error, ConfigError::CredentialSource { .. }));
    assert_eq!(source.reads.load(Ordering::SeqCst), 1);
    assert_eq!(store.len(), 0);
    assert!(!repo.paths().config().exists());
}

#[test]
fn oversized_legacy_map_names_fail_before_path_amplification_or_ports() {
    let huge_name = "x".repeat(512 * 1024);
    let mut unknown_fields = String::new();
    for index in 0..1_000 {
        if index != 0 {
            unknown_fields.push(',');
        }
        unknown_fields.push_str(&format!(r#""future_{index}":0"#));
    }
    let documents = [
        format!(
            r#"{{"contexts":{{"{huge_name}":{{"addr":"https://example.test",{unknown_fields}}}}}}}"#
        ),
        format!(
            r#"{{"contexts":{{"main":{{"addr":"https://example.test","tokens":{{"{huge_name}":{{{unknown_fields}}}}}}}}}}}"#
        ),
    ];

    for document in documents {
        let temp = TempDir::new().expect("tempdir");
        write_legacy(&temp, &document);
        let repo = repository(&temp);
        let store = MemoryCredentials::default();
        let source = CountingLegacyCredentials::default();
        assert!(matches!(
            repo.initialize(&client_id("cli"), &store, &source)
                .expect_err("oversized dynamic legacy name"),
            ConfigError::Malformed { .. }
        ));
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
        assert_eq!(store.len(), 0);
        assert!(!repo.paths().config().exists());
    }
}

#[test]
fn primary_legacy_and_journal_reads_are_size_bounded() {
    const CONFIG_LIMIT: usize = 4 * 1024 * 1024;
    const JOURNAL_LIMIT: usize = 12 * 1024 * 1024;

    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    fs::write(repo.paths().config(), vec![b' '; CONFIG_LIMIT + 1]).expect("oversize primary");
    assert!(matches!(
        repo.snapshot().expect_err("oversize primary"),
        ConfigError::ConfigTooLarge { .. }
    ));

    let temp = TempDir::new().expect("tempdir");
    fs::write(
        temp.path().join("config.json"),
        vec![b' '; CONFIG_LIMIT + 1],
    )
    .expect("oversize legacy");
    let repo = repository(&temp);
    assert!(matches!(
        repo.initialize(
            &client_id("cli"),
            &MemoryCredentials::default(),
            &MemoryLegacyCredentials::default(),
        )
        .expect_err("oversize legacy"),
        ConfigError::ConfigTooLarge { .. }
    ));
    assert!(!repo.paths().config().exists());

    let prepared = prepared_restore();
    let primary = fs::read(prepared.repo.paths().config()).expect("primary");
    let backup = fs::read(prepared.repo.paths().backup()).expect("backup");
    fs::write(
        prepared.repo.paths().restore_journal(),
        vec![b' '; JOURNAL_LIMIT + 1],
    )
    .expect("oversize journal");
    assert!(matches!(
        prepared.repo.snapshot().expect_err("oversize journal"),
        ConfigError::ConfigTooLarge { .. }
    ));
    assert_eq!(
        fs::read(prepared.repo.paths().config()).expect("unchanged primary"),
        primary
    );
    assert_eq!(
        fs::read(prepared.repo.paths().backup()).expect("unchanged backup"),
        backup
    );
}

#[test]
fn restore_preflights_pretty_target_sizes_before_writing_a_journal() {
    const CONFIG_LIMIT: usize = 4 * 1024 * 1024;

    let temp = TempDir::new().expect("tempdir");
    write_legacy(&temp, EMPTY_V1);
    let repo = repository(&temp);
    repo.initialize(
        &client_id("cli"),
        &MemoryCredentials::default(),
        &MemoryLegacyCredentials::default(),
    )
    .expect("migrate empty legacy");
    repo.upsert_connection(
        ConnectionId::deterministic("main", "https://main.test"),
        ConnectionMetadata::new("main", "https://main.test"),
    )
    .expect("create backup");

    let mut oversized_pretty = repo.snapshot().expect("snapshot").into_config();
    let deferred = &mut oversized_pretty
        .migration
        .as_mut()
        .expect("migration")
        .deferred_legacy_fields;
    deferred.clear();
    for index in 0..1_024 {
        let suffix = format!("_{index}");
        deferred.insert(format!("{}{}", "p".repeat(4_088 - suffix.len()), suffix));
    }
    let compact = serde_json::to_vec(&oversized_pretty).expect("compact valid config");
    assert!(
        compact.len() < CONFIG_LIMIT,
        "compact source must be readable"
    );
    assert!(
        canonical_config_bytes(&oversized_pretty).len() > CONFIG_LIMIT,
        "pretty target must exceed the canonical limit"
    );
    fs::write(repo.paths().config(), &compact).expect("compact primary");
    let primary_before = fs::read(repo.paths().config()).expect("primary before restore");
    let backup_before = fs::read(repo.paths().backup()).expect("backup before restore");

    assert!(matches!(
        repo.restore_backup()
            .expect_err("oversize target must fail before journal"),
        ConfigError::ConfigTooLarge { .. }
    ));
    assert_eq!(
        fs::read(repo.paths().config()).expect("unchanged primary"),
        primary_before
    );
    assert_eq!(
        fs::read(repo.paths().backup()).expect("unchanged backup"),
        backup_before
    );
    assert!(!repo.paths().restore_journal().exists());
}

#[test]
fn restore_journal_replays_each_durable_crash_state_idempotently() {
    for crash_state in 0..3 {
        let prepared = prepared_restore();
        fs::write(prepared.repo.paths().restore_journal(), &prepared.journal)
            .expect("write journal");
        if crash_state >= 1 {
            fs::write(
                prepared.repo.paths().backup(),
                &prepared.target_backup_bytes,
            )
            .expect("simulate backup write");
        }
        if crash_state >= 2 {
            fs::write(
                prepared.repo.paths().config(),
                &prepared.target_primary_bytes,
            )
            .expect("simulate primary write");
        }
        let snapshot = prepared.repo.snapshot().expect("complete restore journal");
        assert_eq!(snapshot.revision(), prepared.target_primary.revision);
        assert_eq!(
            fs::read(prepared.repo.paths().config()).expect("target primary"),
            prepared.target_primary_bytes
        );
        assert_eq!(
            fs::read(prepared.repo.paths().backup()).expect("target backup"),
            prepared.target_backup_bytes
        );
        assert!(!prepared.repo.paths().restore_journal().exists());
    }
}

#[test]
fn malformed_or_stale_restore_journal_never_changes_config_files() {
    let prepared = prepared_restore();
    fs::write(prepared.repo.paths().restore_journal(), b"{broken").expect("malformed journal");
    assert!(matches!(
        prepared.repo.snapshot().expect_err("malformed journal"),
        ConfigError::MalformedRestoreJournal { .. }
    ));
    assert_eq!(
        fs::read(prepared.repo.paths().config()).expect("unchanged primary"),
        prepared.source_primary
    );
    assert_eq!(
        fs::read(prepared.repo.paths().backup()).expect("unchanged backup"),
        prepared.source_backup
    );

    let prepared = prepared_restore();
    let mut future: serde_json::Value =
        serde_json::from_slice(&prepared.journal).expect("parse journal");
    future["journal_version"] = json!(2);
    fs::write(
        prepared.repo.paths().restore_journal(),
        serde_json::to_vec(&future).expect("future journal"),
    )
    .expect("write future journal");
    assert!(matches!(
        prepared.repo.snapshot().expect_err("future journal"),
        ConfigError::FutureRestoreJournal { found: 2, .. }
    ));
    assert_eq!(
        fs::read(prepared.repo.paths().config()).expect("unchanged primary"),
        prepared.source_primary
    );
    assert_eq!(
        fs::read(prepared.repo.paths().backup()).expect("unchanged backup"),
        prepared.source_backup
    );

    let prepared = prepared_restore();
    let mut missing: serde_json::Value =
        serde_json::from_slice(&prepared.journal).expect("parse journal");
    missing
        .as_object_mut()
        .expect("journal object")
        .remove("target_backup");
    fs::write(
        prepared.repo.paths().restore_journal(),
        serde_json::to_vec(&missing).expect("missing journal field"),
    )
    .expect("write incomplete journal");
    assert!(matches!(
        prepared.repo.snapshot().expect_err("incomplete journal"),
        ConfigError::MalformedRestoreJournal { .. }
    ));
    assert_eq!(
        fs::read(prepared.repo.paths().config()).expect("unchanged primary"),
        prepared.source_primary
    );
    assert_eq!(
        fs::read(prepared.repo.paths().backup()).expect("unchanged backup"),
        prepared.source_backup
    );

    let prepared = prepared_restore();
    fs::write(prepared.repo.paths().restore_journal(), &prepared.journal)
        .expect("valid stale journal");
    let mut unrelated = prepared.target_backup.clone();
    unrelated.revision += 10;
    let unrelated_bytes = canonical_config_bytes(&unrelated);
    fs::write(prepared.repo.paths().config(), &unrelated_bytes).expect("unrelated primary");
    let backup_before = fs::read(prepared.repo.paths().backup()).expect("backup before conflict");
    assert!(matches!(
        prepared
            .repo
            .snapshot()
            .expect_err("stale journal conflict"),
        ConfigError::RestoreJournalConflict { .. }
    ));
    assert_eq!(
        fs::read(prepared.repo.paths().config()).expect("unchanged unrelated primary"),
        unrelated_bytes
    );
    assert_eq!(
        fs::read(prepared.repo.paths().backup()).expect("unchanged backup"),
        backup_before
    );
    assert!(prepared.repo.paths().restore_journal().exists());
}

#[test]
fn pending_restore_journal_never_overwrites_a_future_schema_primary() {
    let prepared = prepared_restore();
    fs::write(prepared.repo.paths().restore_journal(), &prepared.journal).expect("valid journal");
    let future = br#"{"schema_version":99,"revision":99,"connections":{},"clients":{}}"#;
    fs::write(prepared.repo.paths().config(), future).expect("future primary");
    let backup = fs::read(prepared.repo.paths().backup()).expect("backup before snapshot");
    assert!(matches!(
        prepared.repo.snapshot().expect_err("future schema wins"),
        ConfigError::FutureSchema { found: 99, .. }
    ));
    assert_eq!(
        fs::read(prepared.repo.paths().config()).expect("future primary unchanged"),
        future
    );
    assert_eq!(
        fs::read(prepared.repo.paths().backup()).expect("backup unchanged"),
        backup
    );
    assert!(prepared.repo.paths().restore_journal().exists());
}

#[test]
fn credential_bundle_rotations_publish_once_and_preserve_recovery_generations() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_test_connection(&repo);
    let store = FaultCredentialStore::default();

    let first = repo
        .replace_credential_bundle(
            1,
            &connection_id,
            "default",
            bundle(Some("access-a"), Some("refresh-a"), Some("service-a")),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect("publish first credential bundle");
    assert_eq!(first.snapshot().revision(), 2);
    assert!(first.warnings().is_empty());
    let first_ids = profile_credentials(first.snapshot().config(), &connection_id, "default");
    assert_eq!(first_ids.len(), 3);
    assert!(first_ids
        .values()
        .all(|id| id.as_str().starts_with("credl_")));
    assert!(!repo.paths().credential_transaction_journal().exists());

    let second = repo
        .replace_credential_bundle(
            2,
            &connection_id,
            "default",
            bundle(Some("access-b"), None, None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect("publish second credential bundle");
    let second_ids = profile_credentials(second.snapshot().config(), &connection_id, "default");
    assert_eq!(second_ids.len(), 1);
    assert!(second.warnings().iter().any(|warning| matches!(
        warning,
        CredentialTransactionWarning::CleanupDeferred { .. }
    )));
    assert!(repo.paths().credential_transaction_journal().exists());
    assert!(matches!(
        repo.restore_backup()
            .expect_err("pending GC blocks restore"),
        ConfigError::CredentialRecoveryRequired { .. }
    ));
    assert!(first_ids.values().all(|id| store.contains(id)));

    let third = repo
        .replace_credential_bundle(
            3,
            &connection_id,
            "default",
            bundle(Some("access-c"), None, None),
            CredentialActivation::Preserve,
            &store,
        )
        .expect("immediate third credential rotation");
    let third_ids = profile_credentials(third.snapshot().config(), &connection_id, "default");
    let second_id = second_ids.values().next().expect("second id");
    let third_id = third_ids.values().next().expect("third id");
    assert!(first_ids.values().all(|id| !store.contains(id)));
    assert!(second_ids.values().all(|id| store.contains(id)));
    assert!(store.contains(third_id));
    assert!(!store.deleted(second_id));
    assert!(!store.deleted(third_id));

    repo.update_connection(&connection_id, |metadata| {
        metadata.name = "renamed".to_string();
        Ok(())
    })
    .expect("rotate recovery generations with metadata-only mutation");
    let reconciled = repo
        .reconcile_credentials(&store)
        .expect("finish deferred credential GC");
    assert!(reconciled.warnings().is_empty());
    assert!(!store.contains(second_id));
    assert!(store.contains(third_id));
    assert!(!repo.paths().credential_transaction_journal().exists());
}

#[test]
fn credential_preflight_failures_do_not_write_intent_or_secrets() {
    for collision in [false, true] {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize_empty(&repo);
        let connection_id = add_test_connection(&repo);
        let primary_before = fs::read(repo.paths().config()).expect("primary before transaction");
        let store = FaultCredentialStore::default();
        if collision {
            store.set_collide_validate_on(2);
        } else {
            store.set_fail_validate_on(2);
        }

        let error = repo
            .replace_credential_bundle(
                1,
                &connection_id,
                "default",
                bundle(Some("access"), Some("refresh"), None),
                CredentialActivation::MakeActive,
                &store,
            )
            .expect_err("preflight must stop before durable intent");
        if collision {
            assert!(matches!(error, ConfigError::CredentialIdConflict { .. }));
        } else {
            assert!(matches!(error, ConfigError::CredentialValidation { .. }));
        }
        assert_eq!(store.puts.load(Ordering::SeqCst), 0);
        assert_eq!(store.deletes.load(Ordering::SeqCst), 0);
        assert!(!repo.paths().credential_transaction_journal().exists());
        assert_eq!(
            fs::read(repo.paths().config()).expect("unchanged primary"),
            primary_before
        );
    }

    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_test_connection(&repo);
    let store = FaultCredentialStore::default();
    assert!(matches!(
        repo.replace_credential_bundle(
            0,
            &connection_id,
            "default",
            bundle(Some("access"), None, None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect_err("stale revision fails before backend ports"),
        ConfigError::RevisionConflict { .. }
    ));
    assert_eq!(store.validations.load(Ordering::SeqCst), 0);
    assert_eq!(store.reads.load(Ordering::SeqCst), 0);
    assert_eq!(store.puts.load(Ordering::SeqCst), 0);
    assert_eq!(store.deletes.load(Ordering::SeqCst), 0);
}

#[test]
fn credential_write_and_readback_failures_cleanup_attempt_owned_ids() {
    for failure in 0..3 {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize_empty(&repo);
        let connection_id = add_test_connection(&repo);
        let store = FaultCredentialStore::default();
        match failure {
            0 => store.set_fail_put(),
            1 => store.set_fail_readback(),
            2 => {
                store.set_write_then_fail_put();
                store.set_fail_readback();
            }
            _ => unreachable!(),
        }
        let primary_before = fs::read(repo.paths().config()).expect("primary before failure");
        repo.replace_credential_bundle(
            1,
            &connection_id,
            "default",
            bundle(Some("access"), None, None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect_err("credential backend failure");
        assert_eq!(store.len(), 0);
        assert!(store.deletes.load(Ordering::SeqCst) >= 1);
        assert!(!repo.paths().credential_transaction_journal().exists());
        assert_eq!(
            fs::read(repo.paths().config()).expect("unchanged primary"),
            primary_before
        );
    }
}

#[test]
fn initialize_recovers_a_crash_after_secret_write_before_publish() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_test_connection(&repo);
    let store = FaultCredentialStore::default();
    store.set_after_verified(|_| panic!("simulated process crash"));

    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = repo.replace_credential_bundle(
            1,
            &connection_id,
            "default",
            bundle(Some("access"), None, None),
            CredentialActivation::MakeActive,
            &store,
        );
    }));
    assert!(crashed.is_err());
    assert_eq!(store.len(), 1);
    assert!(repo.paths().credential_transaction_journal().exists());
    assert!(repo
        .snapshot()
        .expect_err("source intent blocks snapshot")
        .to_string()
        .contains("credential recovery"));

    let recovered = repo
        .initialize(
            &client_id("test"),
            &store,
            &MemoryLegacyCredentials::default(),
        )
        .expect("initialize auto-reconciles credential intent");
    assert_eq!(recovered.revision(), 1);
    assert_eq!(store.len(), 0);
    assert!(!repo.paths().credential_transaction_journal().exists());
}

#[test]
fn backup_written_restart_aborts_candidate_and_keeps_only_live_credentials() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_test_connection(&repo);
    let store = FaultCredentialStore::default();
    let first = repo
        .replace_credential_bundle(
            1,
            &connection_id,
            "default",
            bundle(Some("a"), None, None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect("A");
    let first_id = profile_credentials(first.snapshot().config(), &connection_id, "default")
        .into_values()
        .next()
        .expect("A id");
    let second = repo
        .replace_credential_bundle(
            2,
            &connection_id,
            "default",
            bundle(Some("b"), None, None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect("B");
    let second_id = profile_credentials(second.snapshot().config(), &connection_id, "default")
        .into_values()
        .next()
        .expect("B id");
    store.set_after_verified(|_| panic!("crash before config commit"));
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = repo.replace_credential_bundle(
            3,
            &connection_id,
            "default",
            bundle(Some("c"), None, None),
            CredentialActivation::MakeActive,
            &store,
        );
    }));
    assert!(crashed.is_err());

    let source_primary = fs::read(repo.paths().config()).expect("B primary");
    fs::write(repo.paths().backup(), &source_primary).expect("simulate durable backup write");
    repo.initialize(
        &client_id("test"),
        &store,
        &MemoryLegacyCredentials::default(),
    )
    .expect("recover BackupWritten state");
    assert!(!store.contains(&first_id));
    assert!(store.contains(&second_id));
    assert_eq!(store.len(), 1, "unpublished C and displaced A are cleaned");
    assert!(!repo.paths().credential_transaction_journal().exists());
}

#[test]
fn initial_abort_never_retires_the_still_active_source_profile() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_test_connection(&repo);
    let store = FaultCredentialStore::default();
    let first = repo
        .replace_credential_bundle(
            1,
            &connection_id,
            "active",
            bundle(Some("active-a"), None, None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect("active source profile");
    let active_id = profile_credentials(first.snapshot().config(), &connection_id, "active")
        .into_values()
        .next()
        .expect("active id");
    store.set_after_verified(|_| panic!("abort replacement"));
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = repo.replace_credential_bundle(
            2,
            &connection_id,
            "active",
            bundle(Some("active-b"), None, None),
            CredentialActivation::MakeActive,
            &store,
        );
    }));
    assert!(crashed.is_err());
    repo.initialize(
        &client_id("test"),
        &store,
        &MemoryLegacyCredentials::default(),
    )
    .expect("abort prepublish intent");
    assert!(store.contains(&active_id));
    assert_eq!(store.len(), 1);

    repo.replace_credential_bundle(
        2,
        &connection_id,
        "other",
        bundle(Some("other"), None, None),
        CredentialActivation::Preserve,
        &store,
    )
    .expect("unrelated profile remains writable after abort");
    assert!(store.contains(&active_id));
}

#[test]
fn initial_abort_preserves_predecessor_backup_gc_until_rotation() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_test_connection(&repo);
    let store = FaultCredentialStore::default();
    let first = repo
        .replace_credential_bundle(
            1,
            &connection_id,
            "default",
            bundle(Some("a"), None, None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect("A");
    let first_id = profile_credentials(first.snapshot().config(), &connection_id, "default")
        .into_values()
        .next()
        .expect("A id");
    let second = repo
        .replace_credential_bundle(
            2,
            &connection_id,
            "default",
            bundle(Some("b"), None, None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect("B");
    let second_id = profile_credentials(second.snapshot().config(), &connection_id, "default")
        .into_values()
        .next()
        .expect("B id");
    store.set_after_verified(|_| panic!("abort C before backup write"));
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = repo.replace_credential_bundle(
            3,
            &connection_id,
            "default",
            bundle(Some("c"), None, None),
            CredentialActivation::MakeActive,
            &store,
        );
    }));
    assert!(crashed.is_err());
    repo.initialize(
        &client_id("test"),
        &store,
        &MemoryLegacyCredentials::default(),
    )
    .expect("recover initial abort");
    assert!(store.contains(&first_id), "A remains reachable from backup");
    assert!(store.contains(&second_id));
    assert!(repo.paths().credential_transaction_journal().exists());

    repo.update_connection(&connection_id, |metadata| {
        metadata.name = "rotate-after-abort".to_string();
        Ok(())
    })
    .expect("rotate predecessor backup");
    repo.reconcile_credentials(&store)
        .expect("delete predecessor after it is no longer recoverable");
    assert!(!store.contains(&first_id));
    assert!(store.contains(&second_id));
    assert!(!repo.paths().credential_transaction_journal().exists());
}

#[test]
fn credential_delete_callbacks_run_without_the_config_lock() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_test_connection(&repo);
    let store = FaultCredentialStore::default();
    repo.replace_credential_bundle(
        1,
        &connection_id,
        "default",
        bundle(Some("a"), None, None),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("first bundle");
    repo.replace_credential_bundle(
        2,
        &connection_id,
        "default",
        bundle(Some("b"), None, None),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("second bundle");
    repo.update_connection(&connection_id, |metadata| {
        metadata.name = "rotated".to_string();
        Ok(())
    })
    .expect("rotate backup away from retired id");

    let callback_ran = Arc::new(AtomicBool::new(false));
    let callback_flag = callback_ran.clone();
    let callback_repo = repo.clone();
    store.set_before_delete(move |_| {
        callback_repo
            .snapshot()
            .expect("snapshot during store delete");
        callback_flag.store(true, Ordering::SeqCst);
    });
    repo.reconcile_credentials(&store)
        .expect("lock-free credential delete");
    assert!(callback_ran.load(Ordering::SeqCst));
}

#[test]
fn source_intent_blocks_concurrent_config_rotation_during_store_io() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_test_connection(&repo);
    let store = FaultCredentialStore::default();
    let callback_result = Arc::new(Mutex::new(None));
    let callback_result_copy = callback_result.clone();
    let callback_repo = repo.clone();
    let callback_connection = connection_id.clone();
    store.set_after_verified(move |_| {
        let result = callback_repo.update_connection(&callback_connection, |metadata| {
            metadata.name = "concurrent".to_string();
            Ok(())
        });
        *callback_result_copy.lock().expect("callback result lock") =
            Some(result.expect_err("source intent blocks mutation"));
    });
    let outcome = repo
        .replace_credential_bundle(
            1,
            &connection_id,
            "default",
            bundle(Some("access"), None, None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect("credential transaction commits after blocked mutation");
    assert_eq!(outcome.snapshot().revision(), 2);
    assert!(matches!(
        callback_result
            .lock()
            .expect("callback result lock")
            .take()
            .expect("callback result"),
        ConfigError::CredentialRecoveryRequired { .. }
    ));
}

#[test]
fn master_key_fingerprint_bind_is_atomic_idempotent_and_canonical() {
    let (_temp, repo, connection_id, store) = master_key_binding_fixture(None);
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "profile")
        .expect("unbound profile anchor");
    assert_eq!(anchor.expected_master_key_fp(), None);

    let primary_source = fs::read(repo.paths().config()).expect("source primary");
    let calls_before = store.call_counts();
    let outcome = repo
        .bind_expected_master_key_fingerprint_if_profile_matches(&anchor, "0123456789ab")
        .expect("initial binding");
    assert!(matches!(
        &outcome,
        MasterKeyFingerprintBindingOutcome::Bound(_)
    ));
    assert!(outcome.changed());
    assert_eq!(outcome.snapshot().revision(), anchor.source_revision() + 1);
    assert_eq!(
        outcome.snapshot().config().connections[&connection_id]
            .metadata()
            .expected_master_key_fp
            .as_deref(),
        Some("0123456789ab")
    );
    assert_eq!(
        fs::read(repo.paths().backup()).expect("binding backup"),
        primary_source,
        "the backup must be the exact compare-and-swap source bytes"
    );
    assert_eq!(store.call_counts(), calls_before);

    let bound_anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "profile")
        .expect("bound profile anchor");
    assert_eq!(bound_anchor.expected_master_key_fp(), Some("0123456789ab"));
    let primary_before_idempotent = fs::read(repo.paths().config()).expect("bound primary");
    let backup_before_idempotent = fs::read(repo.paths().backup()).expect("bound backup");
    let idempotent = repo
        .bind_expected_master_key_fingerprint_if_profile_matches(&bound_anchor, "0123456789ab")
        .expect("idempotent binding");
    assert!(matches!(
        &idempotent,
        MasterKeyFingerprintBindingOutcome::AlreadyBound(_)
    ));
    assert!(!idempotent.changed());
    assert_eq!(
        idempotent.snapshot().revision(),
        bound_anchor.source_revision()
    );
    assert_eq!(
        fs::read(repo.paths().config()).expect("idempotent primary"),
        primary_before_idempotent
    );
    assert_eq!(
        fs::read(repo.paths().backup()).expect("idempotent backup"),
        backup_before_idempotent
    );

    for invalid in [
        "",
        "0123456789a",
        "0123456789abc",
        "0123456789aB",
        "0123456789ag",
        "master-key-fp",
    ] {
        assert!(matches!(
            repo.bind_expected_master_key_fingerprint_if_profile_matches(&bound_anchor, invalid,),
            Err(ConfigError::InvalidMasterKeyFingerprint)
        ));
    }
    assert_eq!(
        fs::read(repo.paths().config()).expect("primary after invalid inputs"),
        primary_before_idempotent
    );
    assert_eq!(
        fs::read(repo.paths().backup()).expect("backup after invalid inputs"),
        backup_before_idempotent
    );
}

#[test]
fn master_key_fingerprint_bind_rebases_unrelated_revisions_but_not_binding_changes() {
    let (_temp, repo, connection_id, _store) = master_key_binding_fixture(None);
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "profile")
        .expect("profile anchor");
    repo.set_desktop_backup_settings(Some(DesktopBackupSettings {
        backup_dir: Some("/unrelated".to_string()),
        backup_retention_days: Some(7),
        backup_max_count: Some(3),
    }))
    .expect("unrelated revision");
    let rebased_source = fs::read(repo.paths().config()).expect("rebased source");
    let rebased = repo
        .bind_expected_master_key_fingerprint_if_profile_matches(&anchor, "111111111111")
        .expect("bind over unrelated revision");
    assert_eq!(rebased.snapshot().revision(), anchor.source_revision() + 2);
    assert_eq!(
        fs::read(repo.paths().backup()).expect("rebased backup"),
        rebased_source
    );
    let desktop = rebased
        .snapshot()
        .config()
        .clients
        .get(&client_id("desktop"))
        .expect("desktop namespace");
    let ClientNamespace::DesktopV1(desktop) = desktop.namespace() else {
        panic!("desktop namespace schema")
    };
    assert_eq!(
        desktop
            .backup
            .as_ref()
            .and_then(|settings| settings.backup_dir.as_deref()),
        Some("/unrelated")
    );

    let (_temp, repo, connection_id, _store) = master_key_binding_fixture(None);
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "profile")
        .expect("unbound anchor");
    rewrite_primary_json(&repo, |raw| {
        raw["connections"][connection_id.as_str()]["metadata"]["expected_master_key_fp"] =
            json!("222222222222");
    });
    assert!(matches!(
        repo.bind_expected_master_key_fingerprint_if_profile_matches(&anchor, "222222222222"),
        Err(ConfigError::CredentialProfileAnchorConflict {
            field: "expected_master_key_fp",
            ..
        })
    ));

    for replacement in [None, Some("333333333333")] {
        let (_temp, repo, connection_id, _store) = master_key_binding_fixture(Some("222222222222"));
        let anchor = repo
            .resolve_credential_profile_anchor(&connection_id, "profile")
            .expect("bound anchor");
        rewrite_primary_json(&repo, |raw| {
            raw["connections"][connection_id.as_str()]["metadata"]["expected_master_key_fp"] =
                replacement.map_or(serde_json::Value::Null, |value| json!(value));
        });
        assert!(matches!(
            repo.bind_expected_master_key_fingerprint_if_profile_matches(&anchor, "222222222222",),
            Err(ConfigError::CredentialProfileAnchorConflict {
                field: "expected_master_key_fp",
                ..
            })
        ));
    }

    let (_temp, repo, connection_id, _store) =
        master_key_binding_fixture(Some("legacy-master-key-fingerprint"));
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "profile")
        .expect("legacy binding remains parseable");
    let primary_before = fs::read(repo.paths().config()).expect("legacy primary");
    assert_eq!(
        anchor.expected_master_key_fp(),
        Some("legacy-master-key-fingerprint")
    );
    assert!(matches!(
        repo.bind_expected_master_key_fingerprint_if_profile_matches(&anchor, "444444444444"),
        Err(ConfigError::MasterKeyFingerprintRebindRequired { .. })
    ));
    assert_eq!(
        fs::read(repo.paths().config()).expect("unchanged legacy primary"),
        primary_before
    );
}

#[test]
fn master_key_fingerprint_bind_checks_every_profile_and_endpoint_field() {
    assert_master_key_binding_anchor_conflict(
        "profile",
        |_, _| {},
        |raw, connection_id| {
            raw["connections"][connection_id.as_str()]["credential_profiles"]
                .as_object_mut()
                .expect("profile object")
                .remove("profile");
            raw["connections"][connection_id.as_str()]["active_credential"] =
                serde_json::Value::Null;
        },
    );
    assert_master_key_binding_anchor_conflict(
        "address",
        |_, _| {},
        |raw, connection_id| {
            raw["connections"][connection_id.as_str()]["metadata"]["address"] =
                json!("https://relocated.test");
        },
    );
    assert_master_key_binding_anchor_conflict(
        "server_id",
        |_, _| {},
        |raw, connection_id| {
            raw["connections"][connection_id.as_str()]["metadata"]["server_id"] =
                json!("server-other");
        },
    );
    assert_master_key_binding_anchor_conflict(
        "server_fingerprint",
        |_, _| {},
        |raw, connection_id| {
            raw["connections"][connection_id.as_str()]["metadata"]["server_fingerprint"] =
                json!("pin-other");
        },
    );
    assert_master_key_binding_anchor_conflict(
        "storage_id",
        |_, _| {},
        |raw, connection_id| {
            raw["connections"][connection_id.as_str()]["metadata"]["storage_id"] =
                json!("storage-other");
        },
    );
    assert_master_key_binding_anchor_conflict(
        "account_subject",
        |raw, connection_id| {
            let profile =
                &mut raw["connections"][connection_id.as_str()]["credential_profiles"]["profile"];
            profile["account_subject"] = json!("018f4f08-7f1d-7d57-bd43-bb4b7c520001");
            profile["auth_method"] = json!(1);
        },
        |raw, connection_id| {
            raw["connections"][connection_id.as_str()]["credential_profiles"]["profile"]
                ["account_subject"] = json!("018f4f08-7f1d-7d57-bd43-bb4b7c520002");
        },
    );
    assert_master_key_binding_anchor_conflict(
        "auth_method",
        |raw, connection_id| {
            let profile =
                &mut raw["connections"][connection_id.as_str()]["credential_profiles"]["profile"];
            profile["account_subject"] = json!("018f4f08-7f1d-7d57-bd43-bb4b7c520001");
            profile["auth_method"] = json!(1);
        },
        |raw, connection_id| {
            raw["connections"][connection_id.as_str()]["credential_profiles"]["profile"]
                ["auth_method"] = json!(2);
        },
    );
    assert_master_key_binding_anchor_conflict(
        "credentials",
        |_, _| {},
        |raw, connection_id| {
            raw["connections"][connection_id.as_str()]["credential_profiles"]["profile"]
                ["credentials"]
                .as_object_mut()
                .expect("credentials object")
                .remove("refresh");
        },
    );
    assert_master_key_binding_anchor_conflict(
        "access_expires_at",
        |_, _| {},
        |raw, connection_id| {
            raw["connections"][connection_id.as_str()]["credential_profiles"]["profile"]
                ["access_expires_at"] = json!("2026-08-16T13:00:00Z");
        },
    );
}

#[test]
fn master_key_fingerprint_bind_is_repository_bound_and_detects_same_revision_aba() {
    let (_first_temp, first_repo, first_connection, _first_store) =
        master_key_binding_fixture(None);
    let anchor = first_repo
        .resolve_credential_profile_anchor(&first_connection, "profile")
        .expect("first anchor");

    let (_second_temp, second_repo, _second_connection, _second_store) =
        master_key_binding_fixture(None);
    assert!(matches!(
        second_repo
            .bind_expected_master_key_fingerprint_if_profile_matches(&anchor, "555555555555"),
        Err(ConfigError::CredentialProfileAnchorRepositoryMismatch)
    ));

    let path = first_repo.paths().config();
    let primary_before: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("source primary")).expect("source JSON");
    let mut rewritten = primary_before;
    rewritten["connections"][first_connection.as_str()]["metadata"]["name"] = json!("aba-name");
    let rewritten: ConfigV2 = serde_json::from_value(rewritten).expect("typed ABA config");
    let rewritten_bytes = canonical_config_bytes(&rewritten);
    fs::write(&path, &rewritten_bytes).expect("install same-revision ABA");
    let backup_before = fs::read(first_repo.paths().backup()).expect("backup before ABA check");
    assert!(matches!(
        first_repo
            .bind_expected_master_key_fingerprint_if_profile_matches(&anchor, "555555555555"),
        Err(ConfigError::ConfigContentConflict { revision })
            if revision == anchor.source_revision()
    ));
    assert_eq!(fs::read(&path).expect("ABA primary"), rewritten_bytes);
    assert_eq!(
        fs::read(first_repo.paths().backup()).expect("ABA backup"),
        backup_before
    );
}

#[test]
fn master_key_fingerprint_bind_honors_auth_and_credential_intent_barriers() {
    let (_temp, repo, connection_id, store) = master_key_binding_fixture(None);
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "profile")
        .expect("profile anchor");
    let primary_before = fs::read(repo.paths().config()).expect("primary before auth intent");
    let auth_intent_path = repo.paths().root().join("client-auth.intent.json");
    fs::write(&auth_intent_path, b"{}").expect("pending auth intent");
    assert!(matches!(
        repo.bind_expected_master_key_fingerprint_if_profile_matches(&anchor, "666666666666"),
        Err(ConfigError::AuthOperationRecoveryRequired { .. })
    ));
    assert_eq!(
        fs::read(repo.paths().config()).expect("primary after auth barrier"),
        primary_before
    );
    fs::remove_file(auth_intent_path).expect("clear test auth intent");

    let callback_result = Arc::new(Mutex::new(None));
    let callback_result_copy = callback_result.clone();
    let callback_repo = repo.clone();
    let callback_anchor = anchor.clone();
    store.set_after_verified(move |_| {
        let error = callback_repo
            .bind_expected_master_key_fingerprint_if_profile_matches(
                &callback_anchor,
                "666666666666",
            )
            .expect_err("precommit credential intent must block binding");
        *callback_result_copy.lock().expect("callback result lock") = Some(error);
    });
    repo.replace_credential_bundle(
        anchor.source_revision(),
        &connection_id,
        "profile",
        bundle(Some("next-access"), Some("next-refresh"), None),
        CredentialActivation::Preserve,
        &store,
    )
    .expect("credential rotation after blocked callback");
    assert!(matches!(
        callback_result
            .lock()
            .expect("callback result lock")
            .take()
            .expect("callback result"),
        ConfigError::CredentialRecoveryRequired { .. }
    ));
    assert_eq!(
        repo.snapshot().expect("snapshot").config().connections[&connection_id]
            .metadata()
            .expected_master_key_fp,
        None
    );
}

#[test]
fn profile_anchor_rebases_over_unrelated_state_and_preserves_active_selection() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_bound_test_connection(&repo);
    let store = FaultCredentialStore::default();
    repo.replace_credential_bundle(
        1,
        &connection_id,
        "refreshing",
        bundle(Some("old-access"), Some("old-refresh"), None)
            .with_access_expires_at(Some("2026-01-01T00:00:00Z".to_string())),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("initial refresh profile");
    repo.replace_credential_bundle(
        2,
        &connection_id,
        "selected",
        bundle(Some("selected-a"), None, None),
        CredentialActivation::Preserve,
        &store,
    )
    .expect("second profile");

    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "refreshing")
        .expect("profile anchor");
    assert_eq!(anchor.source_revision(), 3);
    assert_eq!(anchor.connection_id(), &connection_id);
    assert_eq!(anchor.profile_name(), "refreshing");
    assert_eq!(anchor.address(), "https://example.test");
    assert_eq!(anchor.server_id(), Some("server-1"));
    assert_eq!(anchor.server_fingerprint(), Some("fingerprint-1"));
    assert_eq!(anchor.storage_id(), Some("storage-1"));
    assert_eq!(anchor.access_expires_at(), Some("2026-01-01T00:00:00Z"));
    assert!(anchor.credentials().contains_key(&CredentialKind::Refresh));
    let debug = format!("{anchor:?}");
    assert!(!debug.contains("old-access"));
    assert!(!debug.contains("old-refresh"));

    repo.replace_credential_bundle(
        3,
        &connection_id,
        "selected",
        bundle(Some("selected-b"), None, None),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("switch active profile while refresh is in flight");
    repo.update_connection(&connection_id, |metadata| {
        metadata.name = "renamed during refresh".to_string();
        Ok(())
    })
    .expect("unrelated metadata write");
    repo.set_desktop_backup_settings(Some(DesktopBackupSettings {
        backup_dir: Some("/tmp/zann-backups".to_string()),
        backup_retention_days: Some(7),
        backup_max_count: Some(3),
    }))
    .expect("unrelated client namespace write");
    let before = repo.snapshot().expect("latest before CAS");
    let selected_credentials = profile_credentials(before.config(), &connection_id, "selected");
    assert_eq!(before.revision(), 6);

    let outcome = repo
        .replace_credential_bundle_if_profile_matches(
            &anchor,
            bundle(Some("new-access"), Some("new-refresh"), None)
                .with_access_expires_at(Some("2026-02-01T00:00:00Z".to_string())),
            CredentialActivation::Preserve,
            &store,
        )
        .expect("rebase profile rotation onto unrelated writes");
    assert_eq!(outcome.snapshot().revision(), 7);
    let config = outcome.snapshot().config();
    let connection = &config.connections[&connection_id];
    assert_eq!(connection.metadata().name, "renamed during refresh");
    assert_eq!(connection.active_credential(), Some("selected"));
    assert_eq!(
        profile_credentials(config, &connection_id, "selected"),
        selected_credentials
    );
    assert_ne!(
        profile_credentials(config, &connection_id, "refreshing"),
        anchor.credentials().clone()
    );
    let desktop = config
        .clients
        .get(&client_id("desktop"))
        .expect("desktop namespace");
    let ClientNamespace::DesktopV1(desktop) = desktop.namespace() else {
        panic!("desktop namespace schema");
    };
    assert_eq!(
        desktop
            .backup
            .as_ref()
            .and_then(|backup| backup.backup_dir.as_deref()),
        Some("/tmp/zann-backups")
    );
}

#[test]
fn session_rotation_preserves_an_untouched_service_credential() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_bound_test_connection(&repo);
    let store = MemoryCredentials::default();
    repo.replace_credential_bundle(
        1,
        &connection_id,
        "mixed",
        bundle(
            Some("old-access"),
            Some("old-refresh"),
            Some("service-secret"),
        )
        .with_access_expires_at(Some("2026-01-01T00:00:00Z".to_string())),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("mixed profile");
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "mixed")
        .expect("mixed profile anchor");
    let service_id = anchor.credentials()[&CredentialKind::ServiceAccount].clone();
    assert_eq!(store.write_count(&service_id), 1);

    let outcome = repo
        .rotate_session_credentials_if_profile_matches(
            &anchor,
            CredentialSecret::new("new-access").expect("access secret"),
            CredentialSecret::new("new-refresh").expect("refresh secret"),
            "2026-02-01T00:00:00Z".to_string(),
            &store,
        )
        .expect("rotate only session credentials");

    let connection = &outcome.snapshot().config().connections[&connection_id];
    let profile = &connection.credential_profiles()["mixed"];
    assert_eq!(
        profile.credentials()[&CredentialKind::ServiceAccount],
        service_id
    );
    assert_eq!(store.value(&service_id).as_deref(), Some("service-secret"));
    assert_eq!(store.write_count(&service_id), 1);
    assert_ne!(
        profile.credentials()[&CredentialKind::Access],
        anchor.credentials()[&CredentialKind::Access]
    );
    assert_ne!(
        profile.credentials()[&CredentialKind::Refresh],
        anchor.credentials()[&CredentialKind::Refresh]
    );
    assert_eq!(
        profile.access_expires_at.as_deref(),
        Some("2026-02-01T00:00:00Z")
    );
    assert_eq!(connection.active_credential(), Some("mixed"));
}

#[test]
fn profile_anchor_rebuilds_from_latest_with_the_preflighted_ids() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_bound_test_connection(&repo);
    let store = PreflightMutatingCredentialStore::default();
    repo.replace_credential_bundle(
        1,
        &connection_id,
        "profile",
        bundle(Some("old-access"), Some("old-refresh"), None),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("initial profile");
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "profile")
        .expect("profile anchor");
    store.clear_observed_ids();
    let callback_repo = repo.clone();
    store.set_before_validation(move || {
        callback_repo
            .set_desktop_backup_settings(Some(DesktopBackupSettings {
                backup_dir: Some("/during-preflight".to_string()),
                backup_retention_days: None,
                backup_max_count: None,
            }))
            .expect("config lock is not held during credential preflight");
    });

    let outcome = repo
        .replace_credential_bundle_if_profile_matches(
            &anchor,
            bundle(Some("new-access"), Some("new-refresh"), None),
            CredentialActivation::Preserve,
            &store,
        )
        .expect("rebuild candidate after preflight mutation");
    assert_eq!(outcome.snapshot().revision(), 4);
    let validated: std::collections::BTreeSet<_> = store.validated_ids().into_iter().collect();
    let written: std::collections::BTreeSet<_> = store.put_ids().into_iter().collect();
    assert_eq!(validated.len(), 2);
    assert_eq!(
        written, validated,
        "rebase must reuse preflighted fresh ids"
    );
    let desktop = outcome
        .snapshot()
        .config()
        .clients
        .get(&client_id("desktop"))
        .expect("desktop namespace survives rebase");
    let ClientNamespace::DesktopV1(desktop) = desktop.namespace() else {
        panic!("desktop namespace schema");
    };
    assert_eq!(
        desktop
            .backup
            .as_ref()
            .and_then(|backup| backup.backup_dir.as_deref()),
        Some("/during-preflight")
    );
}

#[test]
fn profile_anchor_conflicts_fail_before_any_credential_port_call() {
    {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize_empty(&repo);
        let connection_id = add_bound_test_connection(&repo);
        let store = FaultCredentialStore::default();
        repo.replace_credential_bundle(
            1,
            &connection_id,
            "profile",
            bundle(Some("a"), Some("refresh-a"), None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect("initial profile");
        let anchor = repo
            .resolve_credential_profile_anchor(&connection_id, "profile")
            .expect("anchor");
        repo.replace_credential_bundle(
            2,
            &connection_id,
            "profile",
            bundle(Some("b"), Some("refresh-b"), None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect("competing profile rotation");
        let calls = store.call_counts();
        assert!(matches!(
            repo.replace_credential_bundle_if_profile_matches(
                &anchor,
                bundle(Some("c"), Some("refresh-c"), None),
                CredentialActivation::Preserve,
                &store,
            )
            .expect_err("changed credential ids conflict"),
            ConfigError::CredentialProfileAnchorConflict {
                field: "credentials",
                ..
            }
        ));
        assert_eq!(store.call_counts(), calls);
    }

    {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize_empty(&repo);
        let connection_id = add_bound_test_connection(&repo);
        let store = FaultCredentialStore::default();
        repo.replace_credential_bundle(
            1,
            &connection_id,
            "profile",
            bundle(Some("a"), Some("refresh-a"), None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect("initial profile");
        let anchor = repo
            .resolve_credential_profile_anchor(&connection_id, "profile")
            .expect("anchor");
        let primary_path = repo.paths().config();
        let mut raw: serde_json::Value = serde_json::from_slice(
            &fs::read(&primary_path).expect("read primary for endpoint change"),
        )
        .expect("parse primary");
        raw["revision"] = json!(3);
        raw["connections"][connection_id.as_str()]["metadata"]["address"] =
            json!("https://relocated.test/");
        fs::write(
            &primary_path,
            canonical_config_bytes(&serde_json::from_value(raw).expect("typed changed config")),
        )
        .expect("write endpoint change");
        let calls = store.call_counts();
        assert!(matches!(
            repo.replace_credential_bundle_if_profile_matches(
                &anchor,
                bundle(Some("b"), Some("refresh-b"), None),
                CredentialActivation::Preserve,
                &store,
            )
            .expect_err("changed endpoint conflicts"),
            ConfigError::CredentialProfileAnchorConflict {
                field: "address",
                ..
            }
        ));
        assert_eq!(store.call_counts(), calls);
    }

    {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize_empty(&repo);
        let connection_id = add_bound_test_connection(&repo);
        let store = FaultCredentialStore::default();
        repo.replace_credential_bundle(
            1,
            &connection_id,
            "profile",
            bundle(Some("a"), Some("refresh-a"), None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect("initial profile");
        let anchor = repo
            .resolve_credential_profile_anchor(&connection_id, "profile")
            .expect("anchor");
        repo.remove_credential_profile(
            2,
            &connection_id,
            "profile",
            ActiveCredentialAfterRemoval::Clear,
            &store,
        )
        .expect("remove anchored profile");
        let calls = store.call_counts();
        assert!(matches!(
            repo.replace_credential_bundle_if_profile_matches(
                &anchor,
                bundle(Some("b"), Some("refresh-b"), None),
                CredentialActivation::Preserve,
                &store,
            )
            .expect_err("removed profile conflicts"),
            ConfigError::CredentialProfileAnchorConflict {
                field: "profile",
                ..
            }
        ));
        assert_eq!(store.call_counts(), calls);
    }
}

#[test]
fn profile_anchor_is_root_bound_and_rejects_same_revision_rewrites() {
    let first_temp = TempDir::new().expect("first tempdir");
    let first_repo = repository(&first_temp);
    initialize_empty(&first_repo);
    let first_connection = add_bound_test_connection(&first_repo);
    let first_store = FaultCredentialStore::default();
    first_repo
        .replace_credential_bundle(
            1,
            &first_connection,
            "profile",
            bundle(Some("a"), Some("refresh-a"), None),
            CredentialActivation::MakeActive,
            &first_store,
        )
        .expect("first root profile");
    let anchor = first_repo
        .resolve_credential_profile_anchor(&first_connection, "profile")
        .expect("first root anchor");

    let second_temp = TempDir::new().expect("second tempdir");
    let second_repo = repository(&second_temp);
    initialize_empty(&second_repo);
    let second_connection = add_bound_test_connection(&second_repo);
    let second_store = FaultCredentialStore::default();
    second_repo
        .replace_credential_bundle(
            1,
            &second_connection,
            "profile",
            bundle(Some("a"), Some("refresh-a"), None),
            CredentialActivation::MakeActive,
            &second_store,
        )
        .expect("second root profile");
    let calls = second_store.call_counts();
    assert!(matches!(
        second_repo
            .replace_credential_bundle_if_profile_matches(
                &anchor,
                bundle(Some("b"), Some("refresh-b"), None),
                CredentialActivation::Preserve,
                &second_store,
            )
            .expect_err("cross-root anchor must not replay"),
        ConfigError::CredentialProfileAnchorRepositoryMismatch
    ));
    assert_eq!(second_store.call_counts(), calls);

    first_repo
        .update_connection(&first_connection, |metadata| {
            metadata.name = "temporary".to_string();
            Ok(())
        })
        .expect("advance then rewrite source");
    let primary_path = first_repo.paths().config();
    let mut raw: serde_json::Value =
        serde_json::from_slice(&fs::read(&primary_path).expect("read rewritten source"))
            .expect("parse rewritten source");
    raw["revision"] = json!(anchor.source_revision());
    raw["connections"][first_connection.as_str()]["metadata"]["name"] = json!("bound");
    raw["clients"]["desktop"] = json!({
        "namespace": {
            "kind": "desktop_v1",
            "settings": {
                "backup": { "backup_dir": "/aba" }
            }
        }
    });
    let rewritten: ConfigV2 = serde_json::from_value(raw).expect("valid ABA config");
    fs::write(&primary_path, canonical_config_bytes(&rewritten)).expect("install ABA source");
    let calls = first_store.call_counts();
    assert!(matches!(
        first_repo
            .replace_credential_bundle_if_profile_matches(
                &anchor,
                bundle(Some("c"), Some("refresh-c"), None),
                CredentialActivation::Preserve,
                &first_store,
            )
            .expect_err("same revision with different bytes conflicts"),
        ConfigError::ConfigContentConflict { revision } if revision == anchor.source_revision()
    ));
    assert_eq!(first_store.call_counts(), calls);
}

#[test]
fn conflicting_same_revision_publish_never_deletes_its_referenced_secret() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_test_connection(&repo);
    let store = FaultCredentialStore::default();
    let published_id = Arc::new(Mutex::new(None));
    let published_id_copy = published_id.clone();
    let primary_path = repo.paths().config();
    let connection_key = connection_id.as_str().to_string();
    store.set_after_verified(move |credential_id| {
        let mut raw: serde_json::Value = serde_json::from_slice(
            &fs::read(&primary_path).expect("read source primary in callback"),
        )
        .expect("parse source primary in callback");
        raw["revision"] = json!(2);
        raw["connections"][&connection_key]["credential_profiles"]["default"] = json!({
            "credentials": { "access": credential_id.as_str() }
        });
        raw["connections"][&connection_key]["active_credential"] = json!("default");
        let mut bytes = serde_json::to_vec_pretty(&raw).expect("serialize competing primary");
        bytes.push(b'\n');
        fs::write(&primary_path, bytes).expect("install competing primary");
        *published_id_copy.lock().expect("published id lock") = Some(credential_id.clone());
    });

    let error = repo
        .replace_credential_bundle(
            1,
            &connection_id,
            "default",
            bundle(Some("published"), None, None),
            CredentialActivation::MakeActive,
            &store,
        )
        .expect_err("same-revision external publish conflicts with exact CAS");
    assert!(matches!(
        error,
        ConfigError::CredentialTransactionCleanup { .. }
            | ConfigError::CredentialTransactionJournalConflict { .. }
    ));
    let published_id = published_id
        .lock()
        .expect("published id lock")
        .clone()
        .expect("published id");
    assert!(store.contains(&published_id));
    assert!(!store.deleted(&published_id));
    assert!(repo.paths().credential_transaction_journal().exists());
}

#[test]
fn unanchored_credential_intent_never_triggers_store_deletion() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_test_connection(&repo);
    let store = FaultCredentialStore::default();
    store.set_after_verified(|_| panic!("leave source intent"));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = repo.replace_credential_bundle(
            1,
            &connection_id,
            "default",
            bundle(Some("secret"), None, None),
            CredentialActivation::MakeActive,
            &store,
        );
    }));
    let journal_path = repo.paths().credential_transaction_journal();
    let mut journal: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal_path).expect("source intent"))
            .expect("parse source intent");
    journal["source_primary"]["raw_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    let tampered = serde_json::to_vec_pretty(&journal).expect("tampered intent");
    fs::write(&journal_path, &tampered).expect("write tampered intent");
    let primary_before = fs::read(repo.paths().config()).expect("primary before recovery");
    let deletes_before = store.deletes.load(Ordering::SeqCst);

    assert!(matches!(
        repo.reconcile_credentials(&store)
            .expect_err("unanchored source is a conflict"),
        ConfigError::CredentialTransactionJournalConflict { .. }
    ));
    assert_eq!(store.deletes.load(Ordering::SeqCst), deletes_before);
    assert_eq!(fs::read(&journal_path).expect("unchanged intent"), tampered);
    assert_eq!(
        fs::read(repo.paths().config()).expect("unchanged primary"),
        primary_before
    );
}

#[test]
fn failed_gc_is_compactly_carried_across_multiple_rotations() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let connection_id = add_test_connection(&repo);
    let store = FaultCredentialStore::default();
    repo.replace_credential_bundle(
        1,
        &connection_id,
        "default",
        bundle(Some("a"), None, None),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("A");
    repo.replace_credential_bundle(
        2,
        &connection_id,
        "default",
        bundle(Some("b"), None, None),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("B");
    store.set_fail_delete(true);
    for (expected_revision, value) in [(3, "c"), (4, "d")] {
        let outcome = repo
            .replace_credential_bundle(
                expected_revision,
                &connection_id,
                "default",
                bundle(Some(value), None, None),
                CredentialActivation::MakeActive,
                &store,
            )
            .expect("rotation remains live with failed GC");
        assert_eq!(outcome.snapshot().revision(), expected_revision + 1);
        assert!(outcome.warnings().iter().any(|warning| matches!(
            warning,
            CredentialTransactionWarning::CredentialDeleteFailed { .. }
        )));
    }
    assert!(repo.paths().credential_transaction_journal().exists());
    repo.snapshot()
        .expect("compact committed intent remains parseable");
}

#[test]
fn legacy_store_preflight_and_keyring_mapping_fail_before_publication() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{"main":{"addr":"https://example.test","tokens":{"p":{"access_token":"access","service_account_token":"service"}}}}}"#,
    );
    let store = FaultCredentialStore::default();
    store.set_fail_validate_on(2);
    let repo = repository(&temp);
    assert!(matches!(
        repo.initialize(
            &client_id("cli"),
            &store,
            &MemoryLegacyCredentials::default(),
        )
        .expect_err("second backend validation fails before puts"),
        ConfigError::CredentialValidation { .. }
    ));
    assert_eq!(store.puts.load(Ordering::SeqCst), 0);
    assert!(!repo.paths().config().exists());

    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{"main":{"addr":"https://example.test","tokens":{"p":{"access_token":"access","service_account_token":"service"}}}}}"#,
    );
    let store = FaultCredentialStore::default();
    store.set_collide_validate_on(2);
    let repo = repository(&temp);
    assert!(matches!(
        repo.initialize(
            &client_id("cli"),
            &store,
            &MemoryLegacyCredentials::default(),
        )
        .expect_err("second deterministic id conflict is preflighted"),
        ConfigError::CredentialIdConflict { .. }
    ));
    assert_eq!(store.puts.load(Ordering::SeqCst), 0);
    assert!(!repo.paths().config().exists());

    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{"prod":{"addr":"https://example.test","tokens":{"admin::token":{}}}}}"#,
    );
    let source = CountingLegacyCredentials::default();
    let repo = repository(&temp);
    assert!(matches!(
        repo.initialize(&client_id("cli"), &MemoryCredentials::default(), &source)
            .expect_err("ambiguous historical keyring account"),
        ConfigError::AmbiguousLegacyCredentialAccount { .. }
    ));
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    assert!(!repo.paths().config().exists());

    let mapped_locator = locator("prod", "admin", CredentialKind::Access);
    assert_eq!(
        mapped_locator.cli_keyring_account().as_deref(),
        Some("access::prod::admin")
    );
    assert!(locator("prod::admin", "token", CredentialKind::Access)
        .cli_keyring_account()
        .is_none());
    assert!(locator("prod", "admin", CredentialKind::Refresh)
        .cli_keyring_account()
        .is_none());
}

#[test]
fn windows_legacy_case_fold_collisions_fail_before_any_external_io() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{
          "contexts": {
            "Prod": {"addr":"https://one.test","tokens":{"admin":{}}},
            "prod": {"addr":"https://two.test","tokens":{"admin":{}}}
          }
        }"#,
    );
    let source = WindowsLegacyCredentials::verified();
    let store = MemoryCredentials::default();
    let repo = repository(&temp);

    assert!(matches!(
        repo.initialize(&client_id("cli"), &store, &source)
            .expect_err("Windows targets are case-insensitive"),
        ConfigError::LegacyCredentialAccountConflict { .. }
    ));
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    assert_eq!(store.len(), 0);
    assert!(!repo.paths().config().exists());

    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{
          "contexts": {
            "Prod": {"addr":"https://one.test","tokens":{"admin":{"access_token":"inline","service_account_token":"inline-service"}}},
            "prod": {"addr":"https://two.test","tokens":{"admin":{}}}
          }
        }"#,
    );
    let source = WindowsLegacyCredentials::verified();
    let repo = repository(&temp);
    assert!(matches!(
        repo.initialize(&client_id("cli"), &MemoryCredentials::default(), &source,)
            .expect_err("inline aliases still participate when another lookup is needed"),
        ConfigError::LegacyCredentialAccountConflict { .. }
    ));
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    assert!(!repo.paths().config().exists());

    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{
          "contexts": {
            "Prod": {"addr":"https://one.test","tokens":{"admin":{"access_token":"one","service_account_token":"one-service"}}},
            "prod": {"addr":"https://two.test","tokens":{"admin":{"access_token":"two","service_account_token":"two-service"}}}
          }
        }"#,
    );
    let source = WindowsLegacyCredentials::unverified();
    let store = MemoryCredentials::default();
    let repo = repository(&temp);
    repo.initialize(&client_id("cli"), &store, &source)
        .expect("fully inline case variants do not consult Windows keyring");
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    assert_eq!(store.len(), 4);

    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{"Продукт":{"addr":"https://unicode.test","tokens":{"admin":{}}}}}"#,
    );
    let source = WindowsLegacyCredentials::verified();
    let repo = repository(&temp);
    assert!(matches!(
        repo.initialize(&client_id("cli"), &MemoryCredentials::default(), &source,)
            .expect_err("non-ASCII Windows folding cannot be proven before lookup"),
        ConfigError::AmbiguousLegacyCredentialAccount { .. }
    ));
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    assert!(!repo.paths().config().exists());
}

#[test]
fn exact_legacy_backends_keep_case_distinct_namespaces() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{
          "contexts": {
            "Prod": {"addr":"https://one.test","tokens":{"admin":{}}},
            "prod": {"addr":"https://two.test","tokens":{"admin":{}}}
          }
        }"#,
    );
    let source = MemoryLegacyCredentials::default()
        .with(
            locator("Prod", "admin", CredentialKind::Access),
            "upper-secret",
        )
        .with(
            locator("prod", "admin", CredentialKind::Access),
            "lower-secret",
        );
    let store = MemoryCredentials::default();
    let repo = repository(&temp);

    repo.initialize(&client_id("cli"), &store, &source)
        .expect("exact backend keeps case-distinct accounts");
    assert_eq!(store.len(), 2);
}

#[test]
fn unverified_windows_legacy_reader_fails_closed_but_all_inline_skips_it() {
    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{"Prod":{"addr":"https://example.test","tokens":{"admin":{}}}}}"#,
    );
    let source = WindowsLegacyCredentials::unverified();
    let store = MemoryCredentials::default();
    let repo = repository(&temp);
    assert!(matches!(
        repo.initialize(&client_id("cli"), &store, &source)
            .expect_err("backend cannot prove the matched tuple"),
        ConfigError::AmbiguousLegacyCredentialAccount { .. }
    ));
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    assert_eq!(store.len(), 0);
    assert!(!repo.paths().config().exists());

    let temp = TempDir::new().expect("tempdir");
    write_legacy(
        &temp,
        r#"{"contexts":{"Prod":{"addr":"https://example.test","tokens":{"admin":{"access_token":"access","refresh_token":"refresh","service_account_token":"service"}}}}}"#,
    );
    let source = WindowsLegacyCredentials::unverified();
    let store = MemoryCredentials::default();
    let repo = repository(&temp);
    repo.initialize(&client_id("cli"), &store, &source)
        .expect("all-inline migration never needs the case-insensitive reader");
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    assert_eq!(store.len(), 3);
}

#[test]
fn credential_profile_removal_is_journaled_zero_write_and_requires_explicit_fallback() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let store = FaultCredentialStore::default();
    let connection_id = add_test_connection(&repo);
    repo.replace_credential_bundle(
        1,
        &connection_id,
        "first",
        bundle(Some("first"), None, None),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("first profile");
    repo.replace_credential_bundle(
        2,
        &connection_id,
        "second",
        bundle(Some("second"), None, None),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("second profile");
    let second_id = profile_credentials(
        repo.snapshot().expect("before revoke").config(),
        &connection_id,
        "second",
    )[&CredentialKind::Access]
        .clone();
    let calls = (
        store.validations.load(Ordering::SeqCst),
        store.reads.load(Ordering::SeqCst),
        store.puts.load(Ordering::SeqCst),
    );
    assert!(matches!(
        repo.remove_credential_profile(
            3,
            &connection_id,
            "missing",
            ActiveCredentialAfterRemoval::RequireInactive,
            &store,
        )
        .expect_err("missing profile"),
        ConfigError::MissingCredentialProfile { .. }
    ));
    assert!(matches!(
        repo.remove_credential_profile(
            3,
            &connection_id,
            "second",
            ActiveCredentialAfterRemoval::RequireInactive,
            &store,
        )
        .expect_err("active profile needs explicit fallback"),
        ConfigError::ActiveCredentialRemoval { .. }
    ));
    assert!(matches!(
        repo.remove_credential_profile(
            2,
            &connection_id,
            "second",
            ActiveCredentialAfterRemoval::Activate("first".to_string()),
            &store,
        )
        .expect_err("stale revision"),
        ConfigError::RevisionConflict { .. }
    ));
    let removed = repo
        .remove_credential_profile(
            3,
            &connection_id,
            "second",
            ActiveCredentialAfterRemoval::Activate("first".to_string()),
            &store,
        )
        .expect("remove with explicit fallback");
    assert_eq!(removed.snapshot().revision(), 4);
    let connection = &removed.snapshot().config().connections[&connection_id];
    assert!(!connection.credential_profiles().contains_key("second"));
    assert_eq!(connection.active_credential(), Some("first"));
    assert_eq!(
        (
            store.validations.load(Ordering::SeqCst),
            store.reads.load(Ordering::SeqCst),
            store.puts.load(Ordering::SeqCst),
        ),
        calls
    );
    let journal: serde_json::Value = serde_json::from_slice(
        &fs::read(repo.paths().credential_transaction_journal()).expect("revoke journal"),
    )
    .expect("parse revoke journal");
    assert_eq!(journal["journal_version"], json!(2));
    assert_eq!(journal["new_ids"], json!([]));
    assert!(
        store.contains(&second_id),
        "backup keeps predecessor recoverable"
    );

    repo.update_connection(&connection_id, |metadata| {
        metadata.name = "rotate revoked predecessor".to_string();
        Ok(())
    })
    .expect("rotate backup");
    store.set_fail_delete(true);
    let deferred = repo
        .reconcile_credentials(&store)
        .expect("delete failure is a warning");
    assert!(deferred.warnings().iter().any(|warning| matches!(
        warning,
        CredentialTransactionWarning::CredentialDeleteFailed { .. }
    )));
    assert!(store.contains(&second_id));
    store.set_fail_delete(false);
    repo.reconcile_credentials(&store)
        .expect("retry retired credential deletion");
    assert!(!store.contains(&second_id));

    repo.remove_credential_profile(
        5,
        &connection_id,
        "first",
        ActiveCredentialAfterRemoval::Clear,
        &store,
    )
    .expect("remove last profile with explicit clear");
    let final_snapshot = repo.snapshot().expect("final snapshot");
    assert!(final_snapshot.config().connections[&connection_id]
        .credential_profiles()
        .is_empty());
    assert_eq!(
        final_snapshot.config().connections[&connection_id].active_credential(),
        None
    );
}

#[test]
fn anchored_profile_removal_rebases_and_preserves_a_new_active_selection() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let store = FaultCredentialStore::default();
    let connection_id = add_bound_test_connection(&repo);
    repo.replace_credential_bundle(
        1,
        &connection_id,
        "expired",
        bundle(Some("expired-access"), Some("expired-refresh"), None),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("expired profile");
    repo.replace_credential_bundle(
        2,
        &connection_id,
        "selected",
        bundle(Some("selected-access"), Some("selected-refresh"), None),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("selected profile");
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "expired")
        .expect("expired profile anchor");

    repo.update_connection(&connection_id, |metadata| {
        metadata.name = "renamed while refresh was in flight".to_string();
        Ok(())
    })
    .expect("unrelated metadata update");
    let calls = store.call_counts();
    let outcome = repo
        .remove_credential_profile_if_matches(&anchor, ActiveCredentialAfterRemoval::Clear, &store)
        .expect("anchored removal rebases over unrelated changes");

    assert_eq!(outcome.snapshot().revision(), 5);
    let connection = &outcome.snapshot().config().connections[&connection_id];
    assert!(!connection.credential_profiles().contains_key("expired"));
    assert!(connection.credential_profiles().contains_key("selected"));
    assert_eq!(connection.active_credential(), Some("selected"));
    assert_eq!(
        store.call_counts(),
        calls,
        "zero-write revoke uses no ports"
    );
}

#[test]
fn anchored_profile_removal_rejects_a_rotated_target_before_port_calls() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize_empty(&repo);
    let store = FaultCredentialStore::default();
    let connection_id = add_bound_test_connection(&repo);
    repo.replace_credential_bundle(
        1,
        &connection_id,
        "profile",
        bundle(Some("access-a"), Some("refresh-a"), None),
        CredentialActivation::MakeActive,
        &store,
    )
    .expect("initial profile");
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "profile")
        .expect("profile anchor");
    repo.replace_credential_bundle(
        2,
        &connection_id,
        "profile",
        bundle(Some("access-b"), Some("refresh-b"), None),
        CredentialActivation::Preserve,
        &store,
    )
    .expect("rotate profile after anchor");
    let calls = store.call_counts();

    let error = repo
        .remove_credential_profile_if_matches(&anchor, ActiveCredentialAfterRemoval::Clear, &store)
        .expect_err("stale anchor must not revoke a new profile generation");
    assert!(matches!(
        error,
        ConfigError::CredentialProfileAnchorConflict {
            field: "credentials",
            ..
        }
    ));
    assert_eq!(store.call_counts(), calls);
    assert!(
        repo.snapshot().expect("snapshot").config().connections[&connection_id]
            .credential_profiles()
            .contains_key("profile")
    );
}

#[test]
fn credential_journal_v1_and_zero_write_v2_recover_after_crash() {
    let v1_temp = TempDir::new().expect("v1 tempdir");
    let v1_repo = repository(&v1_temp);
    initialize_empty(&v1_repo);
    let v1_connection = add_test_connection(&v1_repo);
    let v1_store = FaultCredentialStore::default();
    v1_store.set_after_verified(|_| panic!("leave precommit journal"));
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = v1_repo.replace_credential_bundle(
            1,
            &v1_connection,
            "default",
            bundle(Some("v1-secret"), None, None),
            CredentialActivation::MakeActive,
            &v1_store,
        );
    }));
    assert!(crashed.is_err());
    let mut v1_journal: serde_json::Value = serde_json::from_slice(
        &fs::read(v1_repo.paths().credential_transaction_journal()).expect("v2 intent"),
    )
    .expect("parse intent");
    v1_journal["journal_version"] = json!(1);
    fs::write(
        v1_repo.paths().credential_transaction_journal(),
        serde_json::to_vec_pretty(&v1_journal).expect("serialize v1 intent"),
    )
    .expect("write v1 intent");
    v1_repo
        .initialize(
            &client_id("test"),
            &v1_store,
            &MemoryLegacyCredentials::default(),
        )
        .expect("recover v1 source intent");
    assert!(!v1_repo.paths().credential_transaction_journal().exists());
    assert_eq!(v1_store.len(), 0);

    let v2_temp = TempDir::new().expect("v2 tempdir");
    let v2_repo = repository(&v2_temp);
    initialize_empty(&v2_repo);
    let v2_connection = add_test_connection(&v2_repo);
    let v2_store = FaultCredentialStore::default();
    v2_repo
        .replace_credential_bundle(
            1,
            &v2_connection,
            "default",
            bundle(Some("kept-after-abort"), None, None),
            CredentialActivation::MakeActive,
            &v2_store,
        )
        .expect("source profile");
    let source_primary = fs::read(v2_repo.paths().config()).expect("source primary");
    let source_backup = fs::read(v2_repo.paths().backup()).expect("source backup");
    let source_id = profile_credentials(
        v2_repo.snapshot().expect("source snapshot").config(),
        &v2_connection,
        "default",
    )[&CredentialKind::Access]
        .clone();
    v2_repo
        .remove_credential_profile(
            2,
            &v2_connection,
            "default",
            ActiveCredentialAfterRemoval::Clear,
            &v2_store,
        )
        .expect("publish revoke and leave deferred journal");
    let revoke_journal =
        fs::read(v2_repo.paths().credential_transaction_journal()).expect("revoke journal");
    fs::write(v2_repo.paths().config(), &source_primary).expect("rewind primary");
    fs::write(v2_repo.paths().backup(), &source_backup).expect("rewind backup");
    fs::write(
        v2_repo.paths().credential_transaction_journal(),
        &revoke_journal,
    )
    .expect("restore source-state revoke journal");
    v2_repo
        .initialize(
            &client_id("test"),
            &v2_store,
            &MemoryLegacyCredentials::default(),
        )
        .expect("abort zero-write revoke source intent");
    assert!(v2_repo
        .snapshot()
        .expect("recovered source")
        .config()
        .connections[&v2_connection]
        .credential_profiles()
        .contains_key("default"));
    assert!(v2_store.contains(&source_id));
    assert!(!v2_repo.paths().credential_transaction_journal().exists());
}

#[test]
fn pending_auth_intent_keeps_reads_available_and_blocks_writers_restore_and_initialize_ports() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    let store = MemoryCredentials::default();
    repo.initialize(
        &client_id("test"),
        &store,
        &MemoryLegacyCredentials::default(),
    )
    .expect("initialize");
    let first_id = ConnectionId::deterministic("first", "https://first.auth.test");
    repo.upsert_connection(
        first_id,
        ConnectionMetadata::new("first", "https://first.auth.test"),
    )
    .expect("create backup");
    fs::write(temp.path().join("client-auth.intent.json"), b"{}").expect("pending auth intent");

    assert!(
        repo.snapshot().is_ok(),
        "read-only snapshot must remain available"
    );
    let writes = store.write_attempt.load(Ordering::SeqCst);
    let second_id = ConnectionId::deterministic("second", "https://second.auth.test");
    assert!(matches!(
        repo.upsert_connection(
            second_id,
            ConnectionMetadata::new("second", "https://second.auth.test"),
        ),
        Err(ConfigError::AuthOperationRecoveryRequired { .. })
    ));
    assert!(matches!(
        repo.reconcile_credentials(&store),
        Err(ConfigError::AuthOperationRecoveryRequired { .. })
    ));
    assert!(matches!(
        repo.restore_backup(),
        Err(ConfigError::AuthOperationRecoveryRequired { .. })
    ));
    assert_eq!(store.write_attempt.load(Ordering::SeqCst), writes);

    let missing_primary = TempDir::new().expect("missing-primary tempdir");
    fs::write(
        missing_primary.path().join("client-auth.intent.json"),
        b"{}",
    )
    .expect("stale auth intent");
    let missing_repo = repository(&missing_primary);
    let missing_store = MemoryCredentials::default();
    let legacy = CountingLegacyCredentials::default();
    assert!(matches!(
        missing_repo.initialize(&client_id("test"), &missing_store, &legacy),
        Err(ConfigError::AuthOperationRecoveryRequired { .. })
    ));
    assert_eq!(missing_store.write_attempt.load(Ordering::SeqCst), 0);
    assert_eq!(legacy.reads.load(Ordering::SeqCst), 0);
}
