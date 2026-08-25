use std::fmt::Write as _;
use std::sync::Arc;

use base64::Engine;
use zeroize::Zeroize;

use crate::{
    validate_secret_store_namespace, Keystore, KeystoreError, KeystoreStatus, KeystoreStatusReason,
    LegacySecretSource, SecretStore, SecretValue,
};

const WINDOWS_SECRET_MAX_UTF16_BYTES: usize = 2560;
const WINDOWS_ACCOUNT_MAX_BYTES: usize = 513;
const WINDOWS_TARGET_MAX_BYTES: usize = 32_767;
const WINDOWS_NAMESPACE_METADATA_INPUT_MAX_BYTES: usize = 192;
const GENERIC_WINDOWS_TARGET_PREFIX: &str = "zann-secret-store:v2:";
const GENERIC_UNIX_SERVICE_PREFIX: &str = "zann-secret-store-v2:";
const GENERIC_UNIX_ACCOUNT_PREFIX: &str = "zann-secret-account-v2:";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenericNamespaceStrategy {
    WindowsTarget,
    VersionedService,
}

fn platform_namespace_strategy() -> GenericNamespaceStrategy {
    if cfg!(target_os = "windows") {
        GenericNamespaceStrategy::WindowsTarget
    } else {
        GenericNamespaceStrategy::VersionedService
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BackendEntry {
    service: String,
    account: String,
    target: Option<String>,
}

fn push_hex(output: &mut String, input: &str) {
    for byte in input.as_bytes() {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
}

/// Encode the complete logical tuple into a lowercase-ASCII Windows target.
///
/// Lengths are UTF-8 byte lengths. Fixed-width length prefixes and hex make
/// this representation injective, canonical under Windows' case-insensitive
/// target matching, and disjoint from keyring-rs' historical
/// `account.service` targets.
fn generic_windows_target(service: &str, account: &str) -> String {
    let mut target = String::with_capacity(
        GENERIC_WINDOWS_TARGET_PREFIX.len() + 18 + (service.len() + account.len()) * 2,
    );
    target.push_str(GENERIC_WINDOWS_TARGET_PREFIX);
    write!(target, "{:08x}:", service.len()).expect("writing to String cannot fail");
    push_hex(&mut target, service);
    target.push(':');
    write!(target, "{:08x}:", account.len()).expect("writing to String cannot fail");
    push_hex(&mut target, account);
    target
}

fn generic_versioned_service(service: &str) -> String {
    let mut physical =
        String::with_capacity(GENERIC_UNIX_SERVICE_PREFIX.len() + 9 + service.len() * 2);
    physical.push_str(GENERIC_UNIX_SERVICE_PREFIX);
    write!(physical, "{:08x}:", service.len()).expect("writing to String cannot fail");
    push_hex(&mut physical, service);
    physical
}

fn generic_versioned_account(account: &str) -> String {
    let mut physical =
        String::with_capacity(GENERIC_UNIX_ACCOUNT_PREFIX.len() + 9 + account.len() * 2);
    physical.push_str(GENERIC_UNIX_ACCOUNT_PREFIX);
    write!(physical, "{:08x}:", account.len()).expect("writing to String cannot fail");
    push_hex(&mut physical, account);
    physical
}

fn generic_backend_entry(
    service: &str,
    account: &str,
    strategy: GenericNamespaceStrategy,
) -> BackendEntry {
    match strategy {
        GenericNamespaceStrategy::WindowsTarget => BackendEntry {
            service: service.to_string(),
            account: account.to_string(),
            target: Some(generic_windows_target(service, account)),
        },
        GenericNamespaceStrategy::VersionedService => BackendEntry {
            service: generic_versioned_service(service),
            account: generic_versioned_account(account),
            target: None,
        },
    }
}

fn legacy_backend_entry(service: &str, account: &str) -> BackendEntry {
    BackendEntry {
        service: service.to_string(),
        account: account.to_string(),
        target: None,
    }
}

#[derive(Clone, Copy)]
struct NamespaceLimits {
    account_max_bytes: usize,
    target_max_bytes: usize,
    metadata_input_max_bytes: usize,
}

const WINDOWS_NAMESPACE_LIMITS: NamespaceLimits = NamespaceLimits {
    account_max_bytes: WINDOWS_ACCOUNT_MAX_BYTES,
    target_max_bytes: WINDOWS_TARGET_MAX_BYTES,
    metadata_input_max_bytes: WINDOWS_NAMESPACE_METADATA_INPUT_MAX_BYTES,
};

fn platform_secret_utf16_byte_limit() -> Option<usize> {
    if cfg!(target_os = "windows") {
        Some(WINDOWS_SECRET_MAX_UTF16_BYTES)
    } else {
        None
    }
}

fn platform_namespace_limits() -> Option<NamespaceLimits> {
    if cfg!(target_os = "windows") {
        Some(WINDOWS_NAMESPACE_LIMITS)
    } else {
        None
    }
}

fn validate_keyring_namespace(
    service: &str,
    account: &str,
    limits: Option<NamespaceLimits>,
    strategy: GenericNamespaceStrategy,
) -> Result<(), KeystoreError> {
    validate_secret_store_namespace(service, account)?;
    let Some(limits) = limits else {
        return Ok(());
    };

    let metadata_input_bytes = service.len().saturating_add(account.len());
    let target_bytes = match strategy {
        GenericNamespaceStrategy::WindowsTarget => generic_windows_target(service, account).len(),
        GenericNamespaceStrategy::VersionedService => metadata_input_bytes.saturating_add(1),
    };
    if account.len() > limits.account_max_bytes
        || target_bytes > limits.target_max_bytes
        || metadata_input_bytes > limits.metadata_input_max_bytes
    {
        return Err(KeystoreError::InvalidNamespace);
    }
    Ok(())
}

fn validate_utf16_byte_limit(
    secret: &SecretValue,
    maximum_bytes: usize,
) -> Result<(), KeystoreError> {
    let encoded_bytes = secret
        .expose_secret()
        .encode_utf16()
        .count()
        .saturating_mul(2);
    if encoded_bytes > maximum_bytes {
        return Err(KeystoreError::SecretTooLarge { maximum_bytes });
    }
    Ok(())
}

trait KeyringBackend: Send + Sync {
    fn set_password(&self, entry: &BackendEntry, password: &str) -> keyring::Result<()>;

    fn get_password(&self, entry: &BackendEntry) -> keyring::Result<String>;

    fn delete_password(&self, entry: &BackendEntry) -> keyring::Result<()>;

    fn get_legacy_password(&self, service: &str, account: &str) -> Result<String, KeystoreError>;
}

struct OsKeyringBackend;

impl KeyringBackend for OsKeyringBackend {
    fn set_password(&self, entry: &BackendEntry, password: &str) -> keyring::Result<()> {
        keyring_entry(entry)?.set_password(password)
    }

    fn get_password(&self, entry: &BackendEntry) -> keyring::Result<String> {
        keyring_entry(entry)?.get_password()
    }

    fn delete_password(&self, entry: &BackendEntry) -> keyring::Result<()> {
        keyring_entry(entry)?.delete_password()
    }

    fn get_legacy_password(&self, service: &str, account: &str) -> Result<String, KeystoreError> {
        get_os_legacy_password(service, account)
    }
}

fn keyring_entry(entry: &BackendEntry) -> keyring::Result<keyring::Entry> {
    match entry.target.as_deref() {
        Some(target) => keyring::Entry::new_with_target(target, &entry.service, &entry.account),
        None => keyring::Entry::new(&entry.service, &entry.account),
    }
}

#[cfg(target_os = "windows")]
fn get_os_legacy_password(service: &str, account: &str) -> Result<String, KeystoreError> {
    let entry = keyring::Entry::new(service, account).map_err(map_error)?;
    let credential = entry
        .get_credential()
        .downcast_ref::<keyring::windows::WinCredential>()
        .ok_or_else(|| KeystoreError::Internal {
            message: "OS credential backend identity is unavailable".to_string(),
        })?;
    let before = credential.get_credential().map_err(map_error)?;
    validate_windows_legacy_identity(service, account, &before.target_name, &before.username)?;
    let mut secret = entry.get_password().map_err(map_error)?;
    let after = match credential.get_credential() {
        Ok(after) => after,
        Err(error) => {
            secret.zeroize();
            return Err(map_error(error));
        }
    };
    if let Err(error) =
        validate_windows_legacy_identity(service, account, &after.target_name, &after.username)
    {
        secret.zeroize();
        return Err(error);
    }
    Ok(secret)
}

#[cfg(not(target_os = "windows"))]
fn get_os_legacy_password(service: &str, account: &str) -> Result<String, KeystoreError> {
    keyring::Entry::new(service, account)
        .and_then(|entry| entry.get_password())
        .map_err(map_error)
}

#[cfg(any(target_os = "windows", test))]
fn validate_windows_legacy_identity(
    service: &str,
    account: &str,
    actual_target: &str,
    actual_account: &str,
) -> Result<(), KeystoreError> {
    let expected_target = format!("{account}.{service}");
    if actual_target != expected_target || actual_account != account {
        return Err(KeystoreError::InvalidNamespace);
    }
    Ok(())
}

fn map_error(err: keyring::Error) -> KeystoreError {
    match err {
        keyring::Error::NoEntry => KeystoreError::NotFound,
        keyring::Error::BadEncoding(mut bytes) => {
            bytes.zeroize();
            KeystoreError::Internal {
                message: "stored secret is not valid UTF-8".to_string(),
            }
        }
        keyring::Error::Ambiguous(_) => KeystoreError::Internal {
            message: "multiple matching credentials in OS secret store".to_string(),
        },
        other => KeystoreError::Internal {
            message: other.to_string(),
        },
    }
}

/// Generic secret storage backed by the OS credential store: Keychain on
/// macOS, Credential Manager on Windows, and Secret Service on Linux.
///
/// The physical namespace is versioned and disjoint from historical keyring-rs
/// entries. Windows uses an explicit, canonical target through
/// `Entry::new_with_target`; Linux and macOS use an injectively encoded service
/// name. In addition to the common namespace contract, the Windows backend
/// caps the account at 513 UTF-8 bytes and the generated target at 32,767
/// bytes. It also limits `service.len() + account.len()` to 192 bytes so
/// keyring-rs can safely build its metadata within Credential Manager's
/// smaller comment field. These backend limits do not narrow Linux or macOS
/// stores.
#[derive(Clone)]
pub struct KeyringSecretStore {
    backend: Arc<dyn KeyringBackend>,
    namespace_limits: Option<NamespaceLimits>,
    namespace_strategy: GenericNamespaceStrategy,
    secret_utf16_byte_limit: Option<usize>,
}

impl KeyringSecretStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_backend(backend: Arc<dyn KeyringBackend>) -> Self {
        Self {
            backend,
            namespace_limits: platform_namespace_limits(),
            namespace_strategy: platform_namespace_strategy(),
            secret_utf16_byte_limit: platform_secret_utf16_byte_limit(),
        }
    }

    #[cfg(test)]
    fn with_backend_and_strategy(
        backend: Arc<dyn KeyringBackend>,
        namespace_strategy: GenericNamespaceStrategy,
    ) -> Self {
        Self {
            backend,
            namespace_limits: match namespace_strategy {
                GenericNamespaceStrategy::WindowsTarget => Some(WINDOWS_NAMESPACE_LIMITS),
                GenericNamespaceStrategy::VersionedService => None,
            },
            namespace_strategy,
            secret_utf16_byte_limit: None,
        }
    }

    #[cfg(test)]
    fn with_backend_and_limit(backend: Arc<dyn KeyringBackend>, maximum_bytes: usize) -> Self {
        Self {
            backend,
            namespace_limits: platform_namespace_limits(),
            namespace_strategy: platform_namespace_strategy(),
            secret_utf16_byte_limit: Some(maximum_bytes),
        }
    }

    #[cfg(test)]
    fn with_backend_and_namespace_limits(
        backend: Arc<dyn KeyringBackend>,
        limits: NamespaceLimits,
    ) -> Self {
        Self {
            backend,
            namespace_limits: Some(limits),
            namespace_strategy: GenericNamespaceStrategy::WindowsTarget,
            secret_utf16_byte_limit: platform_secret_utf16_byte_limit(),
        }
    }
}

impl Default for KeyringSecretStore {
    fn default() -> Self {
        Self {
            backend: Arc::new(OsKeyringBackend),
            namespace_limits: platform_namespace_limits(),
            namespace_strategy: platform_namespace_strategy(),
            secret_utf16_byte_limit: platform_secret_utf16_byte_limit(),
        }
    }
}

impl SecretStore for KeyringSecretStore {
    fn validate_namespace(&self, service: &str, account: &str) -> Result<(), KeystoreError> {
        validate_keyring_namespace(
            service,
            account,
            self.namespace_limits,
            self.namespace_strategy,
        )
    }

    fn validate(&self, secret: &SecretValue) -> Result<(), KeystoreError> {
        match self.secret_utf16_byte_limit {
            Some(maximum_bytes) => validate_utf16_byte_limit(secret, maximum_bytes),
            None => Ok(()),
        }
    }

    fn put(&self, service: &str, account: &str, secret: SecretValue) -> Result<(), KeystoreError> {
        self.validate_namespace(service, account)?;
        self.validate(&secret)?;
        let entry = generic_backend_entry(service, account, self.namespace_strategy);
        self.backend
            .set_password(&entry, secret.expose_secret())
            .map_err(map_error)
    }

    fn get(&self, service: &str, account: &str) -> Result<Option<SecretValue>, KeystoreError> {
        self.validate_namespace(service, account)?;
        let entry = generic_backend_entry(service, account, self.namespace_strategy);
        match self.backend.get_password(&entry) {
            Ok(secret) => Ok(Some(SecretValue::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(map_error(err)),
        }
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), KeystoreError> {
        self.validate_namespace(service, account)?;
        let entry = generic_backend_entry(service, account, self.namespace_strategy);
        match self.backend.delete_password(&entry) {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(map_error(err)),
        }
    }
}

/// Read-only adapter for entries created with keyring-rs' historical default
/// mapping. It is intentionally not a [`SecretStore`].
#[derive(Clone)]
pub struct KeyringLegacySecretSource {
    backend: Arc<dyn KeyringBackend>,
}

impl KeyringLegacySecretSource {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_backend(backend: Arc<dyn KeyringBackend>) -> Self {
        Self { backend }
    }
}

impl Default for KeyringLegacySecretSource {
    fn default() -> Self {
        Self {
            backend: Arc::new(OsKeyringBackend),
        }
    }
}

impl LegacySecretSource for KeyringLegacySecretSource {
    fn validate_legacy_namespace(&self, service: &str, account: &str) -> Result<(), KeystoreError> {
        validate_keyring_namespace(
            service,
            account,
            platform_namespace_limits(),
            GenericNamespaceStrategy::VersionedService,
        )
    }

    fn get_legacy(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<SecretValue>, KeystoreError> {
        self.validate_legacy_namespace(service, account)?;
        match self.backend.get_legacy_password(service, account) {
            Ok(secret) => Ok(Some(SecretValue::new(secret))),
            Err(KeystoreError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// Compatibility adapter for the existing device-wrapping-key API.
pub struct KeyringKeystore {
    backend: Arc<dyn KeyringBackend>,
    service: String,
    account: String,
}

impl KeyringKeystore {
    #[must_use]
    pub fn new(service: &str, account: &str) -> Self {
        Self {
            backend: Arc::new(OsKeyringBackend),
            service: service.to_string(),
            account: account.to_string(),
        }
    }

    #[cfg(test)]
    fn with_backend(backend: Arc<dyn KeyringBackend>, service: &str, account: &str) -> Self {
        Self {
            backend,
            service: service.to_string(),
            account: account.to_string(),
        }
    }
}

impl Keystore for KeyringKeystore {
    fn status(&self) -> KeystoreStatus {
        if let Err(err) = validate_secret_store_namespace(&self.service, &self.account) {
            return KeystoreStatus {
                supported: false,
                biometrics_available: false,
                reason: Some(KeystoreStatusReason::Unavailable),
                message: Some(err.to_string()),
            };
        }
        match self
            .backend
            .get_legacy_password(&self.service, &self.account)
        {
            Ok(_) | Err(KeystoreError::NotFound) => KeystoreStatus {
                supported: true,
                biometrics_available: false,
                reason: None,
                message: None,
            },
            Err(err) => KeystoreStatus {
                supported: false,
                biometrics_available: false,
                reason: Some(KeystoreStatusReason::Unavailable),
                message: Some(err.to_string()),
            },
        }
    }

    fn store_dwk(&self, dwk: &[u8]) -> Result<(), KeystoreError> {
        validate_secret_store_namespace(&self.service, &self.account)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(dwk);
        let entry = legacy_backend_entry(&self.service, &self.account);
        self.backend
            .set_password(&entry, &encoded)
            .map_err(map_error)
    }

    fn load_dwk(&self) -> Result<Option<Vec<u8>>, KeystoreError> {
        validate_secret_store_namespace(&self.service, &self.account)?;
        let encoded = match self
            .backend
            .get_legacy_password(&self.service, &self.account)
        {
            Ok(encoded) => SecretValue::new(encoded),
            Err(KeystoreError::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.expose_secret())
            .map_err(|_| KeystoreError::Internal {
                message: "stored key is not valid base64".to_string(),
            })?;
        Ok(Some(bytes))
    }

    fn delete_dwk(&self) -> Result<(), KeystoreError> {
        validate_secret_store_namespace(&self.service, &self.account)?;
        let entry = legacy_backend_entry(&self.service, &self.account);
        match self.backend.delete_password(&entry) {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(map_error(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use keyring::credential::CredentialApi;
    use zeroize::Zeroizing;

    use super::*;

    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    enum EntryKey {
        Default { service: String, account: String },
        Target(String),
    }

    #[derive(Default)]
    struct MemoryBackend {
        entries: Mutex<HashMap<EntryKey, Zeroizing<String>>>,
    }

    impl MemoryBackend {
        fn entry_key(entry: &BackendEntry) -> EntryKey {
            match &entry.target {
                Some(target) => EntryKey::Target(target.clone()),
                None => EntryKey::Default {
                    service: entry.service.clone(),
                    account: entry.account.clone(),
                },
            }
        }

        fn raw_entry_value(&self, entry: &BackendEntry) -> Option<String> {
            self.entries
                .lock()
                .expect("memory keyring lock")
                .get(&Self::entry_key(entry))
                .map(|value| value.as_str().to_string())
        }

        fn raw_legacy_value(&self, service: &str, account: &str) -> Option<String> {
            self.raw_entry_value(&legacy_backend_entry(service, account))
        }

        fn raw_generic_value(
            &self,
            service: &str,
            account: &str,
            strategy: GenericNamespaceStrategy,
        ) -> Option<String> {
            self.raw_entry_value(&generic_backend_entry(service, account, strategy))
        }

        fn seed_entry(&self, entry: &BackendEntry, value: &str) {
            self.entries
                .lock()
                .expect("memory keyring lock")
                .insert(Self::entry_key(entry), Zeroizing::new(value.to_string()));
        }

        fn seed_legacy(&self, service: &str, account: &str, value: &str) {
            self.seed_entry(&legacy_backend_entry(service, account), value);
        }
    }

    impl KeyringBackend for MemoryBackend {
        fn set_password(&self, entry: &BackendEntry, password: &str) -> keyring::Result<()> {
            self.seed_entry(entry, password);
            Ok(())
        }

        fn get_password(&self, entry: &BackendEntry) -> keyring::Result<String> {
            self.raw_entry_value(entry).ok_or(keyring::Error::NoEntry)
        }

        fn delete_password(&self, entry: &BackendEntry) -> keyring::Result<()> {
            match self
                .entries
                .lock()
                .expect("memory keyring lock")
                .remove(&Self::entry_key(entry))
            {
                Some(_) => Ok(()),
                None => Err(keyring::Error::NoEntry),
            }
        }

        fn get_legacy_password(
            &self,
            service: &str,
            account: &str,
        ) -> Result<String, KeystoreError> {
            self.raw_legacy_value(service, account)
                .ok_or(KeystoreError::NotFound)
        }
    }

    fn memory_store() -> (KeyringSecretStore, Arc<MemoryBackend>) {
        let backend = Arc::new(MemoryBackend::default());
        let store = KeyringSecretStore::with_backend(backend.clone());
        (store, backend)
    }

    #[test]
    fn generic_store_round_trips_values_and_isolates_namespaces() {
        let (store, _) = memory_store();

        assert!(store.get("service-a", "account-a").unwrap().is_none());
        store
            .put("service-a", "account-a", SecretValue::new("first secret"))
            .unwrap();

        let loaded = store
            .get("service-a", "account-a")
            .unwrap()
            .expect("stored secret");
        assert_eq!(loaded.expose_secret(), "first secret");
        assert!(store.get("service-b", "account-a").unwrap().is_none());
        assert!(store.get("service-a", "account-b").unwrap().is_none());
    }

    #[test]
    fn generic_store_replaces_values_and_delete_is_idempotent() {
        let (store, _) = memory_store();

        store
            .put("service", "account", SecretValue::new("first"))
            .unwrap();
        store
            .put("service", "account", SecretValue::new("second"))
            .unwrap();
        let loaded = store
            .get("service", "account")
            .unwrap()
            .expect("stored secret");
        assert_eq!(loaded.expose_secret(), "second");

        store.delete("service", "account").unwrap();
        store.delete("service", "account").unwrap();
        assert!(store.get("service", "account").unwrap().is_none());
    }

    #[test]
    fn windows_targets_are_canonical_and_injective_under_case_folding() {
        let upper = generic_windows_target("zann", "Prod");
        let lower = generic_windows_target("zann", "prod");
        let split_left = generic_windows_target("ab", "c");
        let split_right = generic_windows_target("a", "bc");

        assert!(upper.is_ascii());
        assert_eq!(upper, upper.to_ascii_lowercase());
        assert_ne!(upper, lower);
        assert!(!upper.eq_ignore_ascii_case(&lower));
        assert_ne!(split_left, split_right);
        assert!(upper.starts_with(GENERIC_WINDOWS_TARGET_PREFIX));
        assert!(!upper.eq_ignore_ascii_case("dwk.zann"));
    }

    #[test]
    fn versioned_service_namespace_encodes_both_tuple_parts() {
        let upper =
            generic_backend_entry("zann", "Prod", GenericNamespaceStrategy::VersionedService);
        let lower =
            generic_backend_entry("zann", "prod", GenericNamespaceStrategy::VersionedService);

        assert_ne!(upper, lower);
        assert!(upper.service.starts_with(GENERIC_UNIX_SERVICE_PREFIX));
        assert!(upper.account.starts_with(GENERIC_UNIX_ACCOUNT_PREFIX));
        assert!(upper.service.is_ascii());
        assert!(upper.account.is_ascii());
        assert_eq!(upper.service, upper.service.to_ascii_lowercase());
        assert_eq!(upper.account, upper.account.to_ascii_lowercase());
        assert_ne!(upper.service, "zann");
        assert_ne!(upper.account, "Prod");
    }

    #[test]
    fn windows_legacy_reader_requires_exact_stored_case_and_account_metadata() {
        validate_windows_legacy_identity(
            "zann-cli",
            "access::Prod::admin",
            "access::Prod::admin.zann-cli",
            "access::Prod::admin",
        )
        .unwrap();
        assert!(matches!(
            validate_windows_legacy_identity(
                "zann-cli",
                "access::Prod::admin",
                "access::prod::admin.zann-cli",
                "access::prod::admin",
            ),
            Err(KeystoreError::InvalidNamespace)
        ));
    }

    #[test]
    fn every_generic_platform_namespace_preserves_legacy_dwk_and_case_variants() {
        for strategy in [
            GenericNamespaceStrategy::WindowsTarget,
            GenericNamespaceStrategy::VersionedService,
        ] {
            let backend = Arc::new(MemoryBackend::default());
            let store = KeyringSecretStore::with_backend_and_strategy(backend.clone(), strategy);
            let keystore = KeyringKeystore::with_backend(
                backend.clone(),
                crate::DWK_SERVICE,
                crate::DWK_ACCOUNT,
            );
            let dwk = [4u8; 32];
            keystore.store_dwk(&dwk).unwrap();

            store
                .put("zann", "dwk", SecretValue::new("generic-lower"))
                .unwrap();
            store
                .put("zann", "DWK", SecretValue::new("generic-upper"))
                .unwrap();
            assert_eq!(
                store
                    .get("zann", "dwk")
                    .unwrap()
                    .expect("lower generic value")
                    .expose_secret(),
                "generic-lower"
            );
            assert_eq!(
                store
                    .get("zann", "DWK")
                    .unwrap()
                    .expect("upper generic value")
                    .expose_secret(),
                "generic-upper"
            );
            assert_eq!(keystore.load_dwk().unwrap(), Some(dwk.to_vec()));

            store.delete("zann", "dwk").unwrap();
            store.delete("zann", "DWK").unwrap();
            assert_eq!(keystore.load_dwk().unwrap(), Some(dwk.to_vec()));
        }
    }

    #[test]
    fn legacy_reader_uses_only_the_historical_namespace() {
        let backend = Arc::new(MemoryBackend::default());
        let generic = KeyringSecretStore::with_backend_and_strategy(
            backend.clone(),
            GenericNamespaceStrategy::WindowsTarget,
        );
        let legacy = KeyringLegacySecretSource::with_backend(backend.clone());
        backend.seed_legacy("zann-cli", "access::Prod::admin", "legacy-secret");
        generic
            .put(
                "zann-cli",
                "access::Prod::admin",
                SecretValue::new("generic-secret"),
            )
            .unwrap();

        assert_eq!(
            legacy
                .get_legacy("zann-cli", "access::Prod::admin")
                .unwrap()
                .expect("legacy value")
                .expose_secret(),
            "legacy-secret"
        );
    }

    #[test]
    fn keyring_namespace_validation_rejects_collisions_before_backend_access() {
        let rejected_service = "b.c";
        let rejected_account = "a";
        let allowed_service = "c";
        let allowed_account = "a.b";
        assert_eq!(
            format!("{rejected_account}.{rejected_service}"),
            format!("{allowed_account}.{allowed_service}")
        );

        let (store, backend) = memory_store();
        backend.seed_legacy(rejected_service, rejected_account, "existing backend value");

        assert!(matches!(
            store.put(
                rejected_service,
                rejected_account,
                SecretValue::new("must-not-reach-backend"),
            ),
            Err(KeystoreError::InvalidNamespace)
        ));
        assert_eq!(
            backend
                .raw_legacy_value(rejected_service, rejected_account)
                .as_deref(),
            Some("existing backend value")
        );
        assert!(matches!(
            store.get(rejected_service, rejected_account),
            Err(KeystoreError::InvalidNamespace)
        ));
        assert!(matches!(
            store.delete(rejected_service, rejected_account),
            Err(KeystoreError::InvalidNamespace)
        ));

        let legacy =
            KeyringKeystore::with_backend(backend.clone(), rejected_service, rejected_account);
        let status = legacy.status();
        assert!(!status.supported);
        assert_eq!(
            status.message.as_deref(),
            Some("invalid OS secret store namespace")
        );

        store
            .put(
                allowed_service,
                allowed_account,
                SecretValue::new("first dotted account"),
            )
            .unwrap();
        store
            .put(
                allowed_service,
                "other.account",
                SecretValue::new("second dotted account"),
            )
            .unwrap();
        assert_eq!(
            store
                .get(allowed_service, allowed_account)
                .unwrap()
                .expect("first dotted account")
                .expose_secret(),
            "first dotted account"
        );
        assert_eq!(
            store
                .get(allowed_service, "other.account")
                .unwrap()
                .expect("second dotted account")
                .expose_secret(),
            "second dotted account"
        );
    }

    #[test]
    fn invalid_namespace_errors_are_sanitized_on_every_error_surface() {
        let service = "private.namespace";
        let account = "account-secret-marker";
        let error = validate_secret_store_namespace(service, account)
            .expect_err("service containing a dot is rejected");
        let display = error.to_string();
        let debug = format!("{error:?}");
        let json = serde_json::to_string(&error).expect("serialize keystore error");

        for rendered in [&display, &debug, &json] {
            assert!(!rendered.contains(service));
            assert!(!rendered.contains(account));
        }
        assert!(matches!(error, KeystoreError::InvalidNamespace));
    }

    #[test]
    fn windows_namespace_capability_enforces_metadata_boundary_before_writes() {
        let backend = Arc::new(MemoryBackend::default());
        let store = KeyringSecretStore::with_backend_and_namespace_limits(
            backend.clone(),
            WINDOWS_NAMESPACE_LIMITS,
        );
        let service = "s".repeat(crate::SECRET_STORE_SERVICE_MAX_BYTES);
        let account_at_limit = "a".repeat(
            WINDOWS_NAMESPACE_METADATA_INPUT_MAX_BYTES - crate::SECRET_STORE_SERVICE_MAX_BYTES,
        );
        let account_over_limit = format!("{account_at_limit}a");

        store
            .put(&service, &account_at_limit, SecretValue::new("accepted"))
            .unwrap();
        assert_eq!(
            backend
                .raw_generic_value(
                    &service,
                    &account_at_limit,
                    GenericNamespaceStrategy::WindowsTarget,
                )
                .as_deref(),
            Some("accepted")
        );

        let error = store
            .put(
                &service,
                &account_over_limit,
                SecretValue::new("must-not-reach-backend"),
            )
            .expect_err("metadata input exceeds conservative Windows limit");
        assert!(matches!(error, KeystoreError::InvalidNamespace));
        assert!(backend
            .raw_generic_value(
                &service,
                &account_over_limit,
                GenericNamespaceStrategy::WindowsTarget,
            )
            .is_none());

        let representative_v2_account =
            "credential:v2:550e8400-e29b-41d4-a716-446655440000:password";
        store
            .validate_namespace("zann", representative_v2_account)
            .unwrap();
    }

    #[test]
    fn windows_namespace_limit_helper_checks_account_and_target_boundaries() {
        let relaxed_metadata = NamespaceLimits {
            account_max_bytes: WINDOWS_ACCOUNT_MAX_BYTES,
            target_max_bytes: usize::MAX,
            metadata_input_max_bytes: usize::MAX,
        };
        let account_at_limit = "a".repeat(WINDOWS_ACCOUNT_MAX_BYTES);
        let account_over_limit = format!("{account_at_limit}a");
        validate_keyring_namespace(
            "service",
            &account_at_limit,
            Some(relaxed_metadata),
            GenericNamespaceStrategy::WindowsTarget,
        )
        .unwrap();
        assert!(matches!(
            validate_keyring_namespace(
                "service",
                &account_over_limit,
                Some(relaxed_metadata),
                GenericNamespaceStrategy::WindowsTarget,
            ),
            Err(KeystoreError::InvalidNamespace)
        ));

        let exact_target_len = generic_windows_target("svc", "ab").len();
        let target_at_limit = NamespaceLimits {
            account_max_bytes: crate::SECRET_STORE_ACCOUNT_MAX_BYTES,
            target_max_bytes: exact_target_len,
            metadata_input_max_bytes: usize::MAX,
        };
        validate_keyring_namespace(
            "svc",
            "ab",
            Some(target_at_limit),
            GenericNamespaceStrategy::WindowsTarget,
        )
        .unwrap();
        assert!(matches!(
            validate_keyring_namespace(
                "svc",
                "abc",
                Some(target_at_limit),
                GenericNamespaceStrategy::WindowsTarget,
            ),
            Err(KeystoreError::InvalidNamespace)
        ));
    }

    #[test]
    fn legacy_dwk_adapter_reads_and_writes_the_existing_format() {
        let (_store, backend) = memory_store();
        let keystore =
            KeyringKeystore::with_backend(backend.clone(), crate::DWK_SERVICE, crate::DWK_ACCOUNT);
        let dwk = [7u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(dwk);

        backend.seed_legacy(crate::DWK_SERVICE, crate::DWK_ACCOUNT, &encoded);
        assert!(keystore.status().supported);
        assert_eq!(keystore.load_dwk().unwrap(), Some(dwk.to_vec()));

        keystore.store_dwk(&[8u8; 32]).unwrap();
        assert_eq!(
            backend
                .raw_legacy_value(crate::DWK_SERVICE, crate::DWK_ACCOUNT)
                .unwrap(),
            base64::engine::general_purpose::STANDARD.encode([8u8; 32])
        );
        keystore.delete_dwk().unwrap();
        keystore.delete_dwk().unwrap();
    }

    #[test]
    fn generic_credentials_cannot_overwrite_the_legacy_dwk() {
        let (store, backend) = memory_store();
        let keystore =
            KeyringKeystore::with_backend(backend, crate::DWK_SERVICE, crate::DWK_ACCOUNT);
        let dwk = [9u8; 32];

        keystore.store_dwk(&dwk).unwrap();
        store
            .put(
                "zann",
                "credential:v2:example",
                SecretValue::new("credential secret"),
            )
            .unwrap();

        assert_eq!(keystore.load_dwk().unwrap(), Some(dwk.to_vec()));
    }

    #[test]
    fn malformed_legacy_dwk_does_not_expose_the_stored_value_in_the_error() {
        let (_store, backend) = memory_store();
        let keystore = KeyringKeystore::with_backend(backend.clone(), "zann", "dwk");
        let malformed = "not a base64 device key";
        backend.seed_legacy("zann", "dwk", malformed);

        let error = keystore.load_dwk().expect_err("invalid base64");
        assert!(!error.to_string().contains(malformed));
        assert!(matches!(error, KeystoreError::Internal { .. }));
    }

    #[test]
    fn keyring_encoding_errors_do_not_expose_secret_bytes() {
        let secret = b"must-not-appear".to_vec();
        let error = map_error(keyring::Error::BadEncoding(secret.clone()));

        assert!(!error.to_string().contains("must-not-appear"));
        assert!(matches!(error, KeystoreError::Internal { .. }));
    }

    #[test]
    fn utf16_limit_counts_code_units_in_bytes() {
        let ascii = SecretValue::new("ab");
        assert!(validate_utf16_byte_limit(&ascii, 4).is_ok());
        assert!(matches!(
            validate_utf16_byte_limit(&ascii, 3),
            Err(KeystoreError::SecretTooLarge { maximum_bytes: 3 })
        ));

        // This scalar is represented by a UTF-16 surrogate pair: four bytes.
        let supplementary = SecretValue::new("😀");
        assert!(validate_utf16_byte_limit(&supplementary, 4).is_ok());
        assert!(matches!(
            validate_utf16_byte_limit(&supplementary, 3),
            Err(KeystoreError::SecretTooLarge { maximum_bytes: 3 })
        ));
    }

    #[test]
    fn keyring_put_rejects_oversized_values_before_touching_the_backend() {
        let backend = Arc::new(MemoryBackend::default());
        let store = KeyringSecretStore::with_backend_and_limit(backend.clone(), 8);
        let secret = "must-not-reach-keyring";

        let error = store
            .put("service", "account", SecretValue::new(secret))
            .expect_err("value exceeds test backend limit");

        assert!(matches!(
            &error,
            KeystoreError::SecretTooLarge { maximum_bytes: 8 }
        ));
        assert!(backend
            .raw_generic_value("service", "account", platform_namespace_strategy(),)
            .is_none());
        let display = error.to_string();
        let debug = format!("{error:?}");
        let json = serde_json::to_string(&error).expect("serialize keystore error");
        for rendered in [&display, &debug, &json] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn ambiguous_keyring_errors_are_sanitized_on_every_error_surface() {
        let secret = "ambiguous-mock-secret-must-not-appear";
        let credential = keyring::mock::MockCredential::default();
        credential
            .set_password(secret)
            .expect("seed mock credential");

        let error = map_error(keyring::Error::Ambiguous(vec![Box::new(credential)]));
        let display = error.to_string();
        let debug = format!("{error:?}");
        let json = serde_json::to_string(&error).expect("serialize keystore error");

        for rendered in [&display, &debug, &json] {
            assert!(!rendered.contains(secret));
        }
        assert_eq!(
            display,
            "keystore unavailable: multiple matching credentials in OS secret store"
        );
    }
}
