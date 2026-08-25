//! OS-managed secret storage and remembered-unlock support.
//!
//! [`SecretStore`] is the generic service/account boundary. Its physical
//! keyring namespace is deliberately disjoint from historical entries.
//! [`LegacySecretSource`] is the read-only compatibility boundary for those
//! entries, while the older [`Keystore`] API remains the compatibility adapter
//! for the device wrapping key (DWK) stored under the stable `zann` / `dwk`
//! identifiers.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreStatus {
    /// Whether a working backend is present on this machine.
    pub supported: bool,
    /// Whether the stored key is additionally guarded by a biometric ACL.
    /// No current backend provides this; see `docs/Desktop.md`.
    pub biometrics_available: bool,
    pub reason: Option<KeystoreStatusReason>,
    /// Backend-specific detail behind `reason`, for diagnostics.
    pub message: Option<String>,
}

impl KeystoreStatus {
    #[must_use]
    pub fn unsupported(reason: KeystoreStatusReason) -> Self {
        Self {
            supported: false,
            biometrics_available: false,
            reason: Some(reason),
            message: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeystoreStatusReason {
    Unavailable,
    NotEnrolled,
    LockedOut,
    Changed,
}

#[derive(thiserror::Error, Debug, Clone, Serialize, Deserialize)]
pub enum KeystoreError {
    #[error("operation cancelled")]
    Cancelled,
    #[error("key not found")]
    NotFound,
    #[error("no keystore backend on this platform")]
    Unsupported,
    #[error("invalid OS secret store namespace")]
    InvalidNamespace,
    #[error("secret exceeds OS credential store limit of {maximum_bytes} bytes")]
    SecretTooLarge { maximum_bytes: usize },
    #[error("keystore unavailable: {message}")]
    Internal { message: String },
}

/// An owned secret value whose allocation is erased when dropped.
///
/// It deliberately does not implement `Clone`, serialization, or expose its
/// contents through `Debug`.
pub struct SecretValue(Zeroizing<String>);

/// Maximum UTF-8 byte length for the public service namespace.
pub const SECRET_STORE_SERVICE_MAX_BYTES: usize = 128;
/// Maximum UTF-8 byte length for a secret account identifier.
pub const SECRET_STORE_ACCOUNT_MAX_BYTES: usize = 1024;

impl SecretValue {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Borrow the secret for the duration of a backend operation.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

/// Validate the common injective service/account namespace shared by secret
/// stores.
///
/// Services are non-empty ASCII identifiers containing only letters, digits,
/// `_`, or `-`. This stable logical grammar is independent of each backend's
/// physical mapping. Accounts are non-empty, bounded UTF-8 strings; they may
/// contain dots but never NUL. Individual backends may impose tighter limits through
/// [`SecretStore::validate_namespace`].
pub fn validate_secret_store_namespace(service: &str, account: &str) -> Result<(), KeystoreError> {
    let valid_service = !service.is_empty()
        && service.len() <= SECRET_STORE_SERVICE_MAX_BYTES
        && service
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    let valid_account = !account.is_empty()
        && account.len() <= SECRET_STORE_ACCOUNT_MAX_BYTES
        && !account.as_bytes().contains(&0);
    if !valid_service || !valid_account {
        return Err(KeystoreError::InvalidNamespace);
    }
    Ok(())
}

/// Untyped access to an OS-managed secret store.
///
/// `service` and `account` are caller-owned namespaces, not credential types,
/// and must satisfy [`validate_secret_store_namespace`]. Implementations must
/// call [`validate_namespace`](Self::validate_namespace) before backend access,
/// replace an existing value on [`put`](Self::put), return `Ok(None)` for a
/// missing value, and make [`delete`](Self::delete) idempotent.
pub trait SecretStore: Send + Sync {
    /// Validate a namespace against the common contract and backend-specific
    /// limits before starting a multi-secret write.
    fn validate_namespace(&self, service: &str, account: &str) -> Result<(), KeystoreError> {
        validate_secret_store_namespace(service, account)
    }

    /// Validate a value against backend-specific limits before starting a
    /// multi-secret write. Custom stores accept every value by default.
    fn validate(&self, _secret: &SecretValue) -> Result<(), KeystoreError> {
        Ok(())
    }

    fn put(&self, service: &str, account: &str, secret: SecretValue) -> Result<(), KeystoreError>;

    fn get(&self, service: &str, account: &str) -> Result<Option<SecretValue>, KeystoreError>;

    fn delete(&self, service: &str, account: &str) -> Result<(), KeystoreError>;
}

/// Read-only access to an entry written with keyring-rs' historical
/// `service` / `account` mapping.
///
/// This compatibility boundary is intentionally separate from [`SecretStore`]:
/// generic callers cannot write or delete a legacy CLI credential or the
/// device wrapping key by choosing the same logical tuple.
pub trait LegacySecretSource: Send + Sync {
    /// Validate a legacy namespace without reading the OS store.
    fn validate_legacy_namespace(&self, service: &str, account: &str) -> Result<(), KeystoreError> {
        validate_secret_store_namespace(service, account)
    }

    fn get_legacy(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<SecretValue>, KeystoreError>;
}

/// Compatibility API for the device wrapping key.
pub trait Keystore: Send + Sync {
    fn status(&self) -> KeystoreStatus;
    fn store_dwk(&self, dwk: &[u8]) -> Result<(), KeystoreError>;
    fn load_dwk(&self) -> Result<Option<Vec<u8>>, KeystoreError>;
    fn delete_dwk(&self) -> Result<(), KeystoreError>;
}

#[cfg(all(feature = "fido", any(target_os = "linux", target_os = "macos")))]
pub mod fido;
#[cfg(all(
    feature = "secret-store",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
mod keyring_store;
#[cfg(feature = "remembered")]
pub mod remembered;
mod unsupported;

#[cfg(feature = "remembered")]
pub use remembered::{HardwareKeyEntry, RememberedUnlock, UnlockError, UnlockSource};

#[cfg(all(
    feature = "secret-store",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
pub use keyring_store::{KeyringKeystore, KeyringLegacySecretSource, KeyringSecretStore};
pub use unsupported::UnsupportedKeystore;

const DWK_SERVICE: &str = "zann";
const DWK_ACCOUNT: &str = "dwk";

/// Select the generic OS secret-store backend for the current platform.
#[must_use]
pub fn default_secret_store() -> Box<dyn SecretStore> {
    #[cfg(all(
        feature = "secret-store",
        any(target_os = "macos", target_os = "windows", target_os = "linux")
    ))]
    {
        Box::new(KeyringSecretStore::new())
    }
    #[cfg(not(all(
        feature = "secret-store",
        any(target_os = "macos", target_os = "windows", target_os = "linux")
    )))]
    {
        Box::new(UnsupportedKeystore)
    }
}

/// Select the read-only historical keyring adapter for the current platform.
#[must_use]
pub fn default_legacy_secret_source() -> Box<dyn LegacySecretSource> {
    #[cfg(all(
        feature = "secret-store",
        any(target_os = "macos", target_os = "windows", target_os = "linux")
    ))]
    {
        Box::new(KeyringLegacySecretSource::new())
    }
    #[cfg(not(all(
        feature = "secret-store",
        any(target_os = "macos", target_os = "windows", target_os = "linux")
    )))]
    {
        Box::new(UnsupportedKeystore)
    }
}

#[must_use]
pub fn default_keystore() -> Box<dyn Keystore> {
    #[cfg(all(
        feature = "secret-store",
        any(target_os = "macos", target_os = "windows", target_os = "linux")
    ))]
    {
        Box::new(KeyringKeystore::new(DWK_SERVICE, DWK_ACCOUNT))
    }
    #[cfg(not(all(
        feature = "secret-store",
        any(target_os = "macos", target_os = "windows", target_os = "linux")
    )))]
    {
        Box::new(UnsupportedKeystore)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_backend_reports_no_support() {
        let keystore = UnsupportedKeystore;
        let status = keystore.status();
        assert!(!status.supported);
        assert!(matches!(
            keystore.store_dwk(&[0u8; 32]),
            Err(KeystoreError::Unsupported)
        ));
        assert!(matches!(
            keystore.load_dwk(),
            Err(KeystoreError::Unsupported)
        ));
        assert!(matches!(
            SecretStore::get(&keystore, "service", "account"),
            Err(KeystoreError::Unsupported)
        ));
        assert!(matches!(
            LegacySecretSource::get_legacy(&keystore, "service", "account"),
            Err(KeystoreError::Unsupported)
        ));
    }

    #[test]
    fn dwk_namespace_is_stable() {
        assert_eq!(DWK_SERVICE, "zann");
        assert_eq!(DWK_ACCOUNT, "dwk");
    }
}
