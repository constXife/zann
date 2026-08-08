//! Storage for the device wrapping key (DWK).
//!
//! The DWK decrypts the locally remembered master key, so it must never be
//! written to application files: it belongs in an OS-managed secret store.

use serde::{Deserialize, Serialize};

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
    #[error("keystore unavailable: {message}")]
    Internal { message: String },
}

pub trait Keystore: Send + Sync {
    fn status(&self) -> KeystoreStatus;
    fn store_dwk(&self, dwk: &[u8]) -> Result<(), KeystoreError>;
    fn load_dwk(&self) -> Result<Option<Vec<u8>>, KeystoreError>;
    fn delete_dwk(&self) -> Result<(), KeystoreError>;
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
mod keyring_store;
mod unsupported;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub use keyring_store::KeyringKeystore;
pub use unsupported::UnsupportedKeystore;

const SERVICE: &str = "zann";
const ACCOUNT: &str = "dwk";

#[must_use]
pub fn default_keystore() -> Box<dyn Keystore> {
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        Box::new(KeyringKeystore::new(SERVICE, ACCOUNT))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
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
    }

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[test]
    fn keyring_backend_round_trips_the_dwk() {
        // Runs against keyring's in-memory store so the test does not depend on
        // a Secret Service / Keychain being present.
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());

        let keystore = KeyringKeystore::new("zann-test", "dwk");
        assert!(keystore.status().supported);
        assert_eq!(keystore.load_dwk().unwrap(), None);

        let dwk = [7u8; 32];
        keystore.store_dwk(&dwk).unwrap();
        assert_eq!(keystore.load_dwk().unwrap(), Some(dwk.to_vec()));

        keystore.delete_dwk().unwrap();
        assert_eq!(keystore.load_dwk().unwrap(), None);
        // Deleting a key that is already gone is not an error.
        keystore.delete_dwk().unwrap();
    }
}
