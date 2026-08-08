use base64::Engine;
use keyring::Entry;

use crate::{Keystore, KeystoreError, KeystoreStatus, KeystoreStatusReason};

/// DWK storage backed by the OS credential store: Keychain on macOS,
/// Credential Manager on Windows, Secret Service on Linux.
///
/// The stored key is protected by the OS store's own access rules only. There
/// is no per-item biometric ACL here — see `KeystoreStatus::biometrics_available`.
pub struct KeyringKeystore {
    // Resolved once: `Entry::new` only fails on malformed identifiers, so the
    // outcome is deterministic and the handle is reused for every operation.
    entry: Result<Entry, KeystoreError>,
}

impl KeyringKeystore {
    #[must_use]
    pub fn new(service: &str, account: &str) -> Self {
        Self {
            entry: Entry::new(service, account).map_err(map_error),
        }
    }

    fn entry(&self) -> Result<&Entry, KeystoreError> {
        self.entry.as_ref().map_err(Clone::clone)
    }
}

fn map_error(err: keyring::Error) -> KeystoreError {
    match err {
        keyring::Error::NoEntry => KeystoreError::NotFound,
        other => KeystoreError::Internal {
            message: other.to_string(),
        },
    }
}

impl Keystore for KeyringKeystore {
    fn status(&self) -> KeystoreStatus {
        // Probe the store instead of assuming it works: on Linux the Secret
        // Service may simply not be running, and on any platform the store can
        // be locked. A missing entry is a healthy store with nothing in it.
        let probe = self.entry().and_then(|entry| match entry.get_password() {
            Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(map_error(err)),
        });
        match probe {
            Ok(()) => KeystoreStatus {
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
        let entry = self.entry()?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(dwk);
        entry.set_password(&encoded).map_err(map_error)
    }

    fn load_dwk(&self) -> Result<Option<Vec<u8>>, KeystoreError> {
        let entry = self.entry()?;
        let encoded = match entry.get_password() {
            Ok(value) => value,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(err) => return Err(map_error(err)),
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| KeystoreError::Internal {
                message: "stored key is not valid base64".to_string(),
            })?;
        Ok(Some(bytes))
    }

    fn delete_dwk(&self) -> Result<(), KeystoreError> {
        let entry = self.entry()?;
        match entry.delete_password() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(map_error(err)),
        }
    }
}
