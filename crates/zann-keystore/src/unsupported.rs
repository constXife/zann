use crate::{Keystore, KeystoreError, KeystoreStatus, KeystoreStatusReason};

/// Fallback for platforms with no OS credential store wired up. Every call
/// fails, so callers must not offer "remember unlock" there.
pub struct UnsupportedKeystore;

impl Keystore for UnsupportedKeystore {
    fn status(&self) -> KeystoreStatus {
        KeystoreStatus::unsupported(KeystoreStatusReason::Unavailable)
    }

    fn store_dwk(&self, _dwk: &[u8]) -> Result<(), KeystoreError> {
        Err(KeystoreError::Unsupported)
    }

    fn load_dwk(&self) -> Result<Option<Vec<u8>>, KeystoreError> {
        Err(KeystoreError::Unsupported)
    }

    fn delete_dwk(&self) -> Result<(), KeystoreError> {
        Err(KeystoreError::Unsupported)
    }
}
