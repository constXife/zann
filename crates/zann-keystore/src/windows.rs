use crate::{Keystore, KeystoreError, KeystoreStatus, KeystoreStatusReason};

pub struct WindowsKeystore;

impl WindowsKeystore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsKeystore {
    fn default() -> Self {
        Self::new()
    }
}

impl Keystore for WindowsKeystore {
    fn status(&self) -> Result<KeystoreStatus, KeystoreError> {
        Ok(KeystoreStatus {
            supported: false,
            biometrics_available: false,
            reason: Some(KeystoreStatusReason::Unavailable),
        })
    }

    fn store_dwk(&self, _dwk: &[u8], _require_biometrics: bool) -> Result<(), KeystoreError> {
        Err(KeystoreError::Unsupported)
    }

    fn load_dwk(&self, _prompt: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        Err(KeystoreError::Unsupported)
    }

    fn delete_dwk(&self) -> Result<(), KeystoreError> {
        Err(KeystoreError::Unsupported)
    }
}
