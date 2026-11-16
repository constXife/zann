//! Dedicated biometric-bound backup keys; separate from remembered-unlock DWK.
use crate::{KeystoreError, KeystoreStatus};

pub trait BiometricKeyStore: Send + Sync {
    fn status(&self) -> KeystoreStatus;
    /// Creates a new key ID; must refuse overwriting an existing entry.
    fn store(&self, key_id: &[u8; 16], key: &[u8; 32]) -> Result<(), KeystoreError>;
    /// A fresh biometric prompt must gate every successful load.
    fn load(&self, key_id: &[u8; 16]) -> Result<Option<Vec<u8>>, KeystoreError>;
    fn delete(&self, key_id: &[u8; 16]) -> Result<(), KeystoreError>;
}
pub struct UnsupportedBiometricKeys;
impl BiometricKeyStore for UnsupportedBiometricKeys {
    fn status(&self) -> KeystoreStatus {
        KeystoreStatus::unsupported(crate::KeystoreStatusReason::Unavailable)
    }
    fn store(&self, _: &[u8; 16], _: &[u8; 32]) -> Result<(), KeystoreError> {
        Err(KeystoreError::Unsupported)
    }
    fn load(&self, _: &[u8; 16]) -> Result<Option<Vec<u8>>, KeystoreError> {
        Err(KeystoreError::Unsupported)
    }
    fn delete(&self, _: &[u8; 16]) -> Result<(), KeystoreError> {
        Err(KeystoreError::Unsupported)
    }
}
