use crate::{
    Keystore, KeystoreError, KeystoreStatus, KeystoreStatusReason, LegacySecretSource, SecretStore,
    SecretValue,
};

/// Fallback for platforms with no OS credential store wired up. Every call
/// fails, so callers must not offer "remember unlock" there.
pub struct UnsupportedKeystore;

impl SecretStore for UnsupportedKeystore {
    fn put(&self, service: &str, account: &str, _secret: SecretValue) -> Result<(), KeystoreError> {
        self.validate_namespace(service, account)?;
        Err(KeystoreError::Unsupported)
    }

    fn get(&self, service: &str, account: &str) -> Result<Option<SecretValue>, KeystoreError> {
        self.validate_namespace(service, account)?;
        Err(KeystoreError::Unsupported)
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), KeystoreError> {
        self.validate_namespace(service, account)?;
        Err(KeystoreError::Unsupported)
    }
}

impl LegacySecretSource for UnsupportedKeystore {
    fn get_legacy(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<SecretValue>, KeystoreError> {
        crate::validate_secret_store_namespace(service, account)?;
        Err(KeystoreError::Unsupported)
    }
}

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
