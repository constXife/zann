//! OS secret storage supplied by the Swift and Kotlin shells: Keychain items
//! guarded by `SecAccessControl`, Android Keystore with `BiometricPrompt`.
//!
//! Secrets cross the boundary as plain values that UniFFI copies, so neither
//! side can erase every copy: secret-store values are wrapped in zeroizing
//! [`SecretValue`]s on receipt, and the foreign side owns erasing its own
//! copies. Nothing here derives `Debug` over a secret.

use std::sync::Arc;

use zann_client_sqlite::local_vault::{
    Keystore, KeystoreError, KeystoreStatus, KeystoreStatusReason, SecretStore, SecretValue,
};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PlatformStoreError {
    /// The user dismissed the platform prompt.
    #[error("operation cancelled")]
    Cancelled,
    /// This device has no backend for the store.
    #[error("platform store unsupported")]
    Unsupported,
    #[error("platform store unavailable: {message}")]
    Unavailable { message: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for PlatformStoreError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unavailable {
            message: error.reason,
        }
    }
}

impl From<PlatformStoreError> for KeystoreError {
    fn from(error: PlatformStoreError) -> Self {
        match error {
            PlatformStoreError::Cancelled => Self::Cancelled,
            PlatformStoreError::Unsupported => Self::Unsupported,
            PlatformStoreError::Unavailable { message } => Self::Internal { message },
        }
    }
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum PlatformKeystoreStatusReason {
    Unavailable,
    NotEnrolled,
    LockedOut,
    Changed,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PlatformKeystoreStatus {
    pub supported: bool,
    /// Whether the stored key is guarded by a biometric access policy.
    pub biometrics_available: bool,
    pub reason: Option<PlatformKeystoreStatusReason>,
    /// Platform detail behind `reason`, for diagnostics. Never a secret.
    pub message: Option<String>,
}

/// Holds the device wrapping key that arms remembered unlock.
///
/// Called synchronously on the thread of the facade method that needs it
/// (remember, unlock, forget), so `store_dwk` and `load_dwk` may present a
/// biometric prompt; shells call those methods off the main thread.
///
/// `status` must never prompt. `load_dwk` returns `None` for a missing key;
/// `delete_dwk` treats a missing key as success.
#[uniffi::export(with_foreign)]
pub trait PlatformKeystore: Send + Sync {
    fn status(&self) -> PlatformKeystoreStatus;
    fn store_dwk(&self, dwk: Vec<u8>) -> Result<(), PlatformStoreError>;
    fn load_dwk(&self) -> Result<Option<Vec<u8>>, PlatformStoreError>;
    fn delete_dwk(&self) -> Result<(), PlatformStoreError>;
}

/// Untyped service/account secret storage for remote session tokens. The
/// core chooses both names; a shell maps them to its store unchanged.
///
/// Called from background runtime threads, possibly after the facade call
/// that started a session operation has returned. It must not require the
/// main thread or present UI: use an access policy that needs no user
/// presence, such as `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
///
/// `put` replaces an existing value, `get` returns `None` for a missing one,
/// and `delete` treats a missing value as success.
#[uniffi::export(with_foreign)]
pub trait PlatformSecretStore: Send + Sync {
    fn put(
        &self,
        service: String,
        account: String,
        secret: String,
    ) -> Result<(), PlatformStoreError>;
    fn get(&self, service: String, account: String) -> Result<Option<String>, PlatformStoreError>;
    fn delete(&self, service: String, account: String) -> Result<(), PlatformStoreError>;
}

pub(crate) fn keystore(platform: Arc<dyn PlatformKeystore>) -> Arc<dyn Keystore> {
    Arc::new(ForeignKeystore(platform))
}

pub(crate) fn secret_store(platform: Arc<dyn PlatformSecretStore>) -> Arc<dyn SecretStore> {
    Arc::new(ForeignSecretStore(platform))
}

struct ForeignKeystore(Arc<dyn PlatformKeystore>);

impl Keystore for ForeignKeystore {
    fn status(&self) -> KeystoreStatus {
        let status = self.0.status();
        KeystoreStatus {
            supported: status.supported,
            biometrics_available: status.biometrics_available,
            reason: status.reason.map(|reason| match reason {
                PlatformKeystoreStatusReason::Unavailable => KeystoreStatusReason::Unavailable,
                PlatformKeystoreStatusReason::NotEnrolled => KeystoreStatusReason::NotEnrolled,
                PlatformKeystoreStatusReason::LockedOut => KeystoreStatusReason::LockedOut,
                PlatformKeystoreStatusReason::Changed => KeystoreStatusReason::Changed,
            }),
            message: status.message,
        }
    }

    fn store_dwk(&self, dwk: &[u8]) -> Result<(), KeystoreError> {
        self.0.store_dwk(dwk.to_vec()).map_err(Into::into)
    }

    fn load_dwk(&self) -> Result<Option<Vec<u8>>, KeystoreError> {
        self.0.load_dwk().map_err(Into::into)
    }

    fn delete_dwk(&self) -> Result<(), KeystoreError> {
        self.0.delete_dwk().map_err(Into::into)
    }
}

struct ForeignSecretStore(Arc<dyn PlatformSecretStore>);

impl SecretStore for ForeignSecretStore {
    fn put(&self, service: &str, account: &str, secret: SecretValue) -> Result<(), KeystoreError> {
        self.validate_namespace(service, account)?;
        self.0
            .put(
                service.to_owned(),
                account.to_owned(),
                secret.expose_secret().to_owned(),
            )
            .map_err(Into::into)
    }

    fn get(&self, service: &str, account: &str) -> Result<Option<SecretValue>, KeystoreError> {
        self.validate_namespace(service, account)?;
        Ok(self
            .0
            .get(service.to_owned(), account.to_owned())?
            .map(SecretValue::new))
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), KeystoreError> {
        self.validate_namespace(service, account)?;
        self.0
            .delete(service.to_owned(), account.to_owned())
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recording {
        values: Mutex<BTreeMap<(String, String), String>>,
        calls: Mutex<usize>,
    }

    impl PlatformSecretStore for Recording {
        fn put(
            &self,
            service: String,
            account: String,
            secret: String,
        ) -> Result<(), PlatformStoreError> {
            *self.calls.lock().unwrap() += 1;
            self.values
                .lock()
                .unwrap()
                .insert((service, account), secret);
            Ok(())
        }
        fn get(
            &self,
            service: String,
            account: String,
        ) -> Result<Option<String>, PlatformStoreError> {
            *self.calls.lock().unwrap() += 1;
            Ok(self
                .values
                .lock()
                .unwrap()
                .get(&(service, account))
                .cloned())
        }
        fn delete(&self, service: String, account: String) -> Result<(), PlatformStoreError> {
            *self.calls.lock().unwrap() += 1;
            self.values.lock().unwrap().remove(&(service, account));
            Ok(())
        }
    }

    #[test]
    fn foreign_secret_store_round_trips_and_redacts() {
        let platform = Arc::new(Recording::default());
        let store = secret_store(platform.clone());

        store
            .put("zann", "credential:v2:a", SecretValue::new("test-token"))
            .expect("put");
        let secret = store
            .get("zann", "credential:v2:a")
            .expect("get")
            .expect("present");
        assert_eq!(secret.expose_secret(), "test-token");
        assert!(!format!("{secret:?}").contains("test-token"));

        store.delete("zann", "credential:v2:a").expect("delete");
        assert!(store.get("zann", "credential:v2:a").expect("get").is_none());
    }

    #[test]
    fn invalid_namespace_never_reaches_the_platform() {
        let platform = Arc::new(Recording::default());
        let store = secret_store(platform.clone());

        assert!(matches!(
            store.put("zann service", "a", SecretValue::new("test-token")),
            Err(KeystoreError::InvalidNamespace)
        ));
        assert!(matches!(
            store.get("zann", ""),
            Err(KeystoreError::InvalidNamespace)
        ));
        assert!(matches!(
            store.delete("", "a"),
            Err(KeystoreError::InvalidNamespace)
        ));
        assert_eq!(*platform.calls.lock().unwrap(), 0);
    }

    #[test]
    fn platform_errors_keep_their_kind() {
        assert!(matches!(
            KeystoreError::from(PlatformStoreError::Cancelled),
            KeystoreError::Cancelled
        ));
        assert!(matches!(
            KeystoreError::from(PlatformStoreError::Unsupported),
            KeystoreError::Unsupported
        ));
        assert!(matches!(
            KeystoreError::from(PlatformStoreError::Unavailable { message: "locked".into() }),
            KeystoreError::Internal { message } if message == "locked"
        ));
    }
}
