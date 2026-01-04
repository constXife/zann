use base64::Engine;
use keyring::Entry;

use crate::{Keystore, KeystoreError, KeystoreStatus, KeystoreStatusReason};

pub struct MacosKeystore {
    service: String,
    account: String,
}

impl MacosKeystore {
    pub fn new(service: &str, account: &str) -> Self {
        Self {
            service: service.to_string(),
            account: account.to_string(),
        }
    }

    fn entry(&self) -> Result<Entry, KeystoreError> {
        Entry::new(&self.service, &self.account).map_err(|err| KeystoreError::Internal {
            message: err.to_string(),
        })
    }
}

impl Keystore for MacosKeystore {
    fn status(&self) -> Result<KeystoreStatus, KeystoreError> {
        Ok(KeystoreStatus {
            supported: true,
            biometrics_available: false,
            reason: Some(KeystoreStatusReason::Unavailable),
        })
    }

    fn store_dwk(&self, dwk: &[u8], require_biometrics: bool) -> Result<(), KeystoreError> {
        if require_biometrics {
            return Err(KeystoreError::BiometryUnavailable);
        }
        let entry = self.entry()?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(dwk);
        entry
            .set_password(&encoded)
            .map_err(|err| KeystoreError::Internal {
                message: err.to_string(),
            })
    }

    fn load_dwk(&self, _prompt: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        let entry = self.entry()?;
        let encoded = match entry.get_password() {
            Ok(value) => value,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(err) => {
                return Err(KeystoreError::Internal {
                    message: err.to_string(),
                })
            }
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| KeystoreError::Internal {
                message: "invalid keychain data".to_string(),
            })?;
        Ok(Some(bytes))
    }

    fn delete_dwk(&self) -> Result<(), KeystoreError> {
        let entry = self.entry()?;
        match entry.delete_password() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(KeystoreError::Internal {
                message: err.to_string(),
            }),
        }
    }
}
