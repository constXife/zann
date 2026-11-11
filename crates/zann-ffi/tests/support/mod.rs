//! In-memory stand-ins for the Keychain / Android Keystore adapters a shell
//! supplies through the foreign platform ports.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use zann_ffi::{
    create_core, CoreFacade, PlatformKeystore, PlatformKeystoreStatus, PlatformSecretStore,
    PlatformStoreError,
};

#[derive(Default)]
pub struct MemoryKeystore {
    pub dwk: Mutex<Option<Vec<u8>>>,
    /// When set, `load_dwk` behaves as a dismissed biometric prompt.
    pub cancel_load: Mutex<bool>,
}

impl PlatformKeystore for MemoryKeystore {
    fn status(&self) -> PlatformKeystoreStatus {
        PlatformKeystoreStatus {
            supported: true,
            biometrics_available: true,
            reason: None,
            message: None,
        }
    }
    fn store_dwk(&self, dwk: Vec<u8>) -> Result<(), PlatformStoreError> {
        *self.dwk.lock().unwrap() = Some(dwk);
        Ok(())
    }
    fn load_dwk(&self) -> Result<Option<Vec<u8>>, PlatformStoreError> {
        if *self.cancel_load.lock().unwrap() {
            return Err(PlatformStoreError::Cancelled);
        }
        Ok(self.dwk.lock().unwrap().clone())
    }
    fn delete_dwk(&self) -> Result<(), PlatformStoreError> {
        *self.dwk.lock().unwrap() = None;
        Ok(())
    }
}

#[derive(Default)]
pub struct MemorySecretStore(pub Mutex<BTreeMap<(String, String), String>>);

impl PlatformSecretStore for MemorySecretStore {
    fn put(
        &self,
        service: String,
        account: String,
        secret: String,
    ) -> Result<(), PlatformStoreError> {
        self.0.lock().unwrap().insert((service, account), secret);
        Ok(())
    }
    fn get(&self, service: String, account: String) -> Result<Option<String>, PlatformStoreError> {
        Ok(self.0.lock().unwrap().get(&(service, account)).cloned())
    }
    fn delete(&self, service: String, account: String) -> Result<(), PlatformStoreError> {
        self.0.lock().unwrap().remove(&(service, account));
        Ok(())
    }
}

pub fn open(db_path: &Path) -> Arc<CoreFacade> {
    open_with(db_path, Arc::default())
}

pub fn open_with(db_path: &Path, keystore: Arc<MemoryKeystore>) -> Arc<CoreFacade> {
    create_core(
        db_path.to_str().expect("UTF-8 test path").to_owned(),
        keystore,
        Arc::new(MemorySecretStore::default()),
    )
    .expect("open")
}
