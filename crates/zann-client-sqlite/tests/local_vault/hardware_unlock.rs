use std::sync::{Arc, Mutex};

use tempfile::TempDir;
use zann_client::app::local::{LocalError, LocalVaultService};
use zann_client_sqlite::local_vault::LocalVault;
use zann_db::SqliteFileLocation;
use zann_keystore::{
    FakeHardwareAuthenticator, FidoError, Keystore, KeystoreError, KeystoreStatus,
    KeystoreStatusReason, UnsupportedKeystore,
};

fn open(
    root: &TempDir,
    keystore: Arc<dyn Keystore>,
    auth: Arc<FakeHardwareAuthenticator>,
) -> Arc<LocalVault> {
    let location = SqliteFileLocation::from_path(&root.path().join("local.sqlite")).unwrap();
    LocalVault::open(location, keystore, auth).unwrap()
}

fn initialized(root: &TempDir, auth: Arc<FakeHardwareAuthenticator>) -> Arc<LocalVault> {
    let core = open(root, Arc::new(UnsupportedKeystore), auth);
    core.initialize_master_password("test master password".into())
        .unwrap();
    core
}

fn assert_kind(error: LocalError, expected: &str) {
    assert!(
        std::error::Error::source(&error).is_some(),
        "preserve the original cause"
    );
    match error {
        LocalError::Unlock { kind, .. } => assert_eq!(kind, expected),
        _ => panic!("expected structured unlock error"),
    }
}

#[test]
fn injected_hardware_enrolls_reopens_unlocks_and_polls_without_os_store() {
    let root = TempDir::new().unwrap();
    let auth = Arc::new(FakeHardwareAuthenticator::new(1));
    let core = initialized(&root, auth.clone());
    let port: &dyn LocalVaultService = core.as_ref();
    port.enroll_hardware_key("primary".into(), &|| {
        assert_eq!(auth.touch_requests(), 1);
        assert!(
            !root.path().join("unlock.json").exists(),
            "Touch 1 must not persist anything"
        );
        assert!(!core.remembered_unlock().unwrap().armed);
    })
    .unwrap();
    assert_eq!(auth.touch_requests(), 2);
    assert!(port.remembered_unlock().unwrap().hardware_supported);
    for _ in 0..10 {
        assert!(port.hardware_key_present().unwrap());
    }
    assert_eq!(auth.touch_requests(), 2);
    drop(core);
    let reopened = open(&root, Arc::new(UnsupportedKeystore), auth.clone());
    assert!(reopened.unlock_remembered().unwrap().unlocked);
    reopened.lock().unwrap();
    auth.connect(2);
    assert!(!reopened.hardware_key_present().unwrap());
    assert_kind(
        reopened.unlock_remembered().unwrap_err(),
        "hardware_key_not_enrolled",
    );
    auth.disconnect();
    assert!(!reopened.hardware_key_present().unwrap());
    assert_kind(
        reopened.unlock_remembered().unwrap_err(),
        "hardware_key_absent",
    );
    assert!(!reopened.vault_status().unwrap().unlocked);
    auth.connect(1);
    assert!(reopened.unlock_remembered().unwrap().unlocked);
    let id = reopened.remembered_unlock().unwrap().hardware_keys[0]
        .credential_id
        .clone();
    reopened.remove_hardware_key(id).unwrap();
    assert!(!reopened.hardware_key_present().unwrap());
}

#[test]
fn failed_touch_or_token_swap_never_publishes_enrollment() {
    let root = TempDir::new().unwrap();
    let auth = Arc::new(FakeHardwareAuthenticator::new(1));
    let core = initialized(&root, auth.clone());
    auth.fail_next_create(FidoError::Timeout);
    assert_kind(
        core.enroll_hardware_key("key".into(), &|| panic!("Touch 1 failed"))
            .unwrap_err(),
        "hardware_key_timeout",
    );
    for failure in [FidoError::Timeout, FidoError::NoHmacSecret] {
        let expected_kind = failure.kind();
        auth.fail_next_derive(failure);
        assert_kind(
            core.enroll_hardware_key("key".into(), &|| {}).unwrap_err(),
            expected_kind,
        );
        assert!(!root.path().join("unlock.json").exists());
    }
    assert_kind(
        core.enroll_hardware_key("key".into(), &|| auth.connect(2))
            .unwrap_err(),
        "hardware_key_not_enrolled",
    );
    assert!(!core.remembered_unlock().unwrap().armed);
}

#[test]
fn lock_between_touches_cancels_enrollment() {
    let root = TempDir::new().unwrap();
    let auth = Arc::new(FakeHardwareAuthenticator::new(1));
    let core = initialized(&root, auth.clone());
    let error = core
        .enroll_hardware_key("key".into(), &|| {
            core.lock().unwrap();
        })
        .unwrap_err();
    assert!(matches!(error, LocalError::Locked));
    assert_eq!(auth.touch_requests(), 1);
    assert!(!root.path().join("unlock.json").exists());
}

struct MemoryKeystore(Mutex<Option<Vec<u8>>>);
impl Keystore for MemoryKeystore {
    fn status(&self) -> KeystoreStatus {
        KeystoreStatus::unsupported(KeystoreStatusReason::Unavailable)
    }
    fn store_dwk(&self, key: &[u8]) -> Result<(), KeystoreError> {
        *self.0.lock().unwrap() = Some(key.to_vec());
        Ok(())
    }
    fn load_dwk(&self) -> Result<Option<Vec<u8>>, KeystoreError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn delete_dwk(&self) -> Result<(), KeystoreError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

#[test]
fn injected_keystore_handles_remember_unlock_and_forget() {
    let root = TempDir::new().unwrap();
    let auth = Arc::new(FakeHardwareAuthenticator::new(1));
    auth.disconnect();
    let store = Arc::new(MemoryKeystore(Mutex::new(None)));
    let core = open(&root, store.clone(), auth.clone());
    core.initialize_master_password("test master password".into())
        .unwrap();
    core.remember_with_keystore().unwrap();
    core.lock().unwrap();
    assert!(core.unlock_remembered().unwrap().unlocked);
    core.forget_remembered().unwrap();
    assert!(store.0.lock().unwrap().is_none());
    core.lock().unwrap();
    assert_kind(core.unlock_remembered().unwrap_err(), "keystore_not_found");
    assert_eq!(auth.touch_requests(), 0);
}

#[test]
fn keystore_failure_keeps_its_kind_and_source() {
    let root = TempDir::new().unwrap();
    let core = initialized(&root, Arc::new(FakeHardwareAuthenticator::new(1)));
    assert_kind(
        core.remember_with_keystore().unwrap_err(),
        "keystore_unsupported",
    );
    assert!(!root.path().join("unlock.json").exists());
}
