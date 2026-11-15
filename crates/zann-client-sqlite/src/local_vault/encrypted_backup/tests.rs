use super::*;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, AtomicUsize},
};
const PASSWORD: &str = "synthetic backup passphrase";
#[derive(Default)]
struct Biometrics {
    keys: Mutex<BTreeMap<[u8; 16], Vec<u8>>>,
    cancel: AtomicBool,
    loads: AtomicUsize,
}
impl zann_keystore::BiometricKeyStore for Biometrics {
    fn status(&self) -> KeystoreStatus {
        KeystoreStatus {
            supported: true,
            biometrics_available: true,
            reason: None,
            message: None,
        }
    }
    fn store(&self, id: &[u8; 16], key: &[u8; 32]) -> Result<(), KeystoreError> {
        let mut keys = self.keys.lock().expect("keys");
        if keys.contains_key(id) {
            return Err(KeystoreError::Internal {
                message: "duplicate key".into(),
            });
        }
        keys.insert(*id, key.to_vec());
        Ok(())
    }
    fn load(&self, id: &[u8; 16]) -> Result<Option<Vec<u8>>, KeystoreError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        if self.cancel.load(Ordering::SeqCst) {
            return Err(KeystoreError::Cancelled);
        }
        Ok(self.keys.lock().expect("keys").get(id).cloned())
    }
    fn delete(&self, id: &[u8; 16]) -> Result<(), KeystoreError> {
        self.keys.lock().expect("keys").remove(id);
        Ok(())
    }
}
fn operation() -> SessionOperation {
    SessionOperation::new(Instant::now() + Duration::from_secs(600)).0
}
fn phrase() -> BackupRecipient {
    BackupRecipient::Passphrase {
        passphrase: PASSWORD.into(),
    }
}
fn hardware() -> BackupRecipient {
    BackupRecipient::Hardware {
        pin: Some("1357".into()),
        built_in_uv: false,
    }
}
fn fixture() -> (
    tempfile::TempDir,
    Arc<LocalVault>,
    Arc<zann_keystore::FakeHardwareAuthenticator>,
    Arc<Biometrics>,
) {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("canonical");
    let hardware = Arc::new(zann_keystore::FakeHardwareAuthenticator::new(1));
    hardware.require_pin("1357".into());
    let biometric = Arc::new(Biometrics::default());
    let mut ports = LocalVaultPorts::system_default();
    ports.authenticator = hardware.clone();
    ports.backup_keys = biometric.clone();
    let core = open_vault_at_path(&root.join("local.sqlite"), ports).expect("open");
    core.seed_offline_fixture("synthetic device password".into())
        .expect("seed");
    core.debug_create_kv_item(
        "synthetic/secret".into(),
        "password".into(),
        "plaintext sentinel".into(),
    )
    .expect("item");
    (dir, core, hardware, biometric)
}
#[test]
fn streaming_native_archive_opens_with_each_portable_and_biometric_slot_without_plaintext_files() {
    let (dir, core, token, biometric) = fixture();
    let before = std::fs::read_dir(dir.path())
        .expect("dir")
        .map(|e| e.expect("entry").path())
        .collect::<std::collections::BTreeSet<_>>();
    let handle = core.backup_begin(operation()).expect("begin");
    core.backup_add_recipient(handle.clone(), phrase())
        .expect("passphrase");
    core.backup_add_recipient(handle.clone(), hardware())
        .expect("first hardware");
    token.connect(2);
    core.backup_add_recipient(handle.clone(), hardware())
        .expect("second hardware");
    core.backup_add_recipient(handle.clone(), BackupRecipient::Biometric)
        .expect("biometric");
    let path = dir.path().join("portable.zann");
    let report = core
        .backup_export_encrypted(path.display().to_string(), handle)
        .expect("export");
    assert_eq!(report.items_count, 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).expect("mode").permissions().mode() & 0o777,
            0o600
        );
    }
    let bytes = std::fs::read(&path).expect("bytes");
    assert!(!bytes
        .windows(b"plaintext sentinel".len())
        .any(|w| w == b"plaintext sentinel"));
    for (slot, recipient) in [
        (0, phrase()),
        (1, hardware()),
        (2, hardware()),
        (3, BackupRecipient::Biometric),
    ] {
        if slot == 1 {
            token.connect(1);
        }
        if slot == 2 {
            token.connect(2);
        }
        let opened = core
            .backup_open_encrypted(path.display().to_string(), slot, recipient, operation())
            .expect("open slot");
        let inspection = core
            .backup_inspect_encrypted(opened.clone())
            .expect("canonical dry run");
        assert_eq!(inspection.items_count, 1);
        core.backup_cancel(opened).expect("close");
    }
    assert_eq!(biometric.keys.lock().expect("keys").len(), 1);
    assert!(biometric.loads.load(Ordering::SeqCst) >= 2);
    let added = std::fs::read_dir(dir.path())
        .expect("dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| !before.contains(p))
        .collect::<Vec<_>>();
    assert_eq!(added, vec![path], "only the encrypted archive is created");
}
#[test]
fn biometric_only_is_refused_before_output_and_failed_confirmation_does_not_add_a_slot() {
    let (dir, core, _, biometric) = fixture();
    let handle = core.backup_begin(operation()).expect("begin");
    biometric.cancel.store(true, Ordering::SeqCst);
    assert!(core
        .backup_add_recipient(handle.clone(), BackupRecipient::Biometric)
        .is_err());
    assert!(biometric.keys.lock().expect("keys").is_empty());
    biometric.cancel.store(false, Ordering::SeqCst);
    core.backup_add_recipient(handle.clone(), BackupRecipient::Biometric)
        .expect("enroll");
    let path = dir.path().join("must-not-exist");
    assert!(core
        .backup_export_encrypted(path.display().to_string(), handle)
        .is_err());
    assert!(!path.exists());
}
#[test]
fn tamper_wrong_secret_lock_and_cancel_never_admit_an_archive_or_publish_output() {
    let (dir, core, _, _) = fixture();
    let handle = core.backup_begin(operation()).expect("begin");
    core.backup_add_recipient(handle.clone(), phrase())
        .expect("slot");
    let path = dir.path().join("backup.zann");
    core.backup_export_encrypted(path.display().to_string(), handle.clone())
        .expect("export");
    assert!(core
        .backup_export_encrypted(path.display().to_string(), handle)
        .is_err());
    assert!(core
        .backup_open_encrypted(
            path.display().to_string(),
            0,
            BackupRecipient::Passphrase {
                passphrase: "wrong sentinel".into()
            },
            operation()
        )
        .is_err());
    let mut bytes = std::fs::read(&path).expect("read");
    *bytes.last_mut().expect("final tag") ^= 1;
    std::fs::write(&path, &bytes).expect("tamper");
    assert!(core
        .backup_open_encrypted(path.display().to_string(), 0, phrase(), operation())
        .is_err());
    let (op, cancel) = SessionOperation::new(Instant::now() + Duration::from_secs(600));
    let handle = core.backup_begin(op).expect("begin");
    core.backup_add_recipient(handle.clone(), phrase())
        .expect("slot");
    cancel.cancel();
    assert!(core
        .backup_export_encrypted(dir.path().join("cancelled").display().to_string(), handle)
        .is_err());
    let handle = core.backup_begin(operation()).expect("begin");
    core.backup_add_recipient(handle.clone(), phrase())
        .expect("slot");
    core.lock().expect("lock");
    assert!(core
        .backup_export_encrypted(dir.path().join("locked").display().to_string(), handle)
        .is_err());
}

#[test]
fn cancellation_releases_pending_slot_keys_even_when_the_handle_has_not_reached_the_shell() {
    let (_dir, core, _, _) = fixture();
    let (operation, cancel) = SessionOperation::new(Instant::now() + Duration::from_secs(600));
    let handle = core.backup_begin(operation).expect("begin");
    core.backup_add_recipient(handle, phrase()).expect("slot");
    let weak = {
        let pending = core.archive.lock().expect("archive");
        let ArchiveContent::Prepared(keys) = &pending.as_ref().expect("work").content else {
            panic!("prepared")
        };
        Arc::downgrade(&keys[0])
    };
    cancel.cancel();
    let until = Instant::now() + Duration::from_secs(5);
    while weak.upgrade().is_some() && Instant::now() < until {
        std::thread::yield_now();
    }
    assert!(weak.upgrade().is_none());
    assert!(core.archive.lock().expect("archive").is_none());
}
#[test]
fn keyring_eviction_invalidates_existing_authenticated_readers() {
    use std::io::Read;
    let (dir, core, _, _) = fixture();
    let handle = core.backup_begin(operation()).expect("begin");
    core.backup_add_recipient(handle.clone(), phrase())
        .expect("slot");
    let path = dir.path().join("backup.zann");
    core.backup_export_encrypted(path.display().to_string(), handle)
        .expect("export");
    let opened = core
        .backup_open_encrypted(path.display().to_string(), 0, phrase(), operation())
        .expect("open");
    let (_, content) = core.archive_snapshot(&opened).expect("snapshot");
    let ArchiveContent::Opened(input) = content else {
        panic!("opened")
    };
    let mut reader = input.open().expect("reader");
    reader.read_exact(&mut [0; 1]).expect("first byte");
    let before = core.device_unlock().expect("keyring");
    let mut after = before.clone();
    after.accounts.clear();
    core.commit_device_unlock(Some(&before), &after)
        .expect("eviction");
    assert!(reader.read_exact(&mut [0; 1]).is_err());
}

#[test]
fn lock_cancels_an_encrypted_export_waiting_for_sqlite_and_preserves_the_destination() {
    let (dir, core, _, _) = fixture();
    let handle = core.backup_begin(operation()).expect("begin");
    core.backup_add_recipient(handle.clone(), phrase())
        .expect("slot");
    let root = core.root_key().expect("root");
    let account = core.account_key().expect("account");
    let pool = core.pool();
    let _entered = core.runtime.enter();
    let permits = core.runtime.block_on(async {
        let mut all = Vec::new();
        for _ in 0..5 {
            all.push(pool.acquire().await.expect("connection"));
        }
        all
    });
    let target = dir.path().join("existing.zann");
    std::fs::write(&target, b"existing complete archive").expect("existing");
    let destination = target.display().to_string();
    let other = core.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        tx.send(other.backup_export_encrypted(destination, handle))
            .expect("result")
    });
    let until = Instant::now() + Duration::from_secs(5);
    while !std::fs::read_dir(dir.path()).expect("dir").any(|e| {
        e.expect("entry")
            .file_name()
            .to_string_lossy()
            .starts_with(".zann-export-")
    }) && Instant::now() < until
    {
        std::thread::yield_now();
    }
    core.lock().expect("prompt lock");
    assert!(rx
        .recv_timeout(Duration::from_secs(5))
        .expect("cancel without waiting for SQLite")
        .is_err());
    worker.join().expect("worker");
    assert_eq!(
        std::fs::read(&target).expect("destination"),
        b"existing complete archive"
    );
    assert_eq!(Arc::strong_count(&root), 1);
    assert_eq!(Arc::strong_count(&account), 1);
    assert!(!std::fs::read_dir(dir.path()).expect("dir").any(|e| e
        .expect("entry")
        .file_name()
        .to_string_lossy()
        .starts_with(".zann-export-")));
    drop(permits);
}
