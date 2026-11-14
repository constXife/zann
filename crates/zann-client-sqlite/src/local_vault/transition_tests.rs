//! Deterministic publication races around database/keyring replacement.
use super::*;
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct GatedKeystore {
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    stored: Mutex<Option<Vec<u8>>>,
}
impl Keystore for GatedKeystore {
    fn status(&self) -> KeystoreStatus {
        KeystoreStatus {
            supported: true,
            biometrics_available: true,
            reason: None,
            message: None,
        }
    }
    fn store_dwk(&self, value: &[u8]) -> Result<(), KeystoreError> {
        self.entered.send(()).expect("store entered");
        self.release
            .lock()
            .expect("gate")
            .recv()
            .expect("release store");
        *self.stored.lock().expect("stored") = Some(value.to_vec());
        Ok(())
    }
    fn load_dwk(&self) -> Result<Option<Vec<u8>>, KeystoreError> {
        Ok(self.stored.lock().expect("stored").clone())
    }
    fn delete_dwk(&self) -> Result<(), KeystoreError> {
        *self.stored.lock().expect("stored") = None;
        Ok(())
    }
}

#[test]
fn restore_excludes_unlock_and_late_remembered_publication() {
    let dir = tempfile::tempdir().expect("root");
    let root = dir.path().canonicalize().expect("canonical root");
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let mut ports = LocalVaultPorts::system_default();
    ports.keystore = Arc::new(GatedKeystore {
        entered: entered_tx,
        release: Mutex::new(release_rx),
        stored: Mutex::new(None),
    });
    let core = open_vault_at_path(&root.join("local.sqlite"), ports).expect("core");
    core.seed_offline_fixture("transition fixture password".into())
        .expect("fixture");
    let snapshot = core.snapshot_create(None).expect("snapshot");
    let worker = core.clone();
    let remember = std::thread::spawn(move || worker.remember_with_keystore());
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("OS write is blocked");
    core.snapshot_restore(snapshot.path.clone())
        .expect("restore");
    release_tx.send(()).expect("release OS write");
    assert!(remember.join().expect("worker").is_err());
    assert!(!core.remembered_unlock().expect("remembered state").armed);
    assert!(!core.vault_status().expect("locked").unlocked);

    core.unlock("transition fixture password".into())
        .expect("unlock");
    let previous_root = core.root_key().expect("root");
    let pool = core.pool();
    let _entered = core.runtime.enter();
    let connections = core.runtime.block_on(async {
        let mut connections = Vec::new();
        for _ in 0..5 {
            connections.push(pool.acquire().await.expect("reserve connection"));
        }
        connections
    });
    let worker = core.clone();
    let restore = std::thread::spawn(move || worker.snapshot_restore(snapshot.path));
    let deadline = Instant::now() + Duration::from_secs(3);
    while core.device_key.lock().expect("key").is_some() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(core.device_key.lock().expect("key").is_none());
    assert!(
        core.context_gate.try_read().is_err(),
        "restore owns the publication gate"
    );
    let during_restore = core.context_generation.load(Ordering::SeqCst);
    let worker = core.clone();
    let unlock = std::thread::spawn(move || worker.finish_unlock(previous_root, during_restore));
    drop(connections);
    restore.join().expect("restore worker").expect("restore");
    assert!(unlock.join().expect("unlock worker").is_err());
    assert!(!core.vault_status().expect("still locked").unlocked);
}
