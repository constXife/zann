use super::*;
use chrono::Utc;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Mutex,
};
use zann_core::recovery::RecoveryState;

#[derive(Default)]
struct Store {
    values: Mutex<BTreeMap<CredentialId, CredentialSecret>>,
    corrupt: AtomicBool,
    reads: AtomicUsize,
    root: Option<PathBuf>,
}
impl Store {
    fn check_lock(&self) {
        if let Some(root) = &self.root {
            let _lock = LockKind::Config
                .pending_at(root)
                .unwrap()
                .acquire_blocking(Duration::from_millis(1))
                .expect("keystore I/O must run outside the config lock");
        }
    }
}
impl CredentialStore for Store {
    fn put(&self, id: &CredentialId, value: &CredentialSecret) -> Result<(), CredentialPortError> {
        self.check_lock();
        self.values.lock().unwrap().insert(
            id.clone(),
            CredentialSecret::new(value.expose_secret()).unwrap(),
        );
        Ok(())
    }
    fn get(&self, id: &CredentialId) -> Result<Option<CredentialSecret>, CredentialPortError> {
        self.check_lock();
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.corrupt.load(Ordering::Relaxed) {
            return Ok(Some(CredentialSecret::new("corrupt").unwrap()));
        }
        Ok(self
            .values
            .lock()
            .unwrap()
            .get(id)
            .map(|s| CredentialSecret::new(s.expose_secret()).unwrap()))
    }
    fn delete(&self, id: &CredentialId) -> Result<(), CredentialPortError> {
        self.check_lock();
        self.values.lock().unwrap().remove(id);
        Ok(())
    }
}
fn endpoint(pin: &str) -> VerifiedEndpointBinding {
    VerifiedEndpointBinding::new_for_test("https://vault.example", "server-id", pin).unwrap()
}
fn preparation() -> RecoveryPreparation {
    let mut prep =
        RecoveryPreparation::new(&endpoint("pin-a"), "alice@example.com".into()).unwrap();
    let code = Zeroizing::new(prep.next_recovery_key().to_owned());
    prep.confirm_saved(&code).unwrap();
    prep
}

#[test]
fn restart_keeps_secrets_out_of_intents_and_requires_the_exact_pin() {
    let root = tempfile::tempdir().unwrap();
    let repo = ConfigRepository::new(ClientPaths::new(root.path()));
    let store = Store {
        root: Some(root.path().into()),
        ..Store::default()
    };
    let prep = preparation();
    let id = prep.operation_id();
    repo.prepare_recovery(&prep, &store).unwrap();
    let bytes = fs::read_to_string(repo.paths.recovery_intents()).unwrap();
    assert!(!bytes.contains(prep.secrets.resume_token()));
    assert!(!bytes.contains(prep.next_recovery_key()));
    let restarted = ConfigRepository::new(ClientPaths::new(root.path()));
    let before = store.reads.load(Ordering::Relaxed);
    assert!(restarted
        .recovery_secrets(id, &endpoint("pin-b"), &store)
        .is_err());
    assert_eq!(before, store.reads.load(Ordering::Relaxed));
    let secrets = restarted
        .recovery_secrets(id, &endpoint("pin-a"), &store)
        .unwrap();
    assert!(secrets.confirms_code(prep.next_recovery_key()));
    restarted
        .mark_recovery_dispatched(id, &endpoint("pin-a"), [7; 32])
        .unwrap();
    assert!(restarted
        .mark_recovery_dispatched(id, &endpoint("pin-a"), [8; 32])
        .is_err());
    assert!(restarted.discard_prepared_recovery(id, &store).is_err());
    assert!(restarted
        .recovery_secrets(id, &endpoint("pin-a"), &store)
        .is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(repo.paths.recovery_intents())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
#[test]
fn readback_failure_and_missing_confirmation_never_publish_an_intent() {
    let root = tempfile::tempdir().unwrap();
    let repo = ConfigRepository::new(ClientPaths::new(root.path()));
    let store = Store::default();
    let mut prep = preparation();
    prep.confirmed = false;
    assert!(repo.prepare_recovery(&prep, &store).is_err());
    assert!(store.values.lock().unwrap().is_empty());
    prep.confirmed = true;
    store.corrupt.store(true, Ordering::Relaxed);
    assert!(repo.prepare_recovery(&prep, &store).is_err());
    assert!(!repo.paths.recovery_intents().exists());
}
#[test]
fn scope_copy_and_status_rollback_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let repo = ConfigRepository::new(ClientPaths::new(root.path()));
    let store = Store::default();
    let prep = preparation();
    let id = prep.operation_id();
    repo.prepare_recovery(&prep, &store).unwrap();
    repo.mark_recovery_dispatched(id, &endpoint("pin-a"), [1; 32])
        .unwrap();
    let mut status = RecoveryStatus {
        operation_id: id,
        user_id: Uuid::new_v4(),
        auth_epoch: 2,
        account_key_epoch: Some(1),
        state: RecoveryState::Consumed,
        revision: 1,
        expires_at: Utc::now() + chrono::Duration::hours(24),
    };
    repo.observe_recovery(id, &endpoint("pin-a"), status.clone())
        .unwrap();
    status.revision = 2;
    repo.observe_recovery(id, &endpoint("pin-a"), status.clone())
        .unwrap();
    status.revision = 1;
    assert!(repo
        .observe_recovery(id, &endpoint("pin-a"), status)
        .is_err());
    let other = tempfile::tempdir().unwrap();
    fs::copy(
        repo.paths.recovery_intents(),
        other.path().join(AUTH_RECOVERY_INTENTS_FILENAME),
    )
    .unwrap();
    assert!(ConfigRepository::new(ClientPaths::new(other.path()))
        .pending_recoveries()
        .is_err());
}
#[test]
fn capacity_and_discard_are_account_scoped() {
    let root = tempfile::tempdir().unwrap();
    let repo = ConfigRepository::new(ClientPaths::new(root.path()));
    let store = Store::default();
    let mut ids = Vec::new();
    for _ in 0..MAX_CLIENT_RECOVERY_OPERATIONS {
        let prep = preparation();
        ids.push(prep.operation_id());
        repo.prepare_recovery(&prep, &store).unwrap();
    }
    let count = store.values.lock().unwrap().len();
    assert!(repo.prepare_recovery(&preparation(), &store).is_err());
    assert_eq!(count, store.values.lock().unwrap().len());
    repo.discard_prepared_recovery(ids[0], &store).unwrap();
    assert_eq!(
        repo.pending_recoveries().unwrap().len(),
        MAX_CLIENT_RECOVERY_OPERATIONS - 1
    );
    assert!(repo
        .recovery_secrets(ids[1], &endpoint("pin-a"), &store)
        .is_ok());
}
#[cfg(unix)]
#[test]
fn symlink_journal_is_never_followed() {
    let root = tempfile::tempdir().unwrap();
    let target = tempfile::NamedTempFile::new().unwrap();
    std::os::unix::fs::symlink(
        target.path(),
        root.path().join(AUTH_RECOVERY_INTENTS_FILENAME),
    )
    .unwrap();
    let repo = ConfigRepository::new(ClientPaths::new(root.path()));
    assert!(repo
        .prepare_recovery(&preparation(), &Store::default())
        .is_err());
    assert_eq!(fs::metadata(target.path()).unwrap().len(), 0);
}
