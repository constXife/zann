use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};

const PASSWORD: &str = "synthetic-device-password";
#[derive(Default)]
struct BiometricStore {
    key: Mutex<Option<Vec<u8>>>,
    reads: AtomicUsize,
    cancel: AtomicBool,
    cancel_operation: Mutex<Option<zann_client::app::SessionCancellationHandle>>,
}
impl Keystore for BiometricStore {
    fn status(&self) -> KeystoreStatus {
        KeystoreStatus {
            supported: true,
            biometrics_available: true,
            reason: None,
            message: None,
        }
    }
    fn store_dwk(&self, key: &[u8]) -> Result<(), KeystoreError> {
        *self.key.lock().expect("key") = Some(key.to_vec());
        Ok(())
    }
    fn load_dwk(&self) -> Result<Option<Vec<u8>>, KeystoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(operation) = self.cancel_operation.lock().expect("operation").take() {
            operation.cancel();
        }
        if self.cancel.load(Ordering::SeqCst) {
            return Err(KeystoreError::Cancelled);
        }
        Ok(self.key.lock().expect("key").clone())
    }
    fn delete_dwk(&self) -> Result<(), KeystoreError> {
        self.key.lock().expect("key").take();
        Ok(())
    }
}
fn fixture() -> (
    tempfile::TempDir,
    Arc<LocalVault>,
    Arc<zann_keystore::FakeHardwareAuthenticator>,
    Arc<BiometricStore>,
) {
    let dir = tempfile::tempdir().expect("root");
    let root = dir.path().canonicalize().expect("canonical");
    let hardware = Arc::new(zann_keystore::FakeHardwareAuthenticator::new(1));
    let biometric = Arc::new(BiometricStore::default());
    let mut ports = LocalVaultPorts::system_default();
    ports.authenticator = hardware.clone();
    ports.keystore = biometric.clone();
    let core = open_vault_at_path(&root.join("local.sqlite"), ports).expect("open");
    core.seed_offline_fixture(PASSWORD.into()).expect("fixture");
    (dir, core, hardware, biometric)
}
fn authorize(core: &LocalVault, proof: ExportStepUp) -> LocalResult<ExportAuthorization> {
    core.authorize_export(
        proof,
        SessionOperation::new(Instant::now() + Duration::from_secs(120)).0,
    )
}
fn password(core: &LocalVault) -> ExportAuthorization {
    authorize(core, ExportStepUp::device_password(PASSWORD.into())).expect("fresh password")
}
fn hardware(password: Option<&str>, pin: Option<&str>) -> ExportStepUp {
    ExportStepUp {
        password: password.map(str::to_string),
        factor: ExportFactor::HardwareKey {
            pin: pin.map(str::to_string),
        },
    }
}

#[test]
fn plaintext_export_requires_fresh_single_use_password_proof_before_output_creation() {
    let (dir, core, _, _) = fixture();
    let path = dir.path().join("export.json");
    assert!(matches!(
        core.backup_export_file(
            path.display().to_string(),
            ExportAuthorization::from_token("forged".into())
        ),
        Err(LocalError::Export(ExportError::AuthorizationRequired))
    ));
    assert!(!path.exists());
    let error = authorize(
        &core,
        ExportStepUp::device_password("wrong-sentinel-password".into()),
    )
    .expect_err("wrong password");
    assert!(!format!("{error:?} {error}").contains("sentinel"));
    assert!(std::error::Error::source(&error).is_some());
    let proof = password(&core);
    let replay = ExportAuthorization::from_token(proof.token().into());
    core.backup_export_file(path.display().to_string(), proof)
        .expect("export");
    assert!(path.exists());
    assert!(core
        .backup_export_file(dir.path().join("replay.json").display().to_string(), replay)
        .is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).expect("file").permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn expiry_lock_keyring_change_and_operation_cancellation_invalidate_proofs() {
    let (dir, core, _, _) = fixture();
    let path = dir.path().join("must-not-exist").display().to_string();
    let proof = password(&core);
    core.export_authorization
        .lock()
        .expect("proof")
        .as_mut()
        .expect("pending")
        .expires = Instant::now() - Duration::from_secs(1);
    assert!(matches!(
        core.backup_export_file(path.clone(), proof),
        Err(LocalError::Export(ExportError::AuthorizationExpired))
    ));
    let (op, cancel) = SessionOperation::new(Instant::now() + Duration::from_secs(120));
    let proof = core
        .authorize_export(ExportStepUp::device_password(PASSWORD.into()), op)
        .expect("authorize");
    cancel.cancel();
    assert!(matches!(
        core.backup_export_file(path.clone(), proof),
        Err(LocalError::Cancelled)
    ));
    let proof = password(&core);
    let source = core.device_unlock().expect("keyring");
    let mut changed = source.clone();
    changed.accounts.clear();
    core.commit_device_unlock(Some(&source), &changed)
        .expect("evict");
    assert!(core.backup_export_file(path.clone(), proof).is_err());
    let proof = password(&core);
    core.lock().expect("lock");
    assert!(core.backup_export_file(path.clone(), proof).is_err());
    assert!(!Path::new(&path).exists());
}

#[test]
fn hardware_confirmation_is_live_and_pin_cancellation_preserves_source() {
    let (dir, core, token, _) = fixture();
    core.enroll_hardware_key("Synthetic key".into(), &|| {})
        .expect("enroll");
    token.require_pin("1357".into());
    let error =
        authorize(&core, hardware(None, Some("wrong-sentinel-pin"))).expect_err("wrong PIN");
    assert!(
        matches!(error, LocalError::Unlock { ref kind, .. } if kind == "hardware_key_pin_invalid")
    );
    assert!(!format!("{error:?} {error}").contains("sentinel"));
    assert!(std::error::Error::source(&error).is_some());
    token.fail_next_derive(zann_keystore::FidoError::Timeout);
    assert!(authorize(&core, hardware(None, Some("1357"))).is_err());
    let before = token.touch_requests();
    let proof = authorize(&core, hardware(None, Some("1357"))).expect("live touch/PIN");
    assert_eq!(token.touch_requests(), before + 1);
    core.backup_export_file(
        dir.path().join("hardware.json").display().to_string(),
        proof,
    )
    .expect("export");
    token.disconnect();
    password(&core); // AnyConfiguredFactor allows offline recovery with the device password.
}

#[test]
fn strict_policy_requires_both_factors_and_rejects_removing_the_last_one() {
    let (_dir, core, _, _) = fixture();
    assert!(matches!(
        core.set_export_policy(
            ExportPolicy::PasswordAndHardwareOrBiometric,
            password(&core)
        ),
        Err(LocalError::Export(ExportError::SecondFactorRequired))
    ));
    let enrolled = core
        .enroll_hardware_key("Key".into(), &|| {})
        .expect("enroll");
    core.set_export_policy(
        ExportPolicy::PasswordAndHardwareOrBiometric,
        password(&core),
    )
    .expect("opt in");
    assert!(matches!(
        authorize(&core, ExportStepUp::device_password(PASSWORD.into())),
        Err(LocalError::Export(ExportError::SecondFactorRequired))
    ));
    assert!(matches!(
        authorize(&core, hardware(None, None)),
        Err(LocalError::Export(ExportError::PasswordRequired))
    ));
    assert!(matches!(
        core.remove_hardware_key(enrolled.credential_id.clone()),
        Err(LocalError::Export(ExportError::LastFactor))
    ));
    let proof = authorize(&core, hardware(Some(PASSWORD), None)).expect("both factors");
    core.set_export_policy(ExportPolicy::AnyConfiguredFactor, proof)
        .expect("explicitly disable");
    core.remove_hardware_key(enrolled.credential_id)
        .expect("remove");
    password(&core);
}

#[test]
fn biometric_confirmation_is_fresh_and_dismissal_does_not_mint_a_proof() {
    let (_dir, core, _, biometric) = fixture();
    core.remember_with_keystore().expect("enroll biometric key");
    let before = biometric.reads.load(Ordering::SeqCst);
    authorize(
        &core,
        ExportStepUp {
            password: None,
            factor: ExportFactor::Biometric,
        },
    )
    .expect("fresh biometric");
    assert_eq!(biometric.reads.load(Ordering::SeqCst), before + 1);
    biometric.cancel.store(true, Ordering::SeqCst);
    assert!(authorize(
        &core,
        ExportStepUp {
            password: None,
            factor: ExportFactor::Biometric
        }
    )
    .is_err());
    biometric.cancel.store(false, Ordering::SeqCst);
    core.set_export_policy(
        ExportPolicy::PasswordAndHardwareOrBiometric,
        password(&core),
    )
    .expect("strict biometric policy");
    authorize(
        &core,
        ExportStepUp {
            password: Some(PASSWORD.into()),
            factor: ExportFactor::Biometric,
        },
    )
    .expect("password plus live biometric");
    assert!(matches!(
        core.forget_remembered(),
        Err(LocalError::Export(ExportError::LastFactor))
    ));
}

#[test]
fn lock_cancels_a_consumed_permit_waiting_for_sqlite_without_holding_the_context_gate() {
    let (dir, core, _, _) = fixture();
    let proof = password(&core);
    let pool = core.pool();
    let _entered = core.runtime.enter();
    let permits = core.runtime.block_on(async {
        let mut permits = Vec::new();
        for _ in 0..5 {
            permits.push(pool.acquire().await.expect("connection"));
        }
        permits
    });
    let other = core.clone();
    let target = dir.path().join("cancelled.json");
    std::fs::write(&target, b"previous complete backup").expect("existing destination");
    let destination = target.display().to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        tx.send(other.backup_export_file(destination, proof))
            .expect("result")
    });
    let until = Instant::now() + Duration::from_secs(2);
    while core.syncs.len() == 0 && Instant::now() < until {
        std::thread::yield_now();
    }
    assert_eq!(core.syncs.len(), 1);
    core.lock().expect("lock without waiting for SQLite");
    assert!(matches!(
        rx.recv_timeout(Duration::from_secs(5))
            .expect("prompt cancellation"),
        Err(LocalError::Cancelled)
    ));
    worker.join().expect("worker");
    assert_eq!(
        std::fs::read(&target).expect("destination"),
        b"previous complete backup"
    );
    assert!(!std::fs::read_dir(dir.path()).expect("dir").any(|e| e
        .expect("entry")
        .file_name()
        .to_string_lossy()
        .starts_with(".zann-export-")));
    drop(permits);
}

#[test]
fn an_output_failure_burns_the_permit_and_preserves_the_existing_destination() {
    let (dir, core, _, _) = fixture();
    let proof = password(&core);
    let replay = ExportAuthorization::from_token(proof.token().into());
    let target = dir.path().join("destination-directory");
    std::fs::create_dir(&target).expect("directory");
    assert!(core
        .backup_export_file(target.display().to_string(), proof)
        .is_err());
    assert!(target.is_dir());
    assert!(core
        .backup_export_file(dir.path().join("retry.json").display().to_string(), replay)
        .is_err());
    assert!(!std::fs::read_dir(dir.path()).expect("dir").any(|e| e
        .expect("entry")
        .file_name()
        .to_string_lossy()
        .starts_with(".zann-export-")));
}

#[test]
fn cancellation_during_a_native_factor_prompt_cannot_mint_authorization() {
    let (dir, core, _, biometric) = fixture();
    core.remember_with_keystore().expect("enroll");
    let (operation, cancel) = SessionOperation::new(Instant::now() + Duration::from_secs(120));
    *biometric.cancel_operation.lock().expect("operation") = Some(cancel);
    assert!(matches!(
        core.authorize_export(
            ExportStepUp {
                password: None,
                factor: ExportFactor::Biometric
            },
            operation
        ),
        Err(LocalError::Cancelled)
    ));
    assert!(core.export_authorization.lock().expect("pending").is_none());
    assert!(!dir.path().join("backup.json").exists());
}

#[test]
fn unknown_persisted_policy_fails_closed_instead_of_disabling_strict_mode() {
    let (_dir, core, _, _) = fixture();
    let pool = core.pool();
    core.runtime
        .block_on(
            zann_db::local::MetadataRepo::new(&pool)
                .set_value("export_step_up_policy", "unknown-policy"),
        )
        .expect("corrupt policy");
    assert!(matches!(
        authorize(&core, ExportStepUp::device_password(PASSWORD.into())),
        Err(LocalError::Export(ExportError::InvalidPolicy))
    ));
}
