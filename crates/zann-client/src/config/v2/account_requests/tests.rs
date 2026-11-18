use super::*;
use crate::account_access::intents::{PublicReceipt, PublicRequest, SecurityRequest};
use std::sync::Mutex;
use zann_core::api::account_access::*;
#[derive(Default)]
struct Store {
    values: Mutex<BTreeMap<CredentialId, CredentialSecret>>,
    corrupt: bool,
    root: PathBuf,
}
impl CredentialStore for Store {
    fn put(&self, id: &CredentialId, value: &CredentialSecret) -> Result<(), CredentialPortError> {
        let _config = LockKind::Config
            .pending_at(&self.root)
            .unwrap()
            .acquire_blocking(Duration::from_millis(1))
            .expect("no config lock during keystore I/O");
        self.values.lock().unwrap().insert(
            id.clone(),
            CredentialSecret::new(value.expose_secret()).unwrap(),
        );
        Ok(())
    }
    fn get(&self, id: &CredentialId) -> Result<Option<CredentialSecret>, CredentialPortError> {
        let _config = LockKind::Config
            .pending_at(&self.root)
            .unwrap()
            .acquire_blocking(Duration::from_millis(1))
            .unwrap();
        Ok(if self.corrupt {
            Some(CredentialSecret::new("wrong").unwrap())
        } else {
            self.values
                .lock()
                .unwrap()
                .get(id)
                .map(|v| CredentialSecret::new(v.expose_secret()).unwrap())
        })
    }
    fn delete(&self, id: &CredentialId) -> Result<(), CredentialPortError> {
        self.values.lock().unwrap().remove(id);
        Ok(())
    }
}
fn endpoint(pin: &str) -> VerifiedEndpointBinding {
    crate::remote::trust::verified_endpoint_binding_for_test("https://example.test", "server", pin)
}
#[test]
fn security_intents_cannot_serialize_password_or_recovery_codes_and_resume_exactly() {
    let root = tempfile::tempdir().unwrap();
    let repo = ConfigRepository::new(ClientPaths::new(root.path()));
    let code = zann_crypto::recovery::generate_server_recovery_key();
    let input = ActivateRecoveryCode {
        candidate_id: Uuid::new_v4(),
        expected_revision: 1,
        recovery_key: code.to_string(),
        disable_password: true,
        proof: ManagementProof::InitialPassword {
            server_password: "secret-server-password".into(),
        },
    };
    let intent = repo
        .stage_account_request(
            endpoint("pin"),
            None,
            "v1/users/me/security/recovery-code/activate",
            input.public_request(),
        )
        .unwrap();
    let bytes = std::fs::read_to_string(repo.account_requests_path()).unwrap();
    assert!(!bytes.contains(code.as_str()));
    assert!(!bytes.contains("secret-server-password"));
    let restarted = ConfigRepository::new(ClientPaths::new(root.path()));
    let exact = restarted
        .stage_account_request(endpoint("pin"), None, &intent.path, input.public_request())
        .unwrap();
    assert_eq!(exact.id, intent.id);
    let receipt = PublicReceipt::SecurityReceipt(SecurityReceipt {
        mutation_id: input.candidate_id,
        security_revision: 2,
        credential_id: None,
        recovery_key_version: Some(1),
        recovery_candidate_id: Some(input.candidate_id),
    });
    restarted
        .finish_account_request(intent.id, receipt.clone())
        .unwrap();
    restarted
        .finish_account_request(intent.id, receipt)
        .unwrap();
    assert!(restarted
        .finish_account_request(
            intent.id,
            PublicReceipt::SecurityReceipt(SecurityReceipt {
                mutation_id: Uuid::new_v4(),
                security_revision: 2,
                credential_id: None,
                recovery_key_version: Some(1),
                recovery_candidate_id: None
            })
        )
        .is_err());
    let next = restarted
        .stage_account_request(endpoint("pin"), None, &intent.path, input.public_request())
        .unwrap();
    assert_ne!(next.id, intent.id);
}
#[test]
fn recovery_replay_is_scoped_and_candidate_activation_requires_exact_keystore_readback() {
    let root = tempfile::tempdir().unwrap();
    let repo = ConfigRepository::new(ClientPaths::new(root.path()));
    let store = Store {
        root: root.path().into(),
        ..Store::default()
    };
    let id = Uuid::new_v4();
    let body = PublicRequest::RecoveryComplete {
        mutation_id: Uuid::new_v4(),
        expected_revision: 3,
        successor_code_version: 2,
    };
    repo.stage_account_request(
        endpoint("pin"),
        Some(id),
        &format!("v1/auth/recover/{id}/complete"),
        body,
    )
    .unwrap();
    assert_eq!(
        repo.pending_account_requests(id, &endpoint("pin"))
            .unwrap()
            .len(),
        1
    );
    assert!(repo
        .pending_account_requests(id, &endpoint("changed"))
        .unwrap()
        .is_empty());
    let (candidate, code) = repo
        .prepare_recovery_code(
            endpoint("pin"),
            "storage".into(),
            "subject".into(),
            1,
            None,
            &store,
        )
        .unwrap();
    assert!(!std::fs::read_to_string(repo.account_requests_path())
        .unwrap()
        .contains(code.as_str()));
    assert!(repo
        .confirmed_recovery_code(
            &candidate,
            &endpoint("changed"),
            "storage",
            "subject",
            &code,
            &store
        )
        .is_err());
    assert!(repo
        .confirmed_recovery_code(
            &candidate,
            &endpoint("pin"),
            "storage",
            "subject",
            "wrong",
            &store
        )
        .is_err());
    repo.confirmed_recovery_code(
        &candidate,
        &endpoint("pin"),
        "storage",
        "subject",
        &code,
        &store,
    )
    .unwrap();
    let broken = Store {
        root: root.path().into(),
        corrupt: true,
        ..Store::default()
    };
    assert!(repo
        .prepare_recovery_code(
            endpoint("pin"),
            "other".into(),
            "subject".into(),
            1,
            None,
            &broken
        )
        .is_err());
    assert_eq!(repo.read_account_requests().unwrap().codes.len(), 1);
    repo.forget_activated_recovery_code(candidate.id, &store)
        .unwrap();
    assert!(repo.read_account_requests().unwrap().codes.is_empty());
    assert!(store.values.lock().unwrap().is_empty());
}

#[test]
fn definitive_rejection_closes_dispatch_without_discarding_recovery_authority() {
    let root = tempfile::tempdir().unwrap();
    let repo = ConfigRepository::new(ClientPaths::new(root.path()));
    let authority = Uuid::new_v4();
    let request = PublicRequest::RecoveryOptions(RecoveryCredentialOptions {
        mutation_id: Uuid::new_v4(),
        expected_revision: 3,
        action: RecoveryOptionsPhase::Test,
    });
    let intent = repo
        .stage_account_request(
            endpoint("pin"),
            Some(authority),
            &format!("v1/auth/recover/{authority}/credential/options"),
            request.clone(),
        )
        .unwrap();
    repo.finish_account_request(intent.id, PublicReceipt::Rejected { status: 400 })
        .unwrap();
    assert!(repo
        .pending_account_requests(authority, &endpoint("pin"))
        .unwrap()
        .is_empty());
    // A later explicit action is a new dispatch, while the rejected one remains
    // immutable and cannot be turned into a successful receipt locally.
    let fresh = repo
        .stage_account_request(endpoint("pin"), Some(authority), &intent.path, request)
        .unwrap();
    assert_ne!(fresh.id, intent.id);
    assert!(repo
        .finish_account_request(intent.id, PublicReceipt::Rejected { status: 409 })
        .is_err());
    let id = Uuid::new_v4();
    let code = PublicRequest::Code {
        candidate_id: id,
        expected_revision: 1,
        disable_password: true,
        body_digest: "public-digest".into(),
        proof: crate::account_access::intents::PublicProof::FreshPassword,
    };
    let code_intent = repo
        .stage_account_request(
            endpoint("pin"),
            None,
            "v1/users/me/security/recovery-code/activate",
            code,
        )
        .unwrap();
    repo.finish_account_request(code_intent.id, PublicReceipt::Rejected { status: 400 })
        .unwrap();
    assert!(repo
        .recovery_code_request(id, &endpoint("pin"), false)
        .unwrap()
        .is_none());
    assert!(repo
        .recovery_code_request(id, &endpoint("pin"), true)
        .unwrap()
        .is_some());
}
