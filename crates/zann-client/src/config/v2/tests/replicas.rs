//! Account isolation within one endpoint trust record.
use super::*;

fn authenticated_account(
    repo: &ConfigRepository,
    connection: &ConnectionId,
    profile: &str,
    storage: &str,
    subject: &str,
    store: &TestCredentialStore,
) -> Result<AuthenticatedSessionOutcome, ConfigError> {
    let snapshot = repo.snapshot()?;
    let metadata = snapshot.config().connections[connection].metadata();
    repo.commit_authenticated_session(
        snapshot.revision(),
        AuthenticatedSessionCommit::new(
            endpoint(
                &metadata.address,
                metadata.server_id.as_deref().unwrap(),
                metadata.server_fingerprint.as_deref().unwrap(),
            ),
            Some(storage.into()),
            AuthenticatedConnectionTarget::UseExisting {
                connection_id: connection.clone(),
                expected: StoredConnectionBinding::from_metadata(metadata),
            },
            IdentityCommit::InitializeOrMatch(identity(subject)),
            client_id("desktop"),
            profile,
            bundle("synthetic-access"),
        )
        .with_account_binding(subject, AuthMethod::Password),
        store,
    )
}

#[test]
fn two_subjects_share_trust_but_not_replica_proofs_or_credentials() {
    let temp = TempDir::new().unwrap();
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let id = ConnectionId::deterministic("test", "https://accounts.test");
    let first_storage = uuid::Uuid::now_v7().to_string();
    let second_storage = uuid::Uuid::now_v7().to_string();
    repo.pin_verified_connection(
        0,
        id.clone(),
        "Test".into(),
        &endpoint("https://accounts.test", "server", "pin"),
        Some(ReplicaReservation {
            profile: "first".into(),
            storage: first_storage.clone(),
            expected_subject: None,
            reuse_pending: false,
        }),
        None,
    )
    .unwrap();
    let first_subject = uuid::Uuid::now_v7().to_string();
    let second_subject = uuid::Uuid::now_v7().to_string();
    authenticated_account(&repo, &id, "first", &first_storage, &first_subject, &store).unwrap();
    let anchor = repo
        .resolve_credential_profile_anchor(&id, "first")
        .unwrap();
    let first_generation = repo
        .authorized_target_generation_from_anchor(&anchor)
        .unwrap();
    authenticated_account(
        &repo,
        &id,
        "second",
        &second_storage,
        &second_subject,
        &store,
    )
    .unwrap();
    let current = repo
        .resolve_credential_profile_anchor(&id, "first")
        .unwrap();
    let current_generation = repo
        .authorized_target_generation_from_anchor(&current)
        .unwrap();
    assert_eq!(
        first_generation.stable_target_fingerprint(),
        current_generation.stable_target_fingerprint()
    );
    assert_eq!(current.storage_id(), Some(first_storage.as_str()));
    assert_eq!(repo.snapshot().unwrap().config().connections.len(), 1);
    let before = fs::read(repo.paths().config()).unwrap();
    let calls = store.calls();
    assert!(authenticated_account(
        &repo,
        &id,
        "duplicate",
        &uuid::Uuid::now_v7().to_string(),
        &first_subject,
        &store
    )
    .is_err());
    assert!(authenticated_account(
        &repo,
        &id,
        "duplicate",
        &second_storage,
        &uuid::Uuid::now_v7().to_string(),
        &store
    )
    .is_err());
    assert_eq!(store.calls(), calls);
    assert_eq!(fs::read(repo.paths().config()).unwrap(), before);
    let second = repo
        .resolve_credential_profile_anchor(&id, "second")
        .unwrap();
    repo.remove_credential_profile(
        repo.snapshot().unwrap().revision(),
        &id,
        "first",
        ActiveCredentialAfterRemoval::Clear,
        &store,
    )
    .unwrap();
    let after = repo
        .resolve_credential_profile_anchor(&id, "second")
        .unwrap();
    assert_eq!(after.credentials(), second.credentials());
    assert_eq!(after.storage_id(), Some(second_storage.as_str()));
    assert_eq!(after.account_subject(), Some(second_subject.as_str()));
    assert_eq!(after.server_fingerprint(), Some("pin"));
}

#[test]
fn reconnect_constraint_refuses_a_different_authenticated_subject_before_credential_io() {
    let temp = TempDir::new().unwrap();
    let repo = repository(&temp);
    initialize(&repo);
    let id = ConnectionId::deterministic("test", "https://accounts.test");
    let storage = uuid::Uuid::now_v7().to_string();
    let expected = uuid::Uuid::now_v7().to_string();
    let store = TestCredentialStore::default();
    repo.pin_verified_connection(
        0,
        id.clone(),
        "Test".into(),
        &endpoint("https://accounts.test", "server", "pin"),
        Some(ReplicaReservation {
            profile: "reconnect".into(),
            storage: storage.clone(),
            expected_subject: Some(expected.clone()),
            reuse_pending: false,
        }),
        None,
    )
    .unwrap();
    let before = fs::read(repo.paths().config()).unwrap();
    let calls = store.calls();
    assert!(authenticated_account(
        &repo,
        &id,
        "reconnect",
        &storage,
        &uuid::Uuid::now_v7().to_string(),
        &store
    )
    .is_err());
    assert_eq!(store.calls(), calls);
    assert_eq!(fs::read(repo.paths().config()).unwrap(), before);
    authenticated_account(&repo, &id, "reconnect", &storage, &expected, &store).unwrap();
    let snapshot = repo.snapshot().unwrap();
    let profile = &snapshot.config().connections[&id].credential_profiles()["reconnect"];
    assert_eq!(profile.account_subject(), Some(expected.as_str()));
    assert!(serde_json::to_value(profile)
        .unwrap()
        .get("expected_account_subject")
        .is_none());
}

#[test]
fn anonymous_reservation_reuses_the_atomic_slot_and_never_recycles_an_authenticated_account() {
    let temp = TempDir::new().unwrap();
    let repo = repository(&temp);
    initialize(&repo);
    let id = ConnectionId::deterministic("test", "https://accounts.test");
    let endpoint = endpoint("https://accounts.test", "server", "pin");
    let reservation = |name: &str| ReplicaReservation {
        profile: name.into(),
        storage: uuid::Uuid::now_v7().to_string(),
        expected_subject: None,
        reuse_pending: true,
    };
    let (_, first) = repo
        .pin_verified_connection(
            0,
            id.clone(),
            "Test".into(),
            &endpoint,
            Some(reservation("first")),
            None,
        )
        .unwrap();
    assert!(matches!(
        repo.pin_verified_connection(
            0,
            id.clone(),
            "Test".into(),
            &endpoint,
            Some(reservation("racing")),
            None
        ),
        Err(ConfigError::RevisionConflict { .. })
    ));
    let (snapshot, repeated) = repo
        .pin_verified_connection(
            1,
            id.clone(),
            "Test".into(),
            &endpoint,
            Some(reservation("repeated")),
            None,
        )
        .unwrap();
    assert_eq!(first, repeated);
    assert_eq!(
        snapshot.config().connections[&id]
            .credential_profiles()
            .len(),
        1
    );
    let first = first.unwrap();
    let storage = snapshot.config().connections[&id]
        .profile_storage_id(&first)
        .unwrap()
        .to_string();
    let store = TestCredentialStore::default();
    let old_anchor = repo
        .resolve_login_anchor(&id, &first, &client_id("desktop"))
        .unwrap();
    authenticated_account(
        &repo,
        &id,
        &first,
        &storage,
        &uuid::Uuid::now_v7().to_string(),
        &store,
    )
    .unwrap();
    let current = repo.snapshot().unwrap();
    assert!(
        ensure_login_anchor_matches(
            &old_anchor,
            &old_anchor.repository_binding_digest,
            current.config(),
            &byte_digest(&fs::read(repo.paths().config()).unwrap())
        )
        .is_err(),
        "a competing login cannot replace the authenticated winner"
    );
    let (snapshot, next) = repo
        .pin_verified_connection(
            current.revision(),
            id.clone(),
            "Test".into(),
            &endpoint,
            Some(reservation("next")),
            None,
        )
        .unwrap();
    assert_eq!(next.as_deref(), Some("next"));
    assert_eq!(
        snapshot.config().connections[&id]
            .credential_profiles()
            .len(),
        2
    );
    assert_eq!(
        snapshot.config().connections[&id].profile_storage_id(&first),
        Some(storage.as_str())
    );
}

#[test]
fn replacing_a_token_clears_authenticated_email_with_subject() {
    let temp = TempDir::new().unwrap();
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let id = ConnectionId::deterministic("test", "https://accounts.test");
    repo.pin_verified_connection(
        0,
        id.clone(),
        "Test".into(),
        &endpoint("https://accounts.test", "server", "pin"),
        None,
        None,
    )
    .unwrap();
    let snapshot = repo.snapshot().unwrap();
    let metadata = snapshot.config().connections[&id].metadata();
    let subject = uuid::Uuid::now_v7().to_string();
    repo.commit_authenticated_session(
        snapshot.revision(),
        AuthenticatedSessionCommit::new(
            endpoint(&metadata.address, "server", "pin"),
            Some(uuid::Uuid::now_v7().to_string()),
            AuthenticatedConnectionTarget::UseExisting {
                connection_id: id.clone(),
                expected: StoredConnectionBinding::from_metadata(metadata),
            },
            IdentityCommit::NotRequired {
                email: "canonical@example.test".into(),
            },
            client_id("desktop"),
            "first",
            bundle("synthetic-access"),
        )
        .with_account_binding(subject, AuthMethod::Oidc),
        &store,
    )
    .unwrap();
    let snapshot = repo.snapshot().unwrap();
    assert_eq!(
        snapshot.config().connections[&id].credential_profiles()["first"].account_email(),
        Some("canonical@example.test")
    );
    let replaced = repo
        .replace_credential_bundle(
            snapshot.revision(),
            &id,
            "first",
            bundle("new-token"),
            CredentialActivation::MakeActive,
            &store,
        )
        .unwrap();
    let profile = &replaced.snapshot().config().connections[&id].credential_profiles()["first"];
    assert!(profile.account_email().is_none());
    assert!(profile.account_subject().is_none());
}
