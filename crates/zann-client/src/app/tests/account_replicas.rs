//! Native provisioning remains bounded and preserves exact reconnect intent.
use super::*;

fn ready(outcome: PrepareConnectionOutcome) -> PreparedConnection {
    let PrepareConnectionOutcome::Ready(prepared) = outcome else {
        panic!("ready")
    };
    prepared
}

#[tokio::test]
async fn cancelled_account_probes_reuse_one_unowned_slot() {
    let dir = tempfile::tempdir().unwrap();
    let app = trusting_client(&dir);
    let mut server = mockito::Server::new_async().await;
    let _mock = serve_identity(
        &mut server,
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        "pin",
    )
    .await;
    let first = ready(
        app.prepare_account_connection(&server.url(), CONNECTION_NAME, None)
            .await
            .unwrap(),
    );
    for _ in 0..200 {
        let next = ready(
            app.prepare_account_connection(&server.url(), CONNECTION_NAME, None)
                .await
                .unwrap(),
        );
        assert_eq!(next.target(), first.target());
        assert_eq!(next.storage_id(), first.storage_id());
    }
    let snapshot = app.repository.snapshot().unwrap();
    assert_eq!(snapshot.config().connections.len(), 1);
    assert_eq!(
        snapshot
            .config()
            .connections
            .values()
            .next()
            .unwrap()
            .credential_profiles()
            .len(),
        1
    );
    assert!(
        app.account_locations().unwrap().is_empty(),
        "reservation is not an authenticated account"
    );
}

#[tokio::test]
async fn reconnect_trust_confirmation_keeps_the_selected_uuid_and_subject_in_one_commit() {
    let dir = tempfile::tempdir().unwrap();
    let mut server = mockito::Server::new_async().await;
    let storage = Uuid::now_v7();
    let subject = Uuid::now_v7().to_string();
    let database = Arc::new(StorageDatabase {
        kept: Some(ReplicaAccount {
            storage_id: storage,
            address: server.url(),
            account_subject: subject.clone(),
            server_fingerprint: "old".into(),
        }),
        ..StorageDatabase::default()
    });
    let app = trusting_client_over(&dir, database.clone());
    let _mock = serve_identity(
        &mut server,
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        "new",
    )
    .await;
    let before = app.repository.snapshot().unwrap().revision();
    let outcome = app
        .prepare_account_connection(&server.url(), CONNECTION_NAME, Some(&storage.to_string()))
        .await
        .unwrap();
    let PrepareConnectionOutcome::FingerprintChanged(challenge) = outcome else {
        panic!("challenge")
    };
    assert_eq!(challenge.old_fingerprint(), "old");
    assert_eq!(challenge.new_fingerprint(), "new");
    assert_eq!(app.repository.snapshot().unwrap().revision(), before);
    let prepared = app.trust_connection(*challenge).unwrap();
    let snapshot = app.repository.snapshot().unwrap();
    assert_eq!(snapshot.revision(), before + 1);
    assert_eq!(prepared.storage_id(), storage.to_string());
    let profile = &snapshot.config().connections[prepared.target().connection_id()]
        .credential_profiles()[prepared.target().profile_name()];
    assert_eq!(
        serde_json::to_value(profile).unwrap()["expected_account_subject"],
        subject
    );
    let again = ready(
        app.prepare_account_connection(&server.url(), CONNECTION_NAME, Some(&storage.to_string()))
            .await
            .unwrap(),
    );
    assert_eq!(again.target(), prepared.target());
    assert!(database.released.lock().unwrap().is_empty());
}

#[tokio::test]
async fn native_prepare_reuses_custom_endpoint_owner_and_whole_endpoint_forget_resolves_it() {
    let dir = tempfile::tempdir().unwrap();
    let app = trusting_client(&dir);
    let mut server = mockito::Server::new_async().await;
    let _mock = serve_identity(
        &mut server,
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        "pin",
    )
    .await;
    let custom = ready(
        app.prepare_connection(&server.url(), "Custom CLI name", "custom-profile")
            .await
            .unwrap(),
    );
    let native = ready(
        app.prepare_account_connection(&server.url(), "Remote", None)
            .await
            .unwrap(),
    );
    assert_eq!(
        custom.target().connection_id(),
        native.target().connection_id()
    );
    app.remove_connection(&server.url()).unwrap();
    assert!(app
        .repository
        .snapshot()
        .unwrap()
        .config()
        .connections
        .is_empty());
}
