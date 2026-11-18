#![cfg(feature = "postgres-tests")]
mod account_access_support;
mod support;
use account_access_support::{token::Token, TestApp, ORIGIN};
use axum::http::{Method, StatusCode};
use uuid::Uuid;
use zann_core::{api::account_access::*, recovery::RecoveryState};
use zann_crypto::recovery::RecoverySecrets;

#[tokio::test]
async fn consume_resume_test_complete_and_fresh_ordinary_login_are_separate_authorities() {
    let app = TestApp::new().await;
    let initial = app.register_user().await;
    let (key, descriptor, security) = app.descriptor(&initial.access_token).await;
    let (lost, _) = app
        .enroll_auth_only(&initial.access_token, &key, &descriptor)
        .await;
    let code = app
        .activate_recovery_code(&initial.access_token, &key, &descriptor)
        .await;
    let id = Uuid::new_v4();
    let secrets = RecoverySecrets::generate();
    let input = RecoveryConsume {
        operation_id: id,
        locator: "person@example.test".into(),
        recovery_key: code.to_string(),
        next_recovery_key: secrets.next_recovery_key().into(),
        device: TestApp::device(),
    };
    let consumed: RecoveryConsumeReceipt = app
        .recovery(Method::POST, "/v1/auth/recover", id, &secrets, &input)
        .await;
    assert_eq!(consumed.auth_epoch, security.auth_epoch + 1);
    let replay: RecoveryConsumeReceipt = app
        .recovery(Method::POST, "/v1/auth/recover", id, &secrets, &input)
        .await;
    assert_eq!(consumed.operation_id, replay.operation_id);
    assert_eq!(
        consumed.successor_code_version,
        replay.successor_code_version
    );
    let (status, _) = app
        .request(
            Method::GET,
            "/v1/users/me/security",
            Some(&initial.access_token),
            &(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A restricted resume token cannot be substituted into ordinary Bearer auth.
    let (status, _) = app
        .request(
            Method::GET,
            "/v1/users/me/security",
            Some(secrets.resume_token()),
            &(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let root = format!("/v1/auth/recover/{id}");
    let view: RecoveryView = app.recovery(Method::GET, &root, id, &secrets, &()).await;
    assert_eq!(view.status.state, RecoveryState::Consumed);
    assert_eq!(view.descriptor, Some(descriptor));
    let options = RecoveryCredentialOptions {
        mutation_id: Uuid::new_v4(),
        expected_revision: view.status.revision,
        action: RecoveryOptionsPhase::Register {
            name: "replacement key".into(),
            mode: PasskeyMode::AuthOnly,
        },
    };
    let registration: RecoveryStepReply = app
        .recovery(
            Method::POST,
            &format!("{root}/credential/options"),
            id,
            &secrets,
            &options,
        )
        .await;
    let RecoveryStepResult::Ceremony { options } = registration.result else {
        panic!("registration options");
    };
    let (replacement, response) = Token::register(&options, ORIGIN, true);
    let registration_finish = RecoveryCredentialFinish {
        mutation_id: Uuid::new_v4(),
        expected_revision: registration.status.revision,
        action: RecoveryFinishPhase::Register { response },
    };
    let testing: RecoveryStepReply = app
        .recovery(
            Method::POST,
            &format!("{root}/credential/finish"),
            id,
            &secrets,
            &registration_finish,
        )
        .await;
    let RecoveryStepResult::Ceremony { options } = testing.result else {
        panic!("test options");
    };
    let tested: RecoveryStepReply = app
        .recovery(
            Method::POST,
            &format!("{root}/credential/finish"),
            id,
            &secrets,
            &RecoveryCredentialFinish {
                mutation_id: Uuid::new_v4(),
                expected_revision: testing.status.revision,
                action: RecoveryFinishPhase::Test {
                    response: replacement.assert(&options, ORIGIN, true, false),
                },
            },
        )
        .await;
    assert_eq!(tested.status.state, RecoveryState::CredentialReady);
    // Original sanitized replies survive later revisions; no verifier repeats.
    let replay: RecoveryStepReply = app
        .recovery(
            Method::POST,
            &format!("{root}/credential/finish"),
            id,
            &secrets,
            &registration_finish,
        )
        .await;
    assert_eq!(replay.status.revision, testing.status.revision);
    let login_options: CeremonyOptions = app
        .ok(
            "/v1/auth/passkeys/login/options",
            None,
            &PasskeyLoginOptions {
                operation_id: Uuid::new_v4(),
                device: TestApp::device(),
            },
        )
        .await;
    let premature = CeremonyFinish {
        operation_id: login_options.operation_id,
        response: replacement.assert(&login_options, ORIGIN, true, false),
    };
    let (status, _) = app
        .request(
            Method::POST,
            "/v1/auth/passkeys/login/finish",
            None,
            &premature,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let complete = RecoveryComplete {
        successor_code_version: consumed.successor_code_version,
        mutation_id: Uuid::new_v4(),
        expected_revision: tested.status.revision,
        next_recovery_key: secrets.next_recovery_key().into(),
    };
    let completed: RecoveryStepReply = app
        .recovery(
            Method::POST,
            &format!("{root}/complete"),
            id,
            &secrets,
            &complete,
        )
        .await;
    assert_eq!(completed.status.state, RecoveryState::Completed);
    let completed_again: RecoveryStepReply = app
        .recovery(
            Method::POST,
            &format!("{root}/complete"),
            id,
            &secrets,
            &complete,
        )
        .await;
    assert_eq!(completed_again.status.revision, completed.status.revision);
    // A signed assertion over a pre-completion challenge is never a fresh login.
    let (status, _) = app
        .request(
            Method::POST,
            "/v1/auth/passkeys/login/finish",
            None,
            &premature,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let fresh = app.login_with(&replacement).await;
    assert_eq!(fresh.user_id, consumed.user_id);
    assert_eq!(
        app.security(&fresh.tokens.access_token)
            .await
            .credentials
            .len(),
        1
    );
    let options: CeremonyOptions = app
        .ok(
            "/v1/auth/passkeys/login/options",
            None,
            &PasskeyLoginOptions {
                operation_id: Uuid::new_v4(),
                device: TestApp::device(),
            },
        )
        .await;
    let (status, _) = app
        .request(
            Method::POST,
            "/v1/auth/passkeys/login/finish",
            None,
            &CeremonyFinish {
                operation_id: options.operation_id,
                response: lost.assert(&options, ORIGIN, true, false),
            },
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = app
        .recovery_request(Method::GET, &format!("{root}/data"), id, &secrets, &())
        .await;
    assert_eq!(status, StatusCode::GONE);
}

#[tokio::test]
async fn full_recovery_requires_custody_bound_grant_and_successor_confirmation() {
    use zann_crypto::account_access::{encode, AccountCustody, AccountGrant, AccountPrf};
    let app = TestApp::new().await;
    let initial = app.register_user().await;
    let (key, descriptor, _) = app.descriptor(&initial.access_token).await;
    let _ = app
        .enroll_auth_only(&initial.access_token, &key, &descriptor)
        .await;
    // Publish a real personal vault envelope without placing its plaintext key
    // in any RP/recovery request. Recovery reads only this ciphertext for proof.
    let vault = zann_db::repo::VaultRepo::new(&app.pool)
        .get_personal_by_user(descriptor.user_id)
        .await
        .expect("personal vault")
        .expect("exists");
    let vault_key = zann_crypto::SecretKey::generate();
    let wrapped = zann_crypto::vault_crypto::encrypt_vault_key(&key, vault.id, &vault_key)
        .expect("local wrap");
    zann_db::repo::VaultRepo::new(&app.pool)
        .update_key_by_id(vault.id, &wrapped)
        .await
        .expect("publish opaque envelope");
    let code = app
        .activate_recovery_code(&initial.access_token, &key, &descriptor)
        .await;
    let id = Uuid::new_v4();
    let secrets = RecoverySecrets::generate();
    let root = format!("/v1/auth/recover/{id}");
    let consumed: RecoveryConsumeReceipt = app
        .recovery(
            Method::POST,
            "/v1/auth/recover",
            id,
            &secrets,
            &RecoveryConsume {
                operation_id: id,
                locator: "person@example.test".into(),
                recovery_key: code.to_string(),
                next_recovery_key: secrets.next_recovery_key().into(),
                device: TestApp::device(),
            },
        )
        .await;
    let material: RecoveryKeyMaterial = app
        .recovery(Method::GET, &format!("{root}/data"), id, &secrets, &())
        .await;
    let personal = material.personal.expect("personal key ciphertext");
    assert_eq!(personal.vault_id, vault.id);
    let read_key = zann_crypto::vault_crypto::decrypt_vault_key(
        &key,
        personal.vault_id,
        &zann_crypto::account_access::decode(&personal.vault_key_enc, 65536).expect("encoding"),
    )
    .expect("local proof");
    assert_eq!(read_key.as_bytes(), vault_key.as_bytes());
    let registration: RecoveryStepReply = app
        .recovery(
            Method::POST,
            &format!("{root}/credential/options"),
            id,
            &secrets,
            &RecoveryCredentialOptions {
                mutation_id: Uuid::new_v4(),
                expected_revision: 1,
                action: RecoveryOptionsPhase::Register {
                    name: "full replacement".into(),
                    mode: PasskeyMode::VaultUnlock,
                },
            },
        )
        .await;
    let RecoveryStepResult::Ceremony { options } = registration.result else {
        panic!("register options");
    };
    let (hardware, response) = Token::register(&options, ORIGIN, true);
    let testing: RecoveryStepReply = app
        .recovery(
            Method::POST,
            &format!("{root}/credential/finish"),
            id,
            &secrets,
            &RecoveryCredentialFinish {
                mutation_id: Uuid::new_v4(),
                expected_revision: registration.status.revision,
                action: RecoveryFinishPhase::Register { response },
            },
        )
        .await;
    let RecoveryStepResult::Ceremony { options } = testing.result else {
        panic!("test options");
    };
    let tested: RecoveryStepReply = app
        .recovery(
            Method::POST,
            &format!("{root}/credential/finish"),
            id,
            &secrets,
            &RecoveryCredentialFinish {
                mutation_id: Uuid::new_v4(),
                expected_revision: testing.status.revision,
                action: RecoveryFinishPhase::Test {
                    response: hardware.assert(&options, ORIGIN, true, false),
                },
            },
        )
        .await;
    assert_eq!(
        tested.status.state,
        RecoveryState::Consumed,
        "Full cannot be ready before its custody grant"
    );
    let prf = AccountPrf::from_bytes([73; 32]);
    let grant = AccountGrant::create(
        &descriptor,
        options.rp_id.clone(),
        hardware
            .assert(&options, ORIGIN, true, false)
            .credential_id()
            .into(),
        Uuid::new_v4(),
        &key,
        &prf,
    )
    .expect("local grant");
    let nonce: RecoveryStepReply = app
        .recovery(
            Method::POST,
            &format!("{root}/credential/options"),
            id,
            &secrets,
            &RecoveryCredentialOptions {
                mutation_id: Uuid::new_v4(),
                expected_revision: tested.status.revision,
                action: RecoveryOptionsPhase::Grant {
                    body_digest: encode(&grant.body_digest().expect("digest")),
                },
            },
        )
        .await;
    let RecoveryStepResult::Custody { context } = nonce.result else {
        panic!("custody context");
    };
    let custody = AccountCustody::derive(
        &key,
        &descriptor.server_id,
        descriptor.user_id,
        descriptor.key_epoch,
    )
    .expect("custody");
    let signature = custody.sign_mutation(&descriptor, &context).expect("proof");
    let ready: RecoveryStepReply = app
        .recovery(
            Method::POST,
            &format!("{root}/credential/finish"),
            id,
            &secrets,
            &RecoveryCredentialFinish {
                mutation_id: Uuid::new_v4(),
                expected_revision: nonce.status.revision,
                action: RecoveryFinishPhase::Grant {
                    grant: Box::new(grant.clone()),
                    proof: CustodyProof { context, signature },
                },
            },
        )
        .await;
    assert_eq!(ready.status.state, RecoveryState::CredentialReady);
    let wrong = RecoveryComplete {
        successor_code_version: consumed.successor_code_version,
        mutation_id: Uuid::new_v4(),
        expected_revision: ready.status.revision,
        next_recovery_key: zann_crypto::recovery::generate_server_recovery_key().to_string(),
    };
    let (status, _) = app
        .recovery_request(
            Method::POST,
            &format!("{root}/complete"),
            id,
            &secrets,
            &wrong,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let completed: RecoveryStepReply = app
        .recovery(
            Method::POST,
            &format!("{root}/complete"),
            id,
            &secrets,
            &RecoveryComplete {
                successor_code_version: consumed.successor_code_version,
                mutation_id: Uuid::new_v4(),
                expected_revision: ready.status.revision,
                next_recovery_key: secrets.next_recovery_key().into(),
            },
        )
        .await;
    assert_eq!(completed.status.state, RecoveryState::Completed);
    let logged = app.login_with(&hardware).await;
    let AccountKeyAccess::Ready {
        grant: received,
        descriptor: received_descriptor,
    } = logged.key_access
    else {
        panic!("full key grant");
    };
    assert_eq!(*received, grant);
    assert_eq!(received_descriptor, descriptor);
    assert_eq!(
        received
            .open(&descriptor, &prf)
            .expect("local unwrap")
            .as_bytes(),
        key.as_bytes()
    );
}

#[tokio::test]
async fn unknown_wrong_replay_and_superseded_authorities_fail_without_mutating_personal_data() {
    let app = TestApp::new().await;
    let login = app.register_user().await;
    let (key, descriptor, security) = app.descriptor(&login.access_token).await;
    app.enroll_auth_only(&login.access_token, &key, &descriptor)
        .await;
    let code = app
        .activate_recovery_code(&login.access_token, &key, &descriptor)
        .await;
    let secrets = RecoverySecrets::generate();
    let id = Uuid::new_v4();
    let mut input = RecoveryConsume {
        operation_id: id,
        locator: "unknown@example.test".into(),
        recovery_key: code.to_string(),
        next_recovery_key: secrets.next_recovery_key().into(),
        device: TestApp::device(),
    };
    let (unknown, unknown_body) = app
        .recovery_request(Method::POST, "/v1/auth/recover", id, &secrets, &input)
        .await;
    input.locator = "person@example.test".into();
    input.recovery_key = RecoverySecrets::generate().next_recovery_key().into();
    let (wrong, wrong_body) = app
        .recovery_request(Method::POST, "/v1/auth/recover", id, &secrets, &input)
        .await;
    assert_eq!(unknown, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong, unknown);
    assert_eq!(wrong_body, unknown_body);
    let current = zann_db::repo::UserRepo::new(&app.pool)
        .get_by_id(security.user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.auth_epoch, security.auth_epoch);
    input.recovery_key = code.to_string();
    let _: RecoveryConsumeReceipt = app
        .recovery(Method::POST, "/v1/auth/recover", id, &secrets, &input)
        .await;
    let root = format!("/v1/auth/recover/{id}");
    let bad_resume = RecoverySecrets::generate();
    assert_eq!(
        app.recovery_request(Method::GET, &root, id, &bad_resume, &())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    input.device.name = "changed replay body".into();
    assert_eq!(
        app.recovery_request(Method::POST, "/v1/auth/recover", id, &secrets, &input)
            .await
            .0,
        StatusCode::CONFLICT
    );
    let next = RecoverySecrets::generate();
    let next_id = Uuid::new_v4();
    let successor = RecoveryConsume {
        operation_id: next_id,
        locator: "person@example.test".into(),
        recovery_key: secrets.next_recovery_key().into(),
        next_recovery_key: next.next_recovery_key().into(),
        device: TestApp::device(),
    };
    let _: RecoveryConsumeReceipt = app
        .recovery(Method::POST, "/v1/auth/recover", next_id, &next, &successor)
        .await;
    let old: RecoveryView = app.recovery(Method::GET, &root, id, &secrets, &()).await;
    assert_eq!(old.status.state, RecoveryState::Superseded);
    assert_eq!(
        app.recovery_request(Method::GET, &format!("{root}/data"), id, &secrets, &())
            .await
            .0,
        StatusCode::GONE
    );
    let descriptor_after = zann_db::repo::AccountAccessRepo::new(&app.pool)
        .account(security.user_id)
        .await
        .unwrap()
        .unwrap()
        .descriptor;
    assert_eq!(
        serde_json::from_slice::<AccountDescriptor>(&descriptor_after.unwrap()).unwrap(),
        descriptor
    );
}

#[tokio::test]
async fn expired_recovery_cannot_fetch_keys_or_create_factors_but_keeps_successor_usable() {
    let app = TestApp::new().await;
    let login = app.register_user().await;
    let (key, descriptor, security) = app.descriptor(&login.access_token).await;
    app.enroll_auth_only(&login.access_token, &key, &descriptor)
        .await;
    let code = app
        .activate_recovery_code(&login.access_token, &key, &descriptor)
        .await;
    let secrets = RecoverySecrets::generate();
    let id = Uuid::new_v4();
    let input = RecoveryConsume {
        operation_id: id,
        locator: "person@example.test".into(),
        recovery_key: code.to_string(),
        next_recovery_key: secrets.next_recovery_key().into(),
        device: TestApp::device(),
    };
    let _: RecoveryConsumeReceipt = app
        .recovery(Method::POST, "/v1/auth/recover", id, &secrets, &input)
        .await;
    sqlx_core::query::query::<sqlx_postgres::Postgres>("UPDATE account_recovery_operations SET created_at=CURRENT_TIMESTAMP-INTERVAL '24 hours 1 second',expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE id=$1").bind(id).execute(&app.pool).await.unwrap();
    let root = format!("/v1/auth/recover/{id}");
    assert_eq!(
        app.recovery_request(Method::GET, &format!("{root}/data"), id, &secrets, &())
            .await
            .0,
        StatusCode::GONE
    );
    assert_eq!(
        app.recovery_request(
            Method::POST,
            &format!("{root}/credential/options"),
            id,
            &secrets,
            &RecoveryCredentialOptions {
                mutation_id: Uuid::new_v4(),
                expected_revision: 1,
                action: RecoveryOptionsPhase::Register {
                    name: "blocked".into(),
                    mode: PasskeyMode::AuthOnly
                }
            }
        )
        .await
        .0,
        StatusCode::GONE
    );
    let ended: RecoveryView = app.recovery(Method::GET, &root, id, &secrets, &()).await;
    assert_eq!(ended.status.state, RecoveryState::Expired);
    let user = zann_db::repo::UserRepo::new(&app.pool)
        .get_by_id(security.user_id)
        .await
        .unwrap()
        .unwrap();
    let candidate = Uuid::new_v4();
    let code = zann_crypto::recovery::generate_server_recovery_key();
    let hash = zann_crypto::recovery::server_recovery_verifier(
        &code,
        &user.kdf_salt,
        &app.state.password_pepper,
        &zann_server::domains::auth::core::passwords::kdf_params_from_user(&user),
    )
    .unwrap();
    let mut tx = app.pool.begin().await.unwrap();
    zann_db::repo::AccountAccessRepo::reset_recovery_in(
        &mut tx,
        user.id,
        user.row_version,
        candidate,
        &hash,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let account = zann_db::repo::AccountAccessRepo::new(&app.pool)
        .account(user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(account.active_recovery_id.is_none());
    assert_eq!(account.recovery_candidate_id, Some(candidate));
    assert!(account.auth_epoch > user.auth_epoch);
    assert_eq!(
        serde_json::from_slice::<AccountDescriptor>(&account.descriptor.unwrap()).unwrap(),
        descriptor
    );
    assert!(zann_db::repo::AccountAccessRepo::new(&app.pool)
        .credentials(user.id)
        .await
        .unwrap()
        .is_empty());
}
