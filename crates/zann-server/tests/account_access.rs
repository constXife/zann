#![cfg(feature = "postgres-tests")]
mod account_access_support;
mod support;
use account_access_support::{token::Token, TestApp, ORIGIN};
use axum::http::{Method, StatusCode};
use uuid::Uuid;
use zann_core::api::account_access::*;
use zann_crypto::account_access::{AccountGrant, AccountPrf};

#[tokio::test]
async fn tested_full_grant_login_replay_and_personal_server_boundary() {
    let app = TestApp::new().await;
    let initial = app.register_user().await;
    let (key, descriptor, security) = app.descriptor(&initial.access_token).await;
    let enrollment = EnrollmentRequest {
        operation_id: Uuid::new_v4(),
        expected_revision: security.security_revision,
        name: "test security key".into(),
        mode: PasskeyMode::VaultUnlock,
    };
    let options: CeremonyOptions = app
        .ok(
            "/v1/users/me/passkeys/options",
            Some(&initial.access_token),
            &enrollment,
        )
        .await;
    let (token, response) = Token::register(&options, ORIGIN, true);
    let register = CeremonyFinish {
        operation_id: enrollment.operation_id,
        response,
    };
    let test_options: CeremonyOptions = app
        .ok(
            "/v1/users/me/passkeys/register",
            Some(&initial.access_token),
            &register,
        )
        .await;
    assert!(test_options.credential_ids.is_empty());
    let repeated: CeremonyOptions = app
        .ok(
            "/v1/users/me/passkeys/register",
            Some(&initial.access_token),
            &register,
        )
        .await;
    assert_eq!(test_options.challenge, repeated.challenge);
    let test = CeremonyFinish {
        operation_id: enrollment.operation_id,
        response: token.assert(&test_options, ORIGIN, true, false),
    };
    let receipt: CandidateReceipt = app
        .ok(
            "/v1/users/me/passkeys/test",
            Some(&initial.access_token),
            &test,
        )
        .await;
    let prf = AccountPrf::from_bytes([73; 32]);
    let grant = AccountGrant::create(
        &descriptor,
        options.rp_id,
        receipt.credential_id.clone(),
        Uuid::new_v4(),
        &key,
        &prf,
    )
    .expect("grant");
    let proof = app
        .proof(
            &initial.access_token,
            &key,
            &descriptor,
            security.security_revision,
            MutationPurpose::GrantAdd,
            grant.body_digest().expect("digest"),
        )
        .await;
    let _: CandidateReceipt = app
        .ok(
            "/v1/users/me/passkeys/grant",
            Some(&initial.access_token),
            &StageGrant {
                operation_id: enrollment.operation_id,
                grant: grant.clone(),
                proof,
            },
        )
        .await;
    let proof = app
        .proof(
            &initial.access_token,
            &key,
            &descriptor,
            security.security_revision,
            MutationPurpose::CredentialAdd,
            receipt.activation_digest().expect("digest"),
        )
        .await;
    let _: SecurityReceipt = app
        .ok(
            "/v1/users/me/passkeys/activate",
            Some(&initial.access_token),
            &ActivateCredential {
                operation_id: enrollment.operation_id,
                expected_revision: security.security_revision,
                proof: ManagementProof::Custody { proof },
            },
        )
        .await;
    assert_eq!(
        app.security(&initial.access_token).await.credentials.len(),
        1
    );
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
    assert!(login_options.credential_ids.is_empty());
    let login = CeremonyFinish {
        operation_id: login_options.operation_id,
        response: token.assert(&login_options, ORIGIN, true, false),
    };
    let logged: PasskeyLogin = app.ok("/v1/auth/passkeys/login/finish", None, &login).await;
    assert_eq!(logged.user_id, security.user_id);
    let AccountKeyAccess::Ready {
        grant: received,
        descriptor: received_descriptor,
    } = logged.key_access
    else {
        panic!("missing full grant")
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
    let (status, _) = app
        .request(Method::POST, "/v1/auth/passkeys/login/finish", None, &login)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let sessions = zann_db::repo::SessionRepo::new(&app.pool)
        .list_by_user(security.user_id)
        .await
        .expect("sessions");
    assert_eq!(sessions.len(), 2);
    assert_eq!(
        sessions
            .iter()
            .filter(|s| s.passkey_credential_id.is_some())
            .count(),
        1
    );
}

#[tokio::test]
async fn missing_uv_and_wrong_origin_never_stage_a_credential() {
    let app = TestApp::new().await;
    let initial = app.register_user().await;
    let (_, _, security) = app.descriptor(&initial.access_token).await;
    for (uv, origin) in [(false, ORIGIN), (true, "https://attacker.example")] {
        let enrollment = EnrollmentRequest {
            operation_id: Uuid::new_v4(),
            expected_revision: security.security_revision,
            name: "rejected".into(),
            mode: PasskeyMode::AuthOnly,
        };
        let options: CeremonyOptions = app
            .ok(
                "/v1/users/me/passkeys/options",
                Some(&initial.access_token),
                &enrollment,
            )
            .await;
        let (_, response) = Token::register(&options, origin, uv);
        let (status, _) = app
            .request(
                Method::POST,
                "/v1/users/me/passkeys/register",
                Some(&initial.access_token),
                &CeremonyFinish {
                    operation_id: enrollment.operation_id,
                    response,
                },
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    assert!(app
        .security(&initial.access_token)
        .await
        .credentials
        .is_empty());
    assert_eq!(
        zann_db::repo::DeviceRepo::new(&app.pool)
            .list_by_user(security.user_id, 10, 0, "asc")
            .await
            .expect("devices")
            .len(),
        1
    );
}

#[tokio::test]
async fn revoke_is_idempotent_and_invalidates_only_selected_factor_sessions() {
    let app = TestApp::new().await;
    let initial = app.register_user().await;
    let (key, descriptor, _) = app.descriptor(&initial.access_token).await;
    let (lost, lost_summary) = app
        .enroll_auth_only(&initial.access_token, &key, &descriptor)
        .await;
    let (spare, _) = app
        .enroll_auth_only(&initial.access_token, &key, &descriptor)
        .await;
    let lost_session = app.login_with(&lost).await;
    let spare_session = app.login_with(&spare).await;
    let snapshot = app.security(&initial.access_token).await;
    let mut revoke = RevokeCredential {
        mutation_id: Uuid::new_v4(),
        expected_revision: snapshot.security_revision,
        credential_id: lost_summary.credential_id,
        revoke_sessions: true,
        proof: ManagementProof::InitialPassword {
            server_password: String::new(),
        },
    };
    let proof = app
        .proof(
            &initial.access_token,
            &key,
            &descriptor,
            snapshot.security_revision,
            MutationPurpose::CredentialRevoke,
            revoke.digest().expect("digest"),
        )
        .await;
    revoke.proof = ManagementProof::Custody { proof };
    let first: SecurityReceipt = app
        .ok(
            "/v1/users/me/passkeys/revoke",
            Some(&initial.access_token),
            &revoke,
        )
        .await;
    let replay: SecurityReceipt = app
        .ok(
            "/v1/users/me/passkeys/revoke",
            Some(&initial.access_token),
            &revoke,
        )
        .await;
    assert_eq!(first.security_revision, replay.security_revision);
    let (status, _) = app
        .request(
            Method::GET,
            "/v1/users/me/security",
            Some(&lost_session.tokens.access_token),
            &(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        app.security(&spare_session.tokens.access_token)
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
    revoke.revoke_sessions = false;
    let (status, _) = app
        .request(
            Method::POST,
            "/v1/users/me/passkeys/revoke",
            Some(&initial.access_token),
            &revoke,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn staged_recovery_code_is_replayable_and_disables_only_server_password() {
    let app = TestApp::new().await;
    let initial = app.register_user().await;
    let (key, descriptor, _) = app.descriptor(&initial.access_token).await;
    let (hardware, _) = app
        .enroll_auth_only(&initial.access_token, &key, &descriptor)
        .await;
    let snapshot = app.security(&initial.access_token).await;
    let code = zann_crypto::recovery::generate_server_recovery_key();
    let mut activation = ActivateRecoveryCode {
        candidate_id: Uuid::new_v4(),
        expected_revision: snapshot.security_revision,
        recovery_key: code.to_string(),
        disable_password: true,
        proof: ManagementProof::InitialPassword {
            server_password: String::new(),
        },
    };
    let proof = app
        .proof(
            &initial.access_token,
            &key,
            &descriptor,
            snapshot.security_revision,
            MutationPurpose::CodeRotate,
            activation.digest().expect("digest"),
        )
        .await;
    activation.proof = ManagementProof::Custody { proof };
    let first: SecurityReceipt = app
        .ok(
            "/v1/users/me/security/recovery-code/activate",
            Some(&initial.access_token),
            &activation,
        )
        .await;
    let replay: SecurityReceipt = app
        .ok(
            "/v1/users/me/security/recovery-code/activate",
            Some(&initial.access_token),
            &activation,
        )
        .await;
    assert_eq!(first.security_revision, replay.security_revision);
    let current = app.security(&initial.access_token).await;
    assert!(!current.password_enabled);
    assert_eq!(current.descriptor, Some(descriptor));
    assert_eq!(current.recovery_candidate_id, Some(activation.candidate_id));
    let user = zann_db::repo::UserRepo::new(&app.pool)
        .get_by_id(snapshot.user_id)
        .await
        .expect("user")
        .expect("present");
    assert!(zann_crypto::passwords::verify_password(
        user.recovery_key_hash.as_deref().expect("verifier"),
        &code,
        &user.kdf_salt,
        &zann_server::domains::auth::core::passwords::kdf_params_from_user(&user),
        &app.state.password_pepper
    )
    .expect("verify"));
    assert!(matches!(
        app.login_with(&hardware).await.key_access,
        AccountKeyAccess::AuthOnly { .. }
    ));
    activation.disable_password = false;
    let (status, _) = app
        .request(
            Method::POST,
            "/v1/users/me/security/recovery-code/activate",
            Some(&initial.access_token),
            &activation,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn unrelated_epoch_bump_revokes_old_sessions_but_preserves_active_passkeys() {
    let app = TestApp::new().await;
    let initial = app.register_user().await;
    let (key, descriptor, security) = app.descriptor(&initial.access_token).await;
    let (hardware, _) = app
        .enroll_auth_only(&initial.access_token, &key, &descriptor)
        .await;
    sqlx_core::query::query::<sqlx_postgres::Postgres>(
        "UPDATE users SET auth_epoch=auth_epoch+1 WHERE id=$1",
    )
    .bind(security.user_id)
    .execute(&app.pool)
    .await
    .expect("epoch");
    let (status, _) = app
        .request(
            Method::GET,
            "/v1/users/me/security",
            Some(&initial.access_token),
            &(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let logged = app.login_with(&hardware).await;
    assert_eq!(logged.auth_epoch, security.auth_epoch + 1);
    assert_eq!(
        app.security(&logged.tokens.access_token)
            .await
            .credentials
            .len(),
        1
    );
}

#[tokio::test]
async fn already_admitted_identity_cannot_write_after_epoch_invalidation() {
    let app = TestApp::new().await;
    let initial = app.register_user().await;
    let captured = zann_server::domains::auth::core::identity::identity_from_session_token(
        &app.state,
        &initial.access_token,
    )
    .await
    .expect("admitted bearer");
    assert!(captured.session_authority.is_some());
    let wire = serde_json::to_value(&captured).expect("wire identity");
    assert!(
        wire.get("session_authority").is_none(),
        "mutation authority is never accepted from wire JSON"
    );
    let mut tx = app.pool.begin().await.expect("transaction");
    zann_db::repo::SessionRepo::invalidate_user_in(&mut tx, captured.user_id, None)
        .await
        .expect("invalidate");
    tx.commit().await.expect("commit");
    let result = zann_server::domains::users::service::update_me(
        &app.state,
        &captured,
        zann_server::domains::users::service::UpdateMeCommand {
            full_name: Some("stale write".into()),
        },
    )
    .await;
    assert!(matches!(
        result,
        Err(zann_server::domains::errors::ServiceError::Unauthorized(
            "session_invalidated"
        ))
    ));
    let user = zann_db::repo::UserRepo::new(&app.pool)
        .get_by_id(captured.user_id)
        .await
        .expect("read")
        .expect("account");
    assert_ne!(user.full_name.as_deref(), Some("stale write"));
}
