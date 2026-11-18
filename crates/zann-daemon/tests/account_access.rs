mod support;
use support::*;
use zann_client::browser_ipc::*;
use zann_core::api::account_access::{CeremonyOptions, CeremonyPhase, CeremonyResponse};
fn prompt() -> AccountCeremonyPrompt {
    let server_id = "ceirceirceirceirceirceirceirceirceirceirceirceirceiq".to_owned();
    AccountCeremonyPrompt {
        server_address: "https://zann.example".into(),
        server_fingerprint: "pinned-native-fixture".into(),
        server_id: server_id.clone(),
        require_prf: true,
        options: CeremonyOptions {
            operation_id: "01234567-89ab-4cde-8012-3456789abcde".parse().unwrap(),
            phase: CeremonyPhase::Login,
            challenge: zann_crypto::account_access::encode(&[7; 32]),
            rp_id: "zann.example".into(),
            rp_name: "Zann".into(),
            user_id: None,
            user_name: None,
            credential_ids: vec![],
            prf_input: zann_crypto::account_access::encode(
                &zann_crypto::account_access::prf_input(&server_id, "zann.example").unwrap(),
            ),
        },
    }
}
#[test]
fn locked_account_bridge_binds_selected_pairing_channel_and_one_shot_result() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let mut selected = Client::connect(&fixture, &daemon, 51);
    selected.pair(&daemon);
    let mut other = Client::connect(&fixture, &daemon, 52);
    other.pair(&daemon);
    fixture.vault.lock().unwrap();
    let prompt = prompt();
    let id = prompt.options.operation_id.to_string();
    let wait = daemon
        .control()
        .begin_account_ceremony(&hex::encode(selected.key.public_key()), prompt)
        .unwrap();
    assert!(matches!(
        other.send(Request::AccountCeremonyStatus {}),
        Reply::AccountCeremonyPending { prompt: None }
    ));
    assert!(matches!(
        selected.send(Request::AccountCeremonyStatus {}),
        Reply::AccountCeremonyPending { prompt: Some(_) }
    ));
    assert!(matches!(
        selected.send(Request::AccountCeremonyTake {
            operation_id: id.clone()
        }),
        Reply::AccountCeremonyPending { prompt: Some(_) }
    ));
    let mut reconnected = Client::connect(&fixture, &daemon, 51);
    assert!(matches!(
        reconnected.send(Request::AccountCeremonyFinish {
            operation_id: id.clone(),
            completion: AccountCeremonyCompletion::Failed {
                reason: AccountCeremonyFailure::Cancelled
            }
        }),
        Reply::Error {
            code: ErrorCode::Refused
        }
    ));
    let completion = AccountCeremonyCompletion::Completed {
        result: AccountCeremonyResult {
            response: CeremonyResponse::Assertion {
                credential_id: "AQ".into(),
                client_data_json: "Ag".into(),
                authenticator_data: "Aw".into(),
                signature: "BA".into(),
                user_handle: None,
            },
            prf: Some(PrfOutput::new([73; 32])),
        },
    };
    assert!(matches!(
        selected.send(Request::AccountCeremonyFinish {
            operation_id: id.clone(),
            completion
        }),
        Reply::AccountCeremonyAccepted {}
    ));
    let AccountCeremonyCompletion::Completed { result } = wait.wait().unwrap() else {
        panic!("expected completed result");
    };
    assert!(result.prf.is_some());
    assert_eq!(result.response.credential_id(), "AQ");
    assert!(matches!(
        selected.send(Request::AccountCeremonyFinish {
            operation_id: id,
            completion: AccountCeremonyCompletion::Failed {
                reason: AccountCeremonyFailure::Cancelled
            }
        }),
        Reply::Error {
            code: ErrorCode::Refused
        }
    ));
}
#[test]
fn dropping_native_wait_or_revoking_pairing_cancels_the_pending_authority() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let mut client = Client::connect(&fixture, &daemon, 61);
    client.pair(&daemon);
    let public = hex::encode(client.key.public_key());
    let wait = daemon
        .control()
        .begin_account_ceremony(&public, prompt())
        .unwrap();
    drop(wait);
    assert!(matches!(
        client.send(Request::AccountCeremonyStatus {}),
        Reply::AccountCeremonyPending { prompt: None }
    ));
    let wait = daemon
        .control()
        .begin_account_ceremony(&public, prompt())
        .unwrap();
    daemon.control().revoke(&public).unwrap();
    assert!(wait.wait().is_err());
    assert!(matches!(
        client.send(Request::AccountCeremonyStatus {}),
        Reply::Error {
            code: ErrorCode::Unpaired
        }
    ));
}

#[test]
fn stale_wait_drop_cannot_cancel_a_new_ceremony_for_the_same_server_operation() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let mut client = Client::connect(&fixture, &daemon, 63);
    client.pair(&daemon);
    let public = hex::encode(client.key.public_key());
    let old = daemon
        .control()
        .begin_account_ceremony(&public, prompt())
        .unwrap();
    daemon.control().cancel_account_ceremony().unwrap();
    let current = daemon
        .control()
        .begin_account_ceremony(&public, prompt())
        .unwrap();
    drop(old);
    assert!(matches!(
        client.send(Request::AccountCeremonyStatus {}),
        Reply::AccountCeremonyPending { prompt: Some(_) }
    ));
    drop(current);
    assert!(matches!(
        client.send(Request::AccountCeremonyStatus {}),
        Reply::AccountCeremonyPending { prompt: None }
    ));
}
