mod support;
use support::*;
use zann_client::browser_ipc::{decode_array, ErrorCode, Reply, Request};
use zann_crypto::ipc_pairing::CodeConfirmation;

fn challenge(client: &mut Client, code: &str) -> CodeConfirmation {
    let (exchange, reply) = client.start_pairing(code);
    let Reply::PairChallenge {
        message,
        confirmation,
    } = &reply
    else {
        panic!("challenge expected");
    };
    let key = exchange
        .finish(&decode_array::<33>(message).unwrap())
        .unwrap();
    key.verify_server(&decode_array(confirmation).unwrap())
        .unwrap();
    key
}
fn finish(client: &mut Client, key: &CodeConfirmation) -> Reply {
    client.send(Request::PairFinish {
        confirmation: hex::encode(key.client_proof()),
    })
}
fn refused(reply: Reply) {
    assert!(matches!(
        reply,
        Reply::Error {
            code: ErrorCode::Refused
        }
    ));
}

#[test]
fn no_browser_can_open_a_window_and_wrong_code_grants_no_metadata() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let mut browser = Client::connect(&fixture, &daemon, 1);
    refused(browser.start_pairing("123456").1);
    let code = daemon.control().begin_pairing().unwrap();
    let wrong = if code.value.as_str() == "123456" {
        "654321"
    } else {
        "123456"
    };
    let (exchange, reply) = browser.start_pairing(wrong);
    let Reply::PairChallenge {
        message,
        confirmation,
    } = &reply
    else {
        panic!("challenge expected");
    };
    let wrong_key = exchange
        .finish(&decode_array::<33>(message).unwrap())
        .unwrap();
    assert!(wrong_key
        .verify_server(&decode_array(confirmation).unwrap())
        .is_err());
    refused(finish(&mut browser, &wrong_key));
    assert!(matches!(
        browser.send(query("https://example.com")),
        Reply::Error {
            code: ErrorCode::Unpaired
        }
    ));
    assert!(daemon.control().settings().unwrap().paired.is_empty());
    assert!(!format!("{code:?}").contains(code.value.as_str()));
}

#[test]
fn five_guesses_are_shared_across_connections_and_malformed_starts_count() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let code = daemon.control().begin_pairing().unwrap();
    for n in 1..=5 {
        let mut browser = Client::connect(&fixture, &daemon, n);
        refused(browser.send(Request::PairStart {
            name: "Browser".into(),
            message: "malformed".into(),
        }));
    }
    let mut browser = Client::connect(&fixture, &daemon, 6);
    refused(browser.start_pairing(&code.value).1);
    assert!(daemon.control().settings().unwrap().paired.is_empty());
    let replacement = daemon.control().begin_pairing().unwrap();
    let key = challenge(&mut browser, &replacement.value);
    assert!(matches!(finish(&mut browser, &key), Reply::Paired {}));
}

#[test]
fn successful_code_is_consumed_even_for_another_in_flight_connection() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let code = daemon.control().begin_pairing().unwrap();
    let mut a = Client::connect(&fixture, &daemon, 1);
    let mut b = Client::connect(&fixture, &daemon, 2);
    let ka = challenge(&mut a, &code.value);
    let kb = challenge(&mut b, &code.value);
    assert!(matches!(finish(&mut a, &ka), Reply::Paired {}));
    refused(finish(&mut b, &kb));
    refused(b.start_pairing(&code.value).1);
    let settings = daemon.control().settings().unwrap();
    assert_eq!(settings.paired.len(), 1);
    assert!(settings.active_code_id.is_none());
}

#[test]
fn replacing_code_invalidates_in_flight_confirmations_and_proofs_are_single_use() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let code = daemon.control().begin_pairing().unwrap();
    let mut browser = Client::connect(&fixture, &daemon, 1);
    let old = challenge(&mut browser, &code.value);
    let new = daemon.control().begin_pairing().unwrap();
    refused(finish(&mut browser, &old));
    let key = challenge(&mut browser, &new.value);
    refused(browser.send(Request::PairFinish {
        confirmation: "malformed".into(),
    }));
    refused(finish(&mut browser, &key));
    assert!(daemon.control().settings().unwrap().paired.is_empty());
}

#[test]
fn a_proof_from_another_noise_connection_cannot_enroll_a_key() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let code = daemon.control().begin_pairing().unwrap();
    let mut a = Client::connect(&fixture, &daemon, 1);
    let mut b = Client::connect(&fixture, &daemon, 1);
    let ka = challenge(&mut a, &code.value);
    let _kb = challenge(&mut b, &code.value);
    refused(finish(&mut b, &ka));
    assert!(daemon.control().settings().unwrap().paired.is_empty());
}

#[test]
fn restart_keeps_trust_but_discards_open_codes_and_old_code_cannot_undo_revocation() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let mut browser = Client::connect(&fixture, &daemon, 1);
    browser.pair(&daemon);
    let unused = daemon.control().begin_pairing().unwrap();
    drop(browser);
    daemon.shutdown().unwrap();
    let daemon = fixture.daemon();
    let mut browser = Client::connect(&fixture, &daemon, 1);
    assert!(matches!(
        browser.send(Request::PairStatus {}),
        Reply::Paired {}
    ));
    assert!(daemon
        .control()
        .settings()
        .unwrap()
        .active_code_id
        .is_none());
    daemon
        .control()
        .revoke(&hex::encode(browser.key.public_key()))
        .unwrap();
    assert!(matches!(
        browser.send(Request::PairStatus {}),
        Reply::Error {
            code: ErrorCode::Unpaired
        }
    ));
    refused(browser.start_pairing(&unused.value).1);
}

#[test]
fn revoke_also_cancels_in_flight_enrollment_of_the_revoked_key() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let mut browser = Client::connect(&fixture, &daemon, 1);
    browser.pair(&daemon);
    let code = daemon.control().begin_pairing().unwrap();
    let key = challenge(&mut browser, &code.value);
    daemon
        .control()
        .revoke(&hex::encode(browser.key.public_key()))
        .unwrap();
    refused(finish(&mut browser, &key));
    assert!(daemon.control().settings().unwrap().paired.is_empty());
}
