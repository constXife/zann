#![cfg(feature = "ipc-pairing")]
use zann_crypto::ipc_pairing::{generate_code, validate_code, CodeExchange};

#[test]
fn matching_codes_confirm_both_directions_without_reflection() {
    let code = generate_code();
    validate_code(&code).unwrap();
    let (client, a) = CodeExchange::client(&code, b"endpoint and channel transcript").unwrap();
    let (server, b) = CodeExchange::server(&code, b"endpoint and channel transcript").unwrap();
    let client = client.finish(&b).unwrap();
    let server = server.finish(&a).unwrap();
    client.verify_server(&server.server_proof()).unwrap();
    server.verify_client(&client.client_proof()).unwrap();
    assert!(server.verify_client(&server.server_proof()).is_err());
}

#[test]
fn wrong_code_or_changed_channel_or_identity_cannot_confirm() {
    for (code, binding) in [
        ("123457", &b"bound identities/channel"[..]),
        ("123456", &b"different endpoint/channel"[..]),
    ] {
        let (client, a) = CodeExchange::client("123456", b"bound identities/channel").unwrap();
        let (server, b) = CodeExchange::server(code, binding).unwrap();
        let client = client.finish(&b).unwrap();
        let server = server.finish(&a).unwrap();
        assert!(client.verify_server(&server.server_proof()).is_err());
        assert!(server.verify_client(&client.client_proof()).is_err());
    }
}

#[test]
fn malformed_code_message_and_reflected_spake_role_are_refused() {
    for code in ["", "12345", "1234567", "12a456", "１２３４５６"] {
        assert!(CodeExchange::client(code, b"binding").is_err());
    }
    let (client, message) = CodeExchange::client("000001", b"binding").unwrap();
    assert!(client.finish(&message).is_err());
    let (client, _) = CodeExchange::client("000001", b"binding").unwrap();
    assert!(client.finish(&[0; 34]).is_err());
}
