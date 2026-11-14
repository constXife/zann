mod support;
use support::*;
use zann_client::browser_ipc::{ErrorCode, Reply, Request};
use zann_client::native_messaging::read_frame;

#[test]
fn unpaired_query_and_fill_return_no_metadata_or_secrets() {
    let fixture = Fixture::new();
    let id = fixture.login("Visible only after pairing", "https://example.com");
    let daemon = fixture.daemon();
    let mut client = Client::connect(&fixture, &daemon, 1);
    for request in [
        query("https://example.com"),
        Request::Fill {
            context: context("https://example.com"),
            item_id: id,
            gesture: true,
            include_totp: true,
        },
    ] {
        let reply = client.send(request);
        assert!(matches!(
            reply,
            Reply::Error {
                code: ErrorCode::Unpaired
            }
        ));
        let json = serde_json::to_string(&reply).unwrap();
        assert!(
            !json.contains("Visible only") && !json.contains("alice") && !json.contains("sentinel")
        );
    }
    assert!(daemon
        .control()
        .settings()
        .unwrap()
        .active_code_id
        .is_none());
}

#[test]
fn pairing_scopes_query_fill_gesture_totp_lock_and_revocation() {
    let fixture = Fixture::new();
    let id = fixture.login("Example", "https://example.com");
    fixture.login("Other", "https://other.com");
    let daemon = fixture.daemon();
    let mut client = Client::connect(&fixture, &daemon, 2);
    client.pair(&daemon);
    match &client.send(query("https://example.com")) {
        Reply::Matches { page } => {
            assert_eq!(page.items.len(), 1);
            assert_eq!(page.items[0].item_id, id);
            assert_eq!(page.items[0].username.as_deref(), Some("alice"));
            assert!(!serde_json::to_string(page).unwrap().contains("sentinel"));
        }
        _ => panic!("metadata query failed"),
    }
    assert!(matches!(
        client.send(Request::Fill {
            context: context("https://example.com"),
            item_id: id.clone(),
            gesture: false,
            include_totp: false
        }),
        Reply::Error {
            code: ErrorCode::Refused
        }
    ));
    match &client.send(Request::Fill {
        context: context("https://example.com"),
        item_id: id,
        gesture: true,
        include_totp: true,
    }) {
        Reply::Filled { value, totp } => {
            assert_eq!(value, "password-sentinel");
            assert_eq!(totp.as_ref().unwrap().len(), 6);
        }
        _ => panic!("fill failed"),
    }
    fixture.vault.lock().unwrap();
    assert!(matches!(
        client.send(query("https://example.com")),
        Reply::Error {
            code: ErrorCode::Locked
        }
    ));
    daemon
        .control()
        .revoke(&hex::encode(client.key.public_key()))
        .unwrap();
    assert!(matches!(
        client.send(query("https://example.com")),
        Reply::Error {
            code: ErrorCode::Unpaired
        }
    ));
    assert!(daemon.control().settings().unwrap().paired.is_empty());
}

#[test]
fn origin_mismatch_and_cross_origin_frames_never_release_values() {
    let fixture = Fixture::new();
    let id = fixture.login("Example", "https://example.com");
    let daemon = fixture.daemon();
    for (seed, context) in [
        (3, context("https://example.com.evil.org")),
        (
            4,
            zann_client::app::local::BrowserContext {
                top_level_url: "https://example.com".into(),
                frame_url: "https://sub.example.com".into(),
            },
        ),
    ] {
        let mut client = Client::connect(&fixture, &daemon, seed);
        client.pair(&daemon);
        assert!(matches!(
            client.send(Request::Fill {
                context,
                item_id: id.clone(),
                gesture: true,
                include_totp: true
            }),
            Reply::Error {
                code: ErrorCode::Refused
            }
        ));
    }
}

#[test]
fn signed_request_replay_is_rejected_in_same_and_different_connections() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let mut client = Client::connect(&fixture, &daemon, 5);
    let signed = client.envelope(&Request::PairStatus {});
    let bytes = serde_json::to_vec(&signed).unwrap();
    client.write_signed_bytes(&bytes);
    assert!(matches!(
        client.reply(),
        Reply::Error {
            code: ErrorCode::Unpaired
        }
    ));
    client.write_signed_bytes(&bytes);
    assert!(read_frame(&mut client.socket).unwrap().is_none());
    let mut another = Client::connect(&fixture, &daemon, 5);
    another.write_signed_bytes(&bytes);
    assert!(read_frame(&mut another.socket).unwrap().is_none());
}

#[test]
fn pairing_and_server_identity_survive_restart_and_revoke_is_durable() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let server = daemon.server_key();
    let mut client = Client::connect(&fixture, &daemon, 6);
    client.pair(&daemon);
    let key = hex::encode(client.key.public_key());
    let old_control = daemon.control();
    daemon.shutdown().unwrap();
    assert!(old_control.settings().is_err());
    let daemon = fixture.daemon();
    assert_eq!(daemon.server_key(), server);
    let mut client = Client::connect(&fixture, &daemon, 6);
    assert!(matches!(
        client.send(query("https://example.com")),
        Reply::Matches { .. }
    ));
    daemon.control().revoke(&key).unwrap();
    daemon.control().revoke(&key).unwrap();
    daemon.shutdown().unwrap();
    let daemon = fixture.daemon();
    let mut client = Client::connect(&fixture, &daemon, 6);
    assert!(matches!(
        client.send(query("https://example.com")),
        Reply::Error {
            code: ErrorCode::Unpaired
        }
    ));
}
