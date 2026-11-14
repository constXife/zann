mod support;
use std::os::unix::net::UnixStream;
use support::*;
use zann_client::{
    browser_ipc::{BrowserClient, CapturedLogin, ErrorCode, Reply, Request},
    native_messaging::{read_frame, write_frame},
};

fn exchange(socket: &mut UnixStream, client: &mut BrowserClient, request: Request) -> Reply {
    write_frame(socket, &client.request(&request).unwrap()).unwrap();
    client.reply(&read_frame(socket).unwrap().unwrap()).unwrap()
}
#[test]
fn shared_browser_client_pairs_fills_and_saves_only_in_the_observed_selection() {
    let fixture = Fixture::new();
    let id = fixture.login("Example", "https://example.com");
    let daemon = fixture.daemon();
    let mut socket = UnixStream::connect(fixture.root.join("ipc/browser.sock")).unwrap();
    let mut client = BrowserClient::new(&hex::encode([42; 32]), &daemon.server_key()).unwrap();
    let hello = read_frame(&mut socket).unwrap().unwrap();
    write_frame(&mut socket, &client.connect(&hello).unwrap()).unwrap();
    client
        .finish(&read_frame(&mut socket).unwrap().unwrap())
        .unwrap();
    assert!(matches!(
        exchange(&mut socket, &mut client, query("https://example.com")),
        Reply::Error {
            code: ErrorCode::Unpaired
        }
    ));
    let code = daemon.control().begin_pairing().unwrap();
    let mut pair_socket = UnixStream::connect(fixture.root.join("ipc/browser.sock")).unwrap();
    let mut pairing = zann_client::browser_ipc::BrowserPairingClient::new(
        &hex::encode([42; 32]),
        code.value.to_string(),
        "Chromium".into(),
    )
    .unwrap();
    let hello = read_frame(&mut pair_socket).unwrap().unwrap();
    write_frame(&mut pair_socket, &pairing.connect(&hello).unwrap()).unwrap();
    pairing
        .finish(&read_frame(&mut pair_socket).unwrap().unwrap())
        .unwrap();
    write_frame(&mut pair_socket, &pairing.begin().unwrap()).unwrap();
    let challenge = read_frame(&mut pair_socket).unwrap().unwrap();
    write_frame(&mut pair_socket, &pairing.confirm(&challenge).unwrap()).unwrap();
    let pin = pairing
        .complete(&read_frame(&mut pair_socket).unwrap().unwrap())
        .unwrap();
    assert_eq!(pin, daemon.server_key());
    let reply = exchange(&mut socket, &mut client, query("https://example.com"));
    let Reply::Matches { page } = &reply else {
        panic!("metadata expected");
    };
    let scope = page.scope.clone();
    let reply = exchange(
        &mut socket,
        &mut client,
        Request::Fill {
            context: context("https://example.com"),
            item_id: id,
            gesture: true,
            include_totp: true,
        },
    );
    assert!(
        matches!(&reply, Reply::Filled { value, totp:Some(code) } if value=="password-sentinel" && code.len()==6)
    );
    let login = || CapturedLogin {
        title: "Saved from Chromium".into(),
        username: "bob".into(),
        password: "captured-sentinel".into(),
    };
    let saved = exchange(
        &mut socket,
        &mut client,
        Request::Save {
            context: context("https://example.com/login?token=private#ignored"),
            scope: scope.clone(),
            login: login(),
            gesture: true,
        },
    );
    let Reply::Saved { item_id } = &saved else {
        panic!("save expected");
    };
    let reply = exchange(
        &mut socket,
        &mut client,
        Request::Fill {
            context: context("https://example.com"),
            item_id: item_id.clone(),
            gesture: true,
            include_totp: false,
        },
    );
    assert!(matches!(&reply, Reply::Filled { value, .. } if value=="captured-sentinel"));
    let detail = fixture.vault.item_get(item_id.clone()).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&detail.payload_json).unwrap();
    assert_eq!(payload["fields"]["url"]["value"], "https://example.com/");
    fixture.vault.lock().unwrap();
    fixture.vault.unlock("fixture-password".into()).unwrap();
    assert!(matches!(
        exchange(
            &mut socket,
            &mut client,
            Request::Save {
                context: context("https://example.com"),
                scope,
                login: login(),
                gesture: true
            }
        ),
        Reply::Error {
            code: ErrorCode::Refused
        }
    ));
}
#[test]
fn invalid_server_pin_poisons_the_shared_client_before_application_data() {
    let fixture = Fixture::new();
    let _daemon = fixture.daemon();
    let mut socket = UnixStream::connect(fixture.root.join("ipc/browser.sock")).unwrap();
    let hello = read_frame(&mut socket).unwrap().unwrap();
    let mut client = BrowserClient::new(&hex::encode([43; 32]), &hex::encode([99; 32])).unwrap();
    assert!(client.connect(&hello).is_err());
    assert!(client.request(&query("https://example.com")).is_err());
}
