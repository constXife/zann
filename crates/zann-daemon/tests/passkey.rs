mod support;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use support::*;
use zann_client::app::local::passkey_engine as pk;
use zann_client::browser_ipc::*;

fn create() -> PasskeyRequest {
    PasskeyRequest {
        context: context("https://example.com/login"),
        rp_id: "example.com".into(),
        challenge: B64.encode([7; 32]),
        require_verification: false,
        operation: PasskeyOperation::Create {
            rp_name: "Example".into(),
            user_id: B64.encode([1; 16]),
            user_name: "alice".into(),
            user_display_name: "Alice".into(),
            algorithms: vec![-7],
            exclude_credentials: vec![],
        },
    }
}
fn query(client: &mut Client, request: PasskeyRequest) -> (String, PasskeyMatches) {
    let reply = client.send(Request::PasskeyQuery { request });
    let Reply::PasskeyMatches { ticket, matches } = &reply else {
        panic!("passkey query expected")
    };
    (
        ticket.clone(),
        serde_json::from_value(serde_json::to_value(matches).unwrap()).unwrap(),
    )
}
fn register(client: &mut Client) -> String {
    let (ticket, _) = query(client, create());
    let reply = client.send(Request::MakeCredential {
        ticket,
        gesture: true,
    });
    let Reply::Credential { response } = &reply else {
        panic!("registration expected")
    };
    let auth = B64.decode(&response.authenticator_data).unwrap();
    assert_eq!(auth[32], 0x59);
    assert_eq!(&auth[33..37], &[0; 4]);
    let client_data: serde_json::Value =
        serde_json::from_slice(&B64.decode(&response.client_data_json).unwrap()).unwrap();
    assert_eq!(client_data["origin"], "https://example.com");
    assert_eq!(client_data["type"], "webauthn.create");
    assert!(response.signature.is_none());
    assert!(response.attestation_object.is_some());
    response.credential_id.clone()
}
fn assertion() -> PasskeyRequest {
    let mut request = create();
    request.operation = PasskeyOperation::Get {
        allow_credentials: vec![],
    };
    request
}
fn refused(fixture: &Fixture, daemon: &zann_daemon::Daemon, client: &mut Client, request: Request) {
    assert!(matches!(
        client.send(request),
        Reply::Error {
            code: ErrorCode::Refused
        }
    ));
    *client = Client::connect(fixture, daemon, client.key.seed()[0]);
}
#[test]
fn registration_discovery_allowlist_signature_and_immutable_synced_credential() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let mut client = Client::connect(&fixture, &daemon, 51);
    client.pair(&daemon);
    let id = register(&mut client);
    let (ticket, matches) = query(&mut client, assertion());
    assert_eq!(matches.items.len(), 1);
    assert_eq!(matches.items[0].user_name, "alice");
    let item = fixture
        .vault
        .item_get(matches.items[0].item_id.clone())
        .unwrap();
    let payload = zann_core::EncryptedPayload::from_bytes(item.payload_json.as_bytes()).unwrap();
    let credential = pk::Credential::from_payload(&payload).unwrap();
    let reply = client.send(Request::GetAssertion {
        ticket: ticket.clone(),
        item_id: item.id.clone(),
        gesture: true,
    });
    let Reply::Credential { response } = &reply else {
        panic!("assertion expected")
    };
    assert_eq!(response.credential_id, id);
    assert!(response.attestation_object.is_none());
    let mut signed = B64.decode(&response.authenticator_data).unwrap();
    assert_eq!(signed[32], 0x19);
    assert_eq!(&signed[33..37], &[0; 4]);
    signed.extend(zann_crypto::es256::sha256(
        &B64.decode(&response.client_data_json).unwrap(),
    ));
    zann_crypto::es256::verify(
        &credential.public_key(),
        &signed,
        &B64.decode(response.signature.as_ref().unwrap()).unwrap(),
    )
    .unwrap();
    let after = fixture.vault.item_get(item.id.clone()).unwrap();
    assert!(
        zann_core::EncryptedPayload::from_bytes(after.payload_json.as_bytes()).unwrap() == payload
    );
    refused(
        &fixture,
        &daemon,
        &mut client,
        Request::GetAssertion {
            ticket,
            item_id: item.id,
            gesture: true,
        },
    );
    let mut request = assertion();
    request.operation = PasskeyOperation::Get {
        allow_credentials: vec![id.clone()],
    };
    let (_, matches) = query(&mut client, request);
    assert_eq!(matches.items.len(), 1);
    let mut request = assertion();
    request.operation = PasskeyOperation::Get {
        allow_credentials: vec![B64.encode([88; 32])],
    };
    let (_, matches) = query(&mut client, request);
    assert!(matches.items.is_empty());
    let mut request = create();
    if let PasskeyOperation::Create {
        exclude_credentials,
        ..
    } = &mut request.operation
    {
        exclude_credentials.push(id);
    }
    refused(
        &fixture,
        &daemon,
        &mut client,
        Request::PasskeyQuery { request },
    );
}
#[test]
fn each_confirmation_is_consumed_and_bound_to_channel_selection_pairing_and_operation() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let mut client = Client::connect(&fixture, &daemon, 52);
    client.pair(&daemon);
    let (ticket, _) = query(&mut client, create());
    refused(
        &fixture,
        &daemon,
        &mut client,
        Request::MakeCredential {
            ticket: ticket.clone(),
            gesture: false,
        },
    );
    refused(
        &fixture,
        &daemon,
        &mut client,
        Request::MakeCredential {
            ticket,
            gesture: true,
        },
    );
    let (_, matches) = query(&mut client, assertion());
    assert!(matches.items.is_empty());
    let (ticket, _) = query(&mut client, create());
    let mut other = Client::connect(&fixture, &daemon, 52);
    refused(
        &fixture,
        &daemon,
        &mut other,
        Request::MakeCredential {
            ticket: ticket.clone(),
            gesture: true,
        },
    );
    refused(
        &fixture,
        &daemon,
        &mut client,
        Request::GetAssertion {
            ticket: ticket.clone(),
            item_id: "anything".into(),
            gesture: true,
        },
    );
    refused(
        &fixture,
        &daemon,
        &mut client,
        Request::MakeCredential {
            ticket,
            gesture: true,
        },
    );
    let (ticket, _) = query(&mut client, create());
    let vault = fixture.vault.current_vault_id().unwrap();
    fixture.vault.set_current_vault(vault).unwrap();
    refused(
        &fixture,
        &daemon,
        &mut client,
        Request::MakeCredential {
            ticket,
            gesture: true,
        },
    );
    let (ticket, _) = query(&mut client, create());
    fixture.vault.lock().unwrap();
    assert!(matches!(
        client.send(Request::MakeCredential {
            ticket,
            gesture: true
        }),
        Reply::Error {
            code: ErrorCode::Locked
        }
    ));
    assert!(matches!(
        client.send(Request::PasskeyQuery { request: create() }),
        Reply::Error {
            code: ErrorCode::Locked
        }
    ));
    fixture.vault.unlock("fixture-password".into()).unwrap();
    let (ticket, _) = query(&mut client, create());
    daemon
        .control()
        .revoke(&hex::encode(client.key.public_key()))
        .unwrap();
    assert!(matches!(
        client.send(Request::MakeCredential {
            ticket,
            gesture: true
        }),
        Reply::Error {
            code: ErrorCode::Unpaired
        }
    ));
}
#[test]
fn admission_rejects_insecure_cross_origin_lookalike_and_required_verification() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let mut client = Client::connect(&fixture, &daemon, 53);
    client.pair(&daemon);
    for (top, frame, rp) in [
        ("http://example.com", "http://example.com", "example.com"),
        (
            "https://example.com",
            "https://login.example.com",
            "example.com",
        ),
        ("https://example.com", "https://example.com", "com"),
        (
            "https://example.com.evil.com",
            "https://example.com.evil.com",
            "example.com",
        ),
        (
            "https://alice.github.io",
            "https://alice.github.io",
            "bob.github.io",
        ),
        (
            "https://xn--pple-43d.com",
            "https://xn--pple-43d.com",
            "apple.com",
        ),
    ] {
        let mut request = create();
        request.context = BrowserContext {
            top_level_url: top.into(),
            frame_url: frame.into(),
        };
        request.rp_id = rp.into();
        refused(
            &fixture,
            &daemon,
            &mut client,
            Request::PasskeyQuery { request },
        );
    }
    let mut request = create();
    request.require_verification = true;
    refused(
        &fixture,
        &daemon,
        &mut client,
        Request::PasskeyQuery { request },
    );
}
#[test]
fn candidate_overflow_is_refused_without_truncating_exclusions() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let mut client = Client::connect(&fixture, &daemon, 54);
    client.pair(&daemon);
    for _ in 0..33 {
        register(&mut client);
    }
    refused(
        &fixture,
        &daemon,
        &mut client,
        Request::PasskeyQuery {
            request: assertion(),
        },
    );
}

#[test]
fn rp_lookup_is_bounded_per_site_instead_of_per_vault() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    let mut client = Client::connect(&fixture, &daemon, 55);
    client.pair(&daemon);
    for n in 0..40 {
        let mut request = create();
        request.rp_id = format!("site{n}.example.com");
        request.context = context(&format!("https://{}", request.rp_id));
        let (ticket, _) = query(&mut client, request);
        assert!(matches!(
            client.send(Request::MakeCredential {
                ticket,
                gesture: true
            }),
            Reply::Credential { .. }
        ));
    }
    let (_, matches) = query(&mut client, assertion());
    assert!(matches.items.is_empty());
    register(&mut client);
    let (_, matches) = query(&mut client, assertion());
    assert_eq!(matches.items.len(), 1);
}
