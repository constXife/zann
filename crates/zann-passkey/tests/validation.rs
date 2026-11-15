mod support;
use zann_core::{FieldKind, FieldValue};
use zann_passkey::*;

#[test]
fn malformed_and_oversized_payloads_and_requests_are_rejected_without_values() {
    let site = SiteUrl::parse("https://example.com").unwrap();
    let rp = RpId::parse("example.com").unwrap();
    let registration = make_credential(support::registration(&site, &rp), &[]).unwrap();
    let original = registration.credential.to_payload().unwrap();
    for (name, value) in [
        ("alg", "-8"),
        ("private_key", "sentinel-private-value"),
        ("rp_id", "com"),
        ("credential_id", ""),
        ("user_handle", ""),
        ("created_at", "sentinel-invalid-time"),
        ("discoverable", "false"),
    ] {
        let mut payload = original.clone();
        payload.fields.get_mut(name).unwrap().value = value.into();
        let error = Credential::from_payload(&payload)
            .err()
            .expect("invalid payload");
        assert!(!format!("{error:?} {error}").contains("sentinel"));
    }
    for name in ["private_key", "credential_id", "user_handle", "user_name"] {
        let mut payload = original.clone();
        payload.fields.get_mut(name).unwrap().value = "A".repeat(100_000);
        assert!(Credential::from_payload(&payload).is_err());
    }
    let mut payload = original.clone();
    payload.fields.get_mut("private_key").unwrap().kind = FieldKind::Text;
    assert!(Credential::from_payload(&payload).is_err());
    payload = original.clone();
    payload.fields.insert(
        "last_used_at".into(),
        FieldValue {
            kind: FieldKind::Text,
            value: "1".into(),
            meta: None,
        },
    );
    assert!(Credential::from_payload(&payload).is_err());

    let mut make = support::registration(&site, &rp);
    make.algorithms = &[-8];
    assert!(matches!(
        make_credential(make, &[]),
        Err(PasskeyError::Algorithm)
    ));
    let mut make = support::registration(&site, &rp);
    make.user.id = vec![0; MAX_USER_HANDLE_BYTES + 1];
    assert!(matches!(
        make_credential(make, &[]),
        Err(PasskeyError::Input)
    ));
    let mut make = support::registration(&site, &rp);
    make.user.id.clear();
    assert!(matches!(
        make_credential(make, &[]),
        Err(PasskeyError::Input)
    ));
    let too_many = vec![&b"id"[..]; MAX_CREDENTIAL_LIST + 1];
    let mut get = support::assertion(&site, &rp);
    get.allow_credentials = &too_many;
    assert!(matches!(
        get_assertion(&get, &registration.credential),
        Err(PasskeyError::Input)
    ));
    let oversized = vec![0; MAX_CREDENTIAL_ID_BYTES + 1];
    let ids = [oversized.as_slice()];
    get.allow_credentials = &ids;
    assert!(matches!(
        get_assertion(&get, &registration.credential),
        Err(PasskeyError::Input)
    ));
}

#[test]
fn maximum_user_handle_is_lossless_and_diagnostics_are_redacted() {
    let site = SiteUrl::parse("https://example.com").unwrap();
    let rp = RpId::parse("example.com").unwrap();
    let mut make = support::registration(&site, &rp);
    make.user.id = (0..64).collect();
    let credential = make_credential(make, &[]).unwrap().credential;
    let payload = credential.to_payload().unwrap();
    let restored = Credential::from_payload(&payload).unwrap();
    assert_eq!(credential.user_handle(), restored.user_handle());
    assert_eq!(credential.public_key(), restored.public_key());
    assert_eq!(payload, restored.to_payload().unwrap());
    let rendered = format!("{payload:?} {:?}", payload.fields);
    for name in ["private_key", "credential_id", "user_handle"] {
        assert!(!rendered.contains(&payload.fields[name].value));
    }
}
