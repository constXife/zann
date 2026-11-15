mod support;
use ciborium::value::Value;
use zann_crypto::es256::{sha256, verify};
use zann_passkey::*;

#[test]
fn registration_and_two_offline_devices_preserve_synced_payload() {
    let site = SiteUrl::parse("https://login.example.com").unwrap();
    let rp = RpId::parse("example.com").unwrap();
    let registration =
        make_credential(support::registration(&site, &rp), &[]).expect("registration");
    let credential = registration.credential;
    let data = registration.response.authenticator_data;
    assert_eq!(&data[..32], &sha256(b"example.com"));
    // FIDO CTAP 2.1 §9 example RP hash (same RP in both ceremony examples).
    assert_eq!(
        hex::encode(&data[..32]),
        "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947"
    );
    assert_eq!(data[32], 0x5d); // UP UV BE BS AT
    assert_eq!(&data[33..37], &[0; 4]);
    assert_eq!(&data[37..53], &[0; 16]);
    assert_eq!(&data[53..55], &[0, 32]);
    assert_eq!(&data[55..87], credential.credential_id());
    let cose: Value = ciborium::from_reader(&data[87..]).expect("COSE");
    let map = cose.as_map().unwrap();
    assert_eq!(map.len(), 5);
    let value = |label: i32| &map.iter().find(|(k, _)| *k == label.into()).unwrap().1;
    assert_eq!(*value(1), 2.into());
    assert_eq!(*value(3), (-7).into());
    assert_eq!(*value(-1), 1.into());
    let mut sec1 = vec![4];
    sec1.extend(value(-2).as_bytes().unwrap());
    sec1.extend(value(-3).as_bytes().unwrap());
    assert_eq!(sec1, credential.public_key());
    let attestation: Value =
        ciborium::from_reader(registration.response.attestation_object.as_slice()).unwrap();
    let attestation = attestation.as_map().unwrap();
    assert_eq!(attestation.len(), 3);
    let att = |name: &str| {
        &attestation
            .iter()
            .find(|(k, _)| *k == Value::Text(name.into()))
            .unwrap()
            .1
    };
    assert_eq!(*att("fmt"), Value::Text("none".into()));
    assert_eq!(*att("attStmt"), Value::Map(vec![]));
    assert_eq!(att("authData").as_bytes().unwrap(), &data);

    let original = credential.to_payload().unwrap();
    let synced = original.to_bytes().unwrap();
    // Each device opens an independent synced copy, with no shared mutable state.
    let device_b =
        Credential::from_payload(&zann_core::EncryptedPayload::from_bytes(&synced).unwrap())
            .unwrap();
    for device in [&credential, &device_b, &credential, &device_b] {
        let response = get_assertion(&support::assertion(&site, &rp), device).unwrap();
        assert_eq!(response.authenticator_data.len(), 37);
        assert_eq!(response.authenticator_data[32], 0x1d); // UP UV BE BS
        assert_eq!(&response.authenticator_data[33..], &[0; 4]);
        let mut signed = response.authenticator_data;
        signed.extend([42; 32]);
        verify(&sec1, &signed, &response.signature)
            .expect("independently extracted registration public key");
        signed[37] ^= 1;
        assert!(verify(&sec1, &signed, &response.signature).is_err());
        assert_eq!(device.to_payload().unwrap(), original);
    }
    assert!(!original.fields.contains_key("last_used_at"));
}

#[test]
fn flags_only_report_actual_verification_and_silent_ceremonies_fail() {
    let site = SiteUrl::parse("https://example.com").unwrap();
    let rp = RpId::parse("example.com").unwrap();
    let mut request = support::registration(&site, &rp);
    request.context.verification = UserVerification::NotPerformed;
    assert!(matches!(
        make_credential(request, &[]),
        Err(PasskeyError::Verification)
    ));
    let mut request = support::registration(&site, &rp);
    request.require_verification = false;
    request.context.verification = UserVerification::NotPerformed;
    let result = make_credential(request, &[]).unwrap();
    assert_eq!(result.response.authenticator_data[32], 0x59);
    let mut request = support::assertion(&site, &rp);
    request.require_verification = false;
    request.context.verification = UserVerification::NotPerformed;
    assert_eq!(
        get_assertion(&request, &result.credential)
            .unwrap()
            .authenticator_data[32],
        0x19
    );
    request.context.presence = UserPresence::Absent;
    assert!(matches!(
        get_assertion(&request, &result.credential),
        Err(PasskeyError::Presence)
    ));
    let mut request = support::registration(&site, &rp);
    request.context.presence = UserPresence::Absent;
    assert!(matches!(
        make_credential(request, &[]),
        Err(PasskeyError::Presence)
    ));
}

#[test]
fn selection_exclusions_origin_and_vault_boundaries_fail_closed() {
    let site = SiteUrl::parse("https://example.com").unwrap();
    let rp = RpId::parse("example.com").unwrap();
    let result = make_credential(support::registration(&site, &rp), &[]).unwrap();
    let id = result.credential.credential_id().to_vec();
    let candidates = [result.credential];
    let mut get = support::assertion(&site, &rp);
    assert_eq!(select_credentials(&get, &candidates).unwrap(), [0]);
    get.allow_credentials = &[b"other"];
    assert!(select_credentials(&get, &candidates).unwrap().is_empty());
    assert!(matches!(
        get_assertion(&get, &candidates[0]),
        Err(PasskeyError::NoCredential)
    ));
    let ids = [id.as_slice()];
    get.allow_credentials = &ids;
    assert!(get_assertion(&get, &candidates[0]).is_ok());
    let mut make = support::registration(&site, &rp);
    make.exclude_credentials = &ids;
    assert!(matches!(
        make_credential(make, &candidates),
        Err(PasskeyError::Excluded)
    ));
    let evil = SiteUrl::parse("https://evil.test").unwrap();
    let mut get = support::assertion(&evil, &rp);
    assert!(matches!(
        get_assertion(&get, &candidates[0]),
        Err(PasskeyError::Origin(_))
    ));
    get.context.top_level = &site;
    assert!(get_assertion(&get, &candidates[0]).is_err());
    let other_rp = RpId::parse("other.test").unwrap();
    let other_site = SiteUrl::parse("https://other.test").unwrap();
    assert!(matches!(
        get_assertion(&support::assertion(&other_site, &other_rp), &candidates[0]),
        Err(PasskeyError::NoCredential)
    ));
    for (kind, encryption) in [
        (
            zann_core::VaultKind::Shared,
            zann_core::VaultEncryptionType::Server,
        ),
        (
            zann_core::VaultKind::Shared,
            zann_core::VaultEncryptionType::Client,
        ),
        (
            zann_core::VaultKind::Personal,
            zann_core::VaultEncryptionType::Server,
        ),
    ] {
        let mut make = support::registration(&site, &rp);
        make.vault_kind = kind;
        make.encryption_type = encryption;
        assert!(matches!(
            make_credential(make, &[]),
            Err(PasskeyError::Vault(_))
        ));
    }
}
