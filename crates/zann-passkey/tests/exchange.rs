use std::io::Read;
#[allow(dead_code)]
mod support;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{TimeZone, Utc};
use zann_passkey::{exchange::*, *};
const CXF: &[u8] = include_bytes!("../../../tests/fixtures/passkey-exchange/cxf.json");
const BW: &[u8] = include_bytes!("../../../tests/fixtures/passkey-exchange/bitwarden.json");
const BW64: &[u8] = include_bytes!("../../../tests/fixtures/passkey-exchange/bitwarden-b64.json");
const KP: &[u8] = include_bytes!("../../../tests/fixtures/passkey-exchange/keepassxc.passkey");
const XML: &[u8] = include_bytes!("../../../tests/fixtures/passkey-exchange/keepassxc.xml");
fn corpus() -> [(ExchangeFormat, &'static [u8]); 5] {
    [
        (ExchangeFormat::Cxf, CXF),
        (ExchangeFormat::Bitwarden, BW),
        (ExchangeFormat::Bitwarden, BW64),
        (ExchangeFormat::KeepassXcPasskey, KP),
        (ExchangeFormat::KeepassXml, XML),
    ]
}
fn check(credential: &Credential) {
    let expected = hex::decode(
        include_str!("../../../tests/fixtures/passkey-exchange/es256-public.hex").trim(),
    )
    .unwrap();
    assert_eq!(credential.public_key().as_slice(), expected);
    assert_eq!(
        credential.credential_id(),
        hex::decode("00112233445566778899aabbccddeeff").unwrap()
    );
    assert_eq!(credential.user_handle(), b"synthetic-user-handle");
    let site = SiteUrl::parse("https://login.example.com").unwrap();
    let rp = RpId::parse("example.com").unwrap();
    let before = credential.to_payload().unwrap();
    let response = get_assertion(&support::assertion(&site, &rp), credential).unwrap();
    let mut signed = response.authenticator_data;
    assert_eq!(signed[32], 0x1d);
    assert_eq!(&signed[33..], &[0; 4]);
    signed.extend([42; 32]);
    zann_crypto::es256::verify(&expected, &signed, &response.signature).unwrap();
    assert_eq!(credential.to_payload().unwrap(), before);
}
#[test]
fn golden_managers_and_cxf_produce_valid_immutable_assertions_and_preserve_metadata() {
    for (format, bytes) in corpus() {
        let document = import(bytes, format).unwrap();
        assert_eq!(document.credential_count(), 1);
        let entry = &document.entries[0];
        check(&entry.credentials[0]);
        let payload = entry.payload(0).unwrap();
        assert_eq!(
            Credential::from_payload(&payload)
                .unwrap()
                .to_payload()
                .unwrap(),
            payload
        );
        let mut output = Vec::new();
        write_cxf(
            &mut output,
            &document,
            CxfExportContext {
                timestamp: Utc.timestamp_opt(1794700800, 0).unwrap(),
                account_id: b"synthetic-account",
                username: "test",
                email: "test@example.com",
            },
        )
        .unwrap();
        let reopened = import(output.as_slice(), ExchangeFormat::Cxf).unwrap();
        assert_eq!(reopened.entries[0].payload(0).unwrap(), payload);
        check(&reopened.entries[0].credentials[0]);
        if format == ExchangeFormat::KeepassXcPasskey {
            assert!(!payload.fields.contains_key("created_at"));
        } else {
            assert_eq!(
                entry.metadata.login.as_ref().unwrap().password.as_deref(),
                Some("synthetic-login-secret")
            );
        }
    }
}
#[test]
fn parser_rejects_truncation_overflow_duplicate_members_and_malformed_private_metadata() {
    for (format, bytes) in corpus() {
        for length in 0..bytes.len().saturating_sub(1) {
            assert!(
                import(&bytes[..length], format).is_err(),
                "truncation {format:?} {length}"
            );
        }
    }
    assert!(import(
        std::io::repeat(b' ').take((MAX_EXCHANGE_BYTES + 1) as u64),
        ExchangeFormat::Cxf
    )
    .is_err());
    assert!(import(
        br#"{"encrypted":false,"encrypted":false,"items":[]}"#.as_slice(),
        ExchangeFormat::Bitwarden
    )
    .is_err());
    let document = import(CXF, ExchangeFormat::Cxf).unwrap();
    let mut payload = document.entries[0].payload(0).unwrap();
    payload
        .fields
        .get_mut(EXCHANGE_METADATA_FIELD)
        .unwrap()
        .value = r#"{"v":"sentinel-private-value"}"#.into();
    let error = Credential::from_payload(&payload).err().unwrap();
    assert!(!format!("{error} {error:?}").contains("sentinel"));
}
#[test]
fn rejects_algorithms_bad_rp_identity_bounds_counter_and_off_curve_pkcs8() {
    for (field, value) in [
        ("keyAlgorithm", serde_json::json!("RSA")),
        ("rpId", serde_json::json!("com")),
        ("counter", serde_json::json!("1")),
        (
            "userHandle",
            serde_json::json!(URL_SAFE_NO_PAD.encode([1; 65])),
        ),
        ("credentialId", serde_json::json!("sentinel-invalid-id")),
    ] {
        let mut wire: serde_json::Value = serde_json::from_slice(BW).unwrap();
        wire["items"][0]["login"]["fido2Credentials"][0][field] = value;
        let error = import(
            serde_json::to_vec(&wire).unwrap().as_slice(),
            ExchangeFormat::Bitwarden,
        )
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains("sentinel"));
    }
    let mut wire: serde_json::Value = serde_json::from_slice(CXF).unwrap();
    let value = &mut wire["accounts"][0]["items"][0]["credentials"][0]["key"];
    let mut der = URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap();
    let len = der.len();
    der[len - 64..].fill(0);
    *value = serde_json::json!(URL_SAFE_NO_PAD.encode(der));
    assert!(import(
        serde_json::to_vec(&wire).unwrap().as_slice(),
        ExchangeFormat::Cxf
    )
    .is_err());
}
#[test]
fn explicit_cose_codec_checks_curve_scalar_public_consistency_and_canonical_shape() {
    let bytes = include_bytes!("../../../tests/fixtures/passkey-exchange/es256-private.cbor");
    let key = decode_cose_private_key(bytes).unwrap();
    assert_eq!(
        hex::encode(key.public_key()),
        include_str!("../../../tests/fixtures/passkey-exchange/es256-public.hex").trim()
    );
    for length in 0..bytes.len() {
        assert!(decode_cose_private_key(&bytes[..length]).is_err());
    }
    for index in [2, 4, 6, 12, 50, 100] {
        let mut bad = bytes.to_vec();
        bad[index] ^= 1;
        assert!(decode_cose_private_key(&bad).is_err());
    }
    let mut bad = bytes.to_vec();
    bad.push(0);
    assert!(decode_cose_private_key(&bad).is_err());
}
#[test]
fn plaintext_xml_refuses_entities_encryption_trailing_data_and_duplicate_attributes() {
    let xml = std::str::from_utf8(XML).unwrap();
    for bad in [
        xml.replace(
            "<Root>",
            "<!DOCTYPE Root [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><Root>",
        ),
        xml.replace("ProtectInMemory=\"True\"", "Protected=\"True\""),
        format!("{xml}sentinel"),
        xml.replace("<Key>Title</Key>", "<Key>KPEX_PASSKEY_USERNAME</Key>"),
    ] {
        assert!(import(bad.as_bytes(), ExchangeFormat::KeepassXml).is_err());
    }
}

#[test]
fn complete_error_source_chains_never_format_private_metadata_values() {
    let document = import(CXF, ExchangeFormat::Cxf).unwrap();
    let mut payload = document.entries[0].payload(0).unwrap();
    payload
        .fields
        .get_mut(EXCHANGE_METADATA_FIELD)
        .unwrap()
        .value = r#"{"v":"sentinel-private-key-and-user-handle"}"#.into();
    let error = Credential::from_payload(&payload).err().unwrap();
    let mut current: Option<&dyn std::error::Error> = Some(&error);
    while let Some(error) = current {
        assert!(!format!("{error} {error:?}").contains("sentinel"));
        current = error.source();
    }
}

#[test]
fn malformed_xml_tags_are_redacted_through_the_full_source_chain() {
    let error = import(
        b"<KeePassFile><Root></sentinel-private-key-and-credential>".as_slice(),
        ExchangeFormat::KeepassXml,
    )
    .err()
    .unwrap();
    let mut current: Option<&dyn std::error::Error> = Some(&error);
    while let Some(error) = current {
        assert!(!format!("{error:?} {error}").contains("sentinel"));
        current = error.source();
    }
}

#[test]
fn cxf_metadata_selects_the_pair_of_rp_and_id_and_preserves_mixed_unknown_dates() {
    let mut document = import(CXF, ExchangeFormat::Cxf).unwrap();
    let mut second = document.entries[0].payload(0).unwrap();
    second.fields.get_mut("rp_id").unwrap().value = "example.net".into();
    second.fields.get_mut("rp_name").unwrap().value = "Other RP".into();
    second.fields.remove("created_at");
    document.entries[0]
        .credentials
        .push(Credential::from_payload(&second).unwrap());
    let expected: Vec<_> = (0..2)
        .map(|i| document.entries[0].payload(i).unwrap())
        .collect();
    let mut output = Vec::new();
    write_cxf(
        &mut output,
        &document,
        CxfExportContext {
            timestamp: Utc.timestamp_opt(1794700800, 0).unwrap(),
            account_id: b"synthetic-account",
            username: "test",
            email: "test@example.com",
        },
    )
    .unwrap();
    let reopened = import(output.as_slice(), ExchangeFormat::Cxf).unwrap();
    assert_eq!(
        (0..2)
            .map(|i| reopened.entries[0].payload(i).unwrap())
            .collect::<Vec<_>>(),
        expected
    );
}
