use uuid::Uuid;
use zann_crypto::{EncryptedPayload, PayloadError, SecretKey, VaultCryptoError};

#[test]
fn version_is_checked_before_future_fields_regardless_of_json_order() {
    for bytes in [
        br#"{"v":2,"typeId":"future","fields":{"x":{"kind":"new-secret-kind","value":{}}},"future":true}"#.as_slice(),
        br#"{"fields":{"x":{"kind":"new-secret-kind","value":{}}},"future":true,"v":2}"#.as_slice(),
        br#"{"v":0}"#.as_slice(),
    ] {
        assert!(matches!(EncryptedPayload::from_bytes(bytes), Err(PayloadError::UnsupportedPayloadVersion(_))));
    }
    for malformed in [
        br#"{"v":1,"v":2}"#.as_slice(),
        br#"{"fields":{}}"#.as_slice(),
        br#"{"v":"2"}"#.as_slice(),
    ] {
        assert!(matches!(
            EncryptedPayload::from_bytes(malformed),
            Err(PayloadError::InvalidJson(_))
        ));
    }
}

#[test]
fn unsupported_payload_cannot_be_serialized_or_admitted_by_the_codec() {
    let mut payload = EncryptedPayload::new("login");
    payload.v = 2;
    assert!(matches!(
        payload.to_bytes(),
        Err(PayloadError::UnsupportedPayloadVersion(2))
    ));
    assert!(serde_json::to_vec(&payload).is_err());
    assert!(matches!(
        EncryptedPayload::from_bytes(br#"{"v":2,"typeId":"login","fields":{}}"#),
        Err(PayloadError::UnsupportedPayloadVersion(2))
    ));
}

#[test]
fn encrypted_future_payload_preserves_a_typed_version_error() {
    let key = SecretKey::generate();
    let vault = Uuid::now_v7();
    let item = Uuid::now_v7();
    let ciphertext = zann_crypto::encrypt_payload_bytes(
        &key,
        vault,
        item,
        br#"{"fields":{"x":{"kind":"future"}},"v":2}"#,
    )
    .expect("opaque future fixture");
    assert_eq!(
        zann_crypto::decrypt_payload(&key, vault, item, &ciphertext).expect_err("future version"),
        VaultCryptoError::UnsupportedPayloadVersion(2)
    );
}
