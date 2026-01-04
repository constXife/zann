use proptest::prelude::*;
use zann_core::{EncryptedPayload, FieldKind, FieldValue};

#[test]
fn payload_bytes_roundtrip() {
    let mut payload = EncryptedPayload::new("system/login");
    payload.fields.insert(
        "username".to_string(),
        FieldValue {
            kind: FieldKind::Text,
            value: "user".to_string(),
            meta: None,
        },
    );
    payload.fields.insert(
        "password".to_string(),
        FieldValue {
            kind: FieldKind::Password,
            value: "pass".to_string(),
            meta: None,
        },
    );

    let bytes = payload.to_bytes().expect("serialize");
    let decoded = EncryptedPayload::from_bytes(&bytes).expect("deserialize");

    assert_eq!(decoded.type_id, "system/login");
    assert_eq!(decoded.fields.len(), 2);
    assert!(decoded.fields.contains_key("username"));
    assert!(decoded.fields.contains_key("password"));
}

proptest! {
    #[test]
    fn payload_bytes_roundtrip_prop(values in proptest::collection::vec("[a-z0-9_]{1,16}", 1..8)) {
        let mut payload = EncryptedPayload::new("system/kv");
        for (idx, value) in values.iter().enumerate() {
            payload.fields.insert(
                format!("field_{idx}"),
                FieldValue {
                    kind: FieldKind::Text,
                    value: value.clone(),
                    meta: None,
                },
            );
        }
        let bytes = payload.to_bytes().expect("serialize");
        let decoded = EncryptedPayload::from_bytes(&bytes).expect("deserialize");
        prop_assert_eq!(decoded.type_id, "system/kv");
        prop_assert_eq!(decoded.fields.len(), payload.fields.len());
    }
}
