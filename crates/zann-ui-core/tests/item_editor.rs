use zann_ui_core::item_editor::{field_schemas, DraftError, ItemDraft};
use zann_ui_core::project_item_fields;

#[test]
fn edit_preserves_typed_metadata_extras_and_payload_version() {
    let json = r#"{"v":7,"typeId":"custom","fields":{"z":{"kind":"text","value":"sentinel","meta":{"masked":true,"multiline":true,"readonly":true}},"username":{"kind":"text","value":"user"}},"extra":{"issuer":"source"}}"#;
    let mut draft = ItemDraft::edit("group/item".into(), json).unwrap();
    assert_eq!(draft.fields[0].key, "username");
    assert!(draft.fields[1].masked());
    draft.fields[1].value.value = "edited".into();
    let payload: serde_json::Value = serde_json::from_str(&draft.payload_json().unwrap()).unwrap();
    assert_eq!(payload["v"], 7);
    assert_eq!(payload["typeId"], "custom");
    assert_eq!(payload["extra"]["issuer"], "source");
    assert_eq!(payload["fields"]["z"]["meta"]["readonly"], true);
    assert!(!format!("{draft:?} {:?}", draft.fields).contains("sentinel"));
}

#[test]
fn invalid_payloads_fail_without_reconstructing_missing_fields_or_echoing_values() {
    let error = ItemDraft::edit("item".into(), r#"{"v":1,"typeId":"login","fields":{"password":{"kind":"secret-sentinel","value":"private-sentinel"}}}"#).unwrap_err();
    assert!(matches!(error, DraftError::Payload(_)));
    assert!(!format!("{error:?} {error}").contains("sentinel"));
    assert!(matches!(
        ItemDraft::create("unregistered"),
        Err(DraftError::UnknownType)
    ));
}

#[test]
fn validation_rejects_duplicate_and_invalid_field_keys() {
    let mut draft = ItemDraft::create("login").unwrap();
    assert!(matches!(draft.payload_json(), Err(DraftError::Path)));
    draft.path = "work/login".into();
    draft.fields[1].key = draft.fields[0].key.clone();
    assert!(matches!(
        draft.payload_json(),
        Err(DraftError::DuplicateKey)
    ));
    draft.fields[1].key = "bad/key".into();
    assert!(matches!(draft.payload_json(), Err(DraftError::FieldKey)));
}

#[test]
fn type_changes_preserve_populated_drafts_and_templates_come_from_shared_schema() {
    for (kind, schema) in field_schemas() {
        let draft = ItemDraft::create(kind).unwrap();
        if !schema.main.is_empty() {
            assert_eq!(
                draft
                    .fields
                    .iter()
                    .map(|f| f.key.as_str())
                    .collect::<Vec<_>>(),
                schema
                    .main
                    .iter()
                    .map(|f| f.key.as_str())
                    .collect::<Vec<_>>()
            );
        }
    }
    let mut draft = ItemDraft::create("login").unwrap();
    draft.path = "item".into();
    draft.fields[0].value.value = "keep-value".into();
    assert!(!draft.set_type("note".into()).unwrap());
    assert_eq!(draft.fields[0].value.value, "keep-value");
    let json = draft.payload_json().unwrap();
    assert_eq!(project_item_fields(&json).unwrap()[0].key, "username");
}
