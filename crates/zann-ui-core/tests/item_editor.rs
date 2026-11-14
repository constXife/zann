use zann_ui_core::item_editor::{field_schemas, DraftError, ItemDraft};
use zann_ui_core::project_item_fields;

#[test]
fn separate_name_and_folder_inputs_rename_move_and_reject_missing_names_atomically() {
    let mut draft = ItemDraft::create("login").unwrap();
    draft.set_location(" GitHub ", " Work/Accounts/ ").unwrap();
    assert_eq!(draft.name(), "GitHub");
    assert_eq!(draft.folder(), Some("Work/Accounts"));
    assert_eq!(draft.save().unwrap().path, "Work/Accounts/GitHub");
    for name in ["", "   ", "Other/Name"] {
        assert!(matches!(
            draft.set_location(name, "Elsewhere"),
            Err(DraftError::Name)
        ));
        assert_eq!(draft.path, "Work/Accounts/GitHub");
    }
    draft.set_location("GitHub Enterprise", "").unwrap();
    assert_eq!(draft.folder(), None);
    let saved = draft.save().unwrap();
    assert_eq!(saved.title, "GitHub Enterprise");
    assert_eq!(saved.path, saved.title);
    let edited = ItemDraft::edit(" Work/GitHub/ ".into(), &saved.payload_json).unwrap();
    assert_eq!(edited.name(), "GitHub");
    assert_eq!(edited.folder(), Some("Work"));
}

#[test]
fn edit_preserves_typed_metadata_extras_and_supported_payload_version() {
    let json = r#"{"v":1,"typeId":"custom","fields":{"z":{"kind":"text","value":"sentinel","meta":{"masked":true,"multiline":true,"readonly":true}},"username":{"kind":"text","value":"user"}},"extra":{"issuer":"source"}}"#;
    let mut draft = ItemDraft::edit("group/item".into(), json).unwrap();
    assert_eq!(draft.fields[0].key, "username");
    assert!(draft.fields[1].masked());
    draft.fields[1].value.value = "edited".into();
    let payload: serde_json::Value = serde_json::from_str(&draft.payload_json().unwrap()).unwrap();
    assert_eq!(payload["v"], 1);
    assert_eq!(payload["typeId"], "custom");
    assert_eq!(payload["extra"]["issuer"], "source");
    assert_eq!(payload["fields"]["z"]["meta"]["readonly"], true);
    assert!(!format!("{draft:?} {:?}", draft.fields).contains("sentinel"));
}

#[test]
fn future_payloads_cannot_become_editable_drafts() {
    let error = ItemDraft::edit(
        "item".into(),
        r#"{"fields":{"x":{"kind":"future-kind","value":"private-sentinel"}},"v":7}"#,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        DraftError::Payload(zann_core::secrets::PayloadError::UnsupportedPayloadVersion(
            7
        ))
    ));
    assert!(!format!("{error:?} {error}").contains("sentinel"));
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

#[test]
fn save_trims_the_path_and_titles_the_item_by_its_last_segment() {
    let mut draft = ItemDraft::create("login").unwrap();
    draft.path = "  work/aws/root/  ".into();
    let save = draft.save().unwrap();
    assert_eq!(save.path, "work/aws/root/");
    assert_eq!(save.title, "root");
    assert_eq!(save.type_id, "login");
    let saved: serde_json::Value = serde_json::from_str(&save.payload_json).unwrap();
    assert_eq!(saved["typeId"], "login");
    draft.path = "   ".into();
    assert!(matches!(draft.save(), Err(DraftError::Path)));
}
