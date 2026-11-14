use zann_ui_core::item_editor::{DraftError, ItemDraft, MatchRules, MATCH_RULES_KEY};

#[test]
fn login_editor_preserves_rules_and_other_payload_data_across_reopen() {
    let json = r#"{"v":1,"typeId":"login","fields":{"url":{"kind":"url","value":"https://example.com"},"password":{"kind":"password","value":"private-sentinel"},"match_rules":{"kind":"text","value":"{\"mode\":\"host\"}","meta":{"readonly":false}}},"extra":{"issuer":"import"}}"#;
    let mut draft = ItemDraft::edit("work/site".into(), json).unwrap();
    assert_eq!(draft.login_match_rules().unwrap(), Some(MatchRules::Host));
    draft
        .fields
        .iter_mut()
        .find(|f| f.key == "password")
        .unwrap()
        .value
        .value = "new-private-sentinel".into();
    let saved = draft.save().unwrap();
    let value: serde_json::Value = serde_json::from_str(&saved.payload_json).unwrap();
    assert_eq!(value["extra"]["issuer"], "import");
    assert_eq!(value["fields"][MATCH_RULES_KEY]["meta"]["readonly"], false);
    let mut reopened = ItemDraft::edit(saved.path, &saved.payload_json).unwrap();
    assert_eq!(
        reopened.login_match_rules().unwrap(),
        Some(MatchRules::Host)
    );
    reopened.set_login_match_rules(MatchRules::Never).unwrap();
    let saved = reopened.save().unwrap();
    let value: serde_json::Value = serde_json::from_str(&saved.payload_json).unwrap();
    assert_eq!(value["fields"]["password"]["value"], "new-private-sentinel");
    assert_eq!(
        reopened
            .fields
            .iter()
            .filter(|f| f.key == MATCH_RULES_KEY)
            .count(),
        1
    );
    assert!(!format!("{reopened:?}").contains("private-sentinel"));
}

#[test]
fn absent_rules_are_not_written_until_edited_and_invalid_rules_cannot_save() {
    let mut draft = ItemDraft::create("login").unwrap();
    draft.path = "site".into();
    assert_eq!(
        draft.login_match_rules().unwrap(),
        Some(MatchRules::RegistrableDomain)
    );
    let saved: serde_json::Value =
        serde_json::from_str(&draft.save().unwrap().payload_json).unwrap();
    assert!(saved["fields"].get(MATCH_RULES_KEY).is_none());
    draft
        .set_login_match_rules(MatchRules::Regex {
            pattern: "(private-sentinel".into(),
        })
        .unwrap();
    let error = draft.save().unwrap_err();
    assert!(matches!(error, DraftError::Autofill(_)));
    assert_eq!(error.translation_key(), "errors.match_rules_invalid");
    assert!(!format!("{error:?} {error}").contains("private-sentinel"));
    draft
        .set_login_match_rules(MatchRules::Regex {
            pattern: r"https://example\.com/.*".into(),
        })
        .unwrap();
    let saved = draft.save().unwrap();
    assert_eq!(
        ItemDraft::edit(saved.path, &saved.payload_json)
            .unwrap()
            .login_match_rules()
            .unwrap(),
        draft.login_match_rules().unwrap()
    );
    let mut note = ItemDraft::create("note").unwrap();
    assert_eq!(note.login_match_rules().unwrap(), None);
    assert!(matches!(
        note.set_login_match_rules(MatchRules::Host),
        Err(DraftError::Type)
    ));
}
