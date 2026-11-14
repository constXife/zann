use zann_ffi::{
    CoreError, DraftErrorKindFfi, ItemDetail, ItemDraftFfi, LoginMatchRulesFfi, MatchModeFfi,
};

#[test]
fn typed_match_rules_cross_ffi_and_survive_edit_without_losing_fields() {
    let draft = ItemDraftFfi::create("login".into()).unwrap();
    draft.set_path("site".into());
    draft.set_field_value(1, "private-sentinel".into()).unwrap();
    assert_eq!(
        draft.login_match_rules().unwrap().unwrap().mode,
        MatchModeFfi::RegistrableDomain
    );
    for mode in [
        MatchModeFfi::Host,
        MatchModeFfi::Exact,
        MatchModeFfi::Never,
        MatchModeFfi::Regex,
    ] {
        draft
            .set_login_match_rules(LoginMatchRulesFfi {
                mode,
                pattern: r"https://example\.com/.*".into(),
            })
            .unwrap();
        let request = draft.update_request().unwrap();
        let payload: serde_json::Value = serde_json::from_str(&request.payload_json).unwrap();
        assert_eq!(payload["fields"]["password"]["value"], "private-sentinel");
        let edited = ItemDraftFfi::edit(ItemDetail {
            id: "item".into(),
            title: request.title,
            path: request.path,
            type_id: request.type_id,
            payload_json: request.payload_json,
        })
        .unwrap();
        assert_eq!(edited.login_match_rules().unwrap().unwrap().mode, mode);
    }
    draft
        .set_login_match_rules(LoginMatchRulesFfi {
            mode: MatchModeFfi::Regex,
            pattern: "(private-sentinel".into(),
        })
        .unwrap();
    let error = draft.update_request().unwrap_err();
    assert!(
        matches!(&error, CoreError::Draft { kind: DraftErrorKindFfi::Autofill, translation_key, .. } if translation_key == "errors.match_rules_invalid")
    );
    assert!(!format!("{error:?} {error}").contains("private-sentinel"));
}
