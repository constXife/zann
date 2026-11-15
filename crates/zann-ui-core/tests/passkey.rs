use serde_json::json;
use zann_ui_core::{
    category_views,
    item_editor::{editable_field_schemas, DraftError, ItemDraft},
    project_item_fields, ItemCounts, VaultScope,
};

#[test]
fn passkey_projection_obeys_security_profile_despite_hostile_field_metadata() {
    let fields = json!({
        "rp_id": {"kind":"text","value":"example.com"},
        "user_name": {"kind":"text","value":"test@example.com"},
        "private_key": {"kind":"text","value":"sentinel-private-key","meta":{"masked":false,"copyable":true}},
        "credential_id": {"kind":"url","value":"https://sentinel-id.test","meta":{"masked":false}},
        "user_handle": {"kind":"text","value":"sentinel-user-handle"},
        "exchange_metadata": {"kind":"text","value":"sentinel-login-password","meta":{"masked":false,"copyable":true}},
        "unknown": {"kind":"text","value":"sentinel-unknown"}
    });
    let payload = json!({"v":1,"typeId":"passkey","fields":fields}).to_string();
    let projection = project_item_fields(&payload).unwrap();
    assert_eq!(projection.len(), 2);
    assert!(projection
        .iter()
        .all(|field| !field.value.contains("sentinel")));
    assert!(matches!(
        ItemDraft::edit("passkey".into(), &payload),
        Err(DraftError::CeremonyManaged)
    ));
    assert!(matches!(
        ItemDraft::create("passkey"),
        Err(DraftError::CeremonyManaged)
    ));
    assert!(editable_field_schemas().all(|(id, _)| id != "passkey"));
    let mut draft = ItemDraft::create("login").unwrap();
    assert!(matches!(
        draft.set_type("passkey".into()),
        Err(DraftError::CeremonyManaged)
    ));
    draft.type_id = "passkey".into();
    assert!(matches!(draft.save(), Err(DraftError::CeremonyManaged)));
    let registry = zann_core::SecurityProfileRegistry::from_yaml(include_str!(
        "../../../schemas/security_profiles.yaml"
    ))
    .unwrap();
    let profile = registry.profile("passkey").unwrap();
    for key in [
        "private_key",
        "credential_id",
        "user_handle",
        "exchange_metadata",
    ] {
        assert!(profile.never_log_fields.contains(&key.into()));
        assert!(!profile.exposable_public_attrs.contains(&key.into()));
        assert!(!profile.ui.copyable.contains(&key.into()));
        assert!(!profile.ui.revealable.contains(&key.into()));
    }
}

#[test]
fn passkey_categories_count_and_filter_personal_items_without_manual_creation() {
    let counts = ItemCounts::new(8, 3).with_type("passkey", 5);
    let personal = category_views(&counts, VaultScope::Personal);
    let passkey = personal
        .iter()
        .find(|category| category.id == "passkey")
        .unwrap();
    assert_eq!(passkey.count, 5);
    assert!(passkey.create_action.is_none());
    assert!(!category_views(&counts, VaultScope::Shared)
        .iter()
        .any(|category| category.id == "passkey"));
    for language in ["en", "ru"] {
        let catalogue = zann_ui_core::Catalogue::new(language);
        assert!(catalogue.has(&passkey.label_key));
        assert!(catalogue.has("types.passkey"));
        assert!(catalogue.has("errors.passkey_managed"));
    }
}
