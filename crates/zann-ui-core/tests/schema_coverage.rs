//! Every item type the schemas know must sit in exactly one item category.
//!
//! An item whose type no category lists shows only under "All items", and a
//! type listed twice is counted twice; either way the category badges stop
//! adding up to the "All items" count. The type ids come from every schema
//! that names them, so a type added to one schema and forgotten in another
//! fails here instead of disappearing from the sidebar.

use std::collections::BTreeSet;

use serde_json::Value;
use zann_core::SecurityProfileRegistry;
use zann_ui_core::categories::schema;
use zann_ui_core::i18n::{EN, RU};
use zann_ui_core::item_editor::{field_schemas, FieldKind, ItemDraft};
use zann_ui_core::project_item_fields;

const SECURITY_PROFILES_YAML: &str = include_str!("../../../schemas/security_profiles.yaml");

fn catalogue_types(catalogue: &str) -> BTreeSet<String> {
    let catalogue: Value = serde_json::from_str(catalogue).expect("catalogue parses");
    catalogue["types"]
        .as_object()
        .expect("catalogue has types")
        .keys()
        .cloned()
        .collect()
}

#[test]
fn every_schema_names_the_same_item_types() {
    let templates: BTreeSet<String> = field_schemas().keys().cloned().collect();
    let profiles: BTreeSet<String> = SecurityProfileRegistry::from_yaml(SECURITY_PROFILES_YAML)
        .expect("security profiles parse")
        .profiles()
        .keys()
        .cloned()
        .collect();
    let categorized: BTreeSet<String> = schema()
        .categories
        .iter()
        .filter_map(|category| category.filter.as_ref()?.type_ids.clone())
        .flatten()
        .collect();

    assert!(templates.contains("secret"), "server-provisioned type");
    assert_eq!(
        profiles, templates,
        "security_profiles.yaml vs item_fields.json"
    );
    assert_eq!(
        categorized, templates,
        "ui_categories.json vs item_fields.json"
    );
    assert_eq!(catalogue_types(EN), templates, "i18n/en.json types");
    assert_eq!(catalogue_types(RU), templates, "i18n/ru.json types");
}

#[test]
fn every_item_type_sits_in_exactly_one_category() {
    for type_id in field_schemas().keys() {
        let owners: Vec<&str> = schema()
            .categories
            .iter()
            .filter(|category| {
                category
                    .filter
                    .as_ref()
                    .and_then(|filter| filter.type_ids.as_ref())
                    .is_some_and(|type_ids| type_ids.contains(type_id))
            })
            .map(|category| category.id.as_str())
            .collect();
        assert_eq!(owners.len(), 1, "{type_id} is listed by {owners:?}");
    }
}

/// `zann-server provision` writes a `secret` item as exactly a password-kind
/// `value` and a text-kind `policy`; the template and the detail view follow it.
#[test]
fn secret_template_matches_the_provisioned_payload() {
    let draft = ItemDraft::create("secret").expect("secret template");
    let fields: Vec<(&str, FieldKind)> = draft
        .fields
        .iter()
        .map(|field| (field.key.as_str(), field.value.kind))
        .collect();
    assert_eq!(
        fields,
        [("value", FieldKind::Password), ("policy", FieldKind::Text)]
    );

    let provisioned = r#"{"v":1,"typeId":"secret","fields":{
        "policy":{"kind":"text","value":"default"},
        "value":{"kind":"password","value":"provisioned-sentinel"}}}"#;
    let projected = project_item_fields(provisioned).expect("project secret");
    let shown: Vec<(&str, bool)> = projected
        .iter()
        .map(|field| (field.key.as_str(), field.masked))
        .collect();
    assert_eq!(shown, [("value", true), ("policy", false)]);
}
