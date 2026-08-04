//! The QML frontend reads these structures as JSON, so their field names are
//! part of the contract with `apps/kde/qml/main.qml`. Renaming a field here
//! silently breaks the UI, which no compiler catches — these tests do.

use serde_json::Value;

use zann_ui_core::{build_folder_tree, generate_totp, ItemView, TotpParams};

fn item(path: &str) -> ItemView {
    ItemView {
        title: path.to_string(),
        type_id: "login".to_string(),
        path: path.to_string(),
        deleted: false,
    }
}

#[test]
fn folder_tree_json_matches_the_qml_contract() {
    let tree = build_folder_tree(&[item("work/aws/root"), item("scratch")]);
    let json: Value = serde_json::from_str(&serde_json::to_string(&tree).expect("serialize"))
        .expect("valid json");

    assert_eq!(json["items_without_folder"], 1);

    let root = &json["tree"][0];
    assert_eq!(root["name"], "work");
    assert_eq!(root["path"], "work");
    assert_eq!(root["item_count"], 0);
    assert_eq!(root["total_count"], 1);

    let child = &root["children"][0];
    assert_eq!(child["path"], "work/aws");
    assert_eq!(child["total_count"], 1);
}

#[test]
fn totp_json_matches_the_qml_contract() {
    let code = generate_totp(&TotpParams::new("JBSWY3DPEHPK3PXP")).expect("totp");
    let json: Value = serde_json::from_str(&serde_json::to_string(&code).expect("serialize"))
        .expect("valid json");

    assert!(json["code"].as_str().is_some_and(|code| code.len() == 6));
    assert_eq!(json["period"], 30);
    assert!(json["remaining_seconds"].as_u64().is_some());
}
