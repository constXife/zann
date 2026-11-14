#![cfg(feature = "browser-ipc")]
use zann_autofill::MatchQuality;
use zann_client::browser_ipc::{BrowserMatch, BrowserScope, BrowserUsage, MAX_USAGE_ENTRIES};

fn server() -> String {
    "ab".repeat(32)
}
fn scope() -> BrowserScope {
    BrowserScope {
        storage_id: "storage".into(),
        vault_id: "vault".into(),
        generation: 1,
    }
}
fn item(id: &str, quality: MatchQuality) -> BrowserMatch {
    BrowserMatch {
        item_id: id.into(),
        title: "title never stored".into(),
        username: Some("username never stored".into()),
        match_quality: quality,
    }
}
fn ids(items: &[BrowserMatch]) -> Vec<&str> {
    items.iter().map(|item| item.item_id.as_str()).collect()
}

#[test]
fn match_precision_precedes_recency_and_unknown_ties_preserve_native_order() {
    let mut usage = BrowserUsage::from_json("null").unwrap();
    usage
        .record_success(&server(), &scope(), "used-origin")
        .unwrap();
    usage.record_success(&server(), &scope(), "domain").unwrap();
    let before = usage.to_json().unwrap();
    let mut items = vec![
        item("origin-a", MatchQuality::Origin),
        item("domain", MatchQuality::Domain),
        item("used-origin", MatchQuality::Origin),
        item("exact", MatchQuality::Exact),
        item("origin-b", MatchQuality::Origin),
    ];
    usage.rank(&server(), &scope(), &mut items).unwrap();
    assert_eq!(
        ids(&items),
        ["exact", "used-origin", "origin-a", "origin-b", "domain"]
    );
    assert_eq!(before, usage.to_json().unwrap(), "search never records use");
    assert!(!before.contains("title never stored"));
    assert!(!before.contains("username never stored"));
}

#[test]
fn history_round_trips_and_repeat_success_moves_one_entry_to_the_front() {
    let mut usage = BrowserUsage::from_json("null").unwrap();
    for id in ["a", "b", "a"] {
        usage.record_success(&server(), &scope(), id).unwrap();
    }
    let snapshot = usage.to_json().unwrap();
    let usage = BrowserUsage::from_json(&snapshot).unwrap();
    let mut items = vec![
        item("b", MatchQuality::Origin),
        item("a", MatchQuality::Origin),
    ];
    usage.rank(&server(), &scope(), &mut items).unwrap();
    assert_eq!(ids(&items), ["a", "b"]);
    let json: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(json["entries"].as_array().unwrap().len(), 2);
    assert_eq!(
        json["entries"][0].as_object().unwrap().len(),
        4,
        "only opaque IDs, no clocks or frequency counters"
    );
}

#[test]
fn server_storage_and_vault_are_isolated_but_lock_generations_keep_usage() {
    let mut usage = BrowserUsage::from_json("null").unwrap();
    usage.record_success(&server(), &scope(), "b").unwrap();
    for change in 0..4 {
        let mut selected = scope();
        let mut selected_server = server();
        match change {
            0 => selected_server = "cd".repeat(32),
            1 => selected.storage_id = "other-storage".into(),
            2 => selected.vault_id = "other-vault".into(),
            _ => selected.generation += 1,
        }
        let mut items = vec![
            item("a", MatchQuality::Origin),
            item("b", MatchQuality::Origin),
        ];
        usage.rank(&selected_server, &selected, &mut items).unwrap();
        assert_eq!(
            ids(&items),
            if change == 3 {
                vec!["b", "a"]
            } else {
                vec!["a", "b"]
            }
        );
    }
}

#[test]
fn retention_is_bounded_and_drops_the_least_recent_entry() {
    let mut usage = BrowserUsage::from_json("null").unwrap();
    for index in 0..=MAX_USAGE_ENTRIES {
        usage
            .record_success(&server(), &scope(), &index.to_string())
            .unwrap();
    }
    let json: serde_json::Value = serde_json::from_str(&usage.to_json().unwrap()).unwrap();
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), MAX_USAGE_ENTRIES);
    assert_eq!(entries[0]["item_id"], MAX_USAGE_ENTRIES.to_string());
    assert!(entries.iter().all(|e| e["item_id"] != "0"));
    BrowserUsage::from_json(&usage.to_json().unwrap()).unwrap();
}

#[test]
fn malformed_future_duplicate_and_oversized_snapshots_are_not_replaced_by_empty_history() {
    for json in [
        "{}",
        "[]",
        "not json",
        r#"{"version":2,"entries":[]}"#,
        r#"{"version":1,"entries":[],"unknown":true}"#,
    ] {
        assert!(BrowserUsage::from_json(json).is_err());
    }
    let mut usage = BrowserUsage::from_json("null").unwrap();
    usage.record_success(&server(), &scope(), "a").unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&usage.to_json().unwrap()).unwrap();
    let duplicate = value["entries"][0].clone();
    value["entries"].as_array_mut().unwrap().push(duplicate);
    assert!(BrowserUsage::from_json(&value.to_string()).is_err());
    assert!(BrowserUsage::from_json(&" ".repeat(4 * 1024 * 1024 + 1)).is_err());
    let before = usage.to_json().unwrap();
    assert!(usage.record_success(&server(), &scope(), "").is_err());
    assert_eq!(before, usage.to_json().unwrap());
}
