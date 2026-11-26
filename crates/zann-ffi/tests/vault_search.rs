mod support;

use zann_ffi::{CoreError, ItemCreate, ItemsFilter, Page, TranslationCatalogue, VaultSearchFfi};

#[test]
fn offline_search_returns_scoped_pages_of_evidence_without_persisting_payload_text() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("local.sqlite");
    let core = support::open(&database);
    core.seed_offline_fixture("fixture-password".into())
        .unwrap();
    let catalogue = TranslationCatalogue::new("ru".into());
    let search = |text: &str, cursor| {
        core.items_list(
            ItemsFilter {
                updated: None,
                query: Some(VaultSearchFfi {
                    text: text.into(),
                    catalogue: catalogue.clone(),
                }),
                include_deleted: false,
            },
            Page { limit: 1, cursor },
        )
    };
    let create = |name: &str, fields: serde_json::Value| {
        core.item_create(ItemCreate {
            title: name.into(),
            path: name.into(),
            type_id: "login".into(),
            payload_json: serde_json::json!({"v":1,"typeId":"login","fields":fields}).to_string(),
        })
        .unwrap()
    };
    let card = create(
        "Carrier",
        serde_json::json!({
            "PIN": {"kind":"password","value":"451028"},
            "PUK": {"kind":"text","value":"984677"},
            "username": {"kind":"text","value":"private-username"},
            "notes": {"kind":"note","value":"sealed-note-phrase"},
            "SecretLabelSentinel": {"kind":"otp","value":"otp-secret-sentinel"},
            "hidden": {"kind":"note","value":"masked-note-sentinel","meta":{"masked":true}}
        }),
    );
    create(
        "Partial",
        serde_json::json!({"PIN":{"kind":"text","value":"PUK"}}),
    );
    let note = create(
        "Letter",
        serde_json::json!({"memo":{"kind":"note","value":"Reset the PIN with the PUK."}}),
    );
    let first = search("  pIn  PUK  ", None).unwrap();
    assert_eq!((first.total_count, first.counts.all), (2, 2));
    assert_eq!(first.items[0].id, note.id);
    assert_eq!(
        first.items[0].caption.as_deref(),
        Some("Совпадение в заметке")
    );
    let next = search("pin puk", Some(first.next_cursor.unwrap())).unwrap();
    assert_eq!(next.items[0].id, card.id);
    assert_eq!(
        next.items[0].caption.as_deref(),
        Some("Найдены поля PIN и PUK")
    );
    assert!(next.next_cursor.is_none());
    assert_eq!(next.total_count, 2);
    assert_eq!(
        search("PIN sealed-note", None).unwrap().items[0]
            .caption
            .as_deref(),
        Some("Совпадение в заметке")
    );
    assert_eq!(search("Carrier PUK", None).unwrap().items[0].id, card.id);
    let localized = catalogue.field_label("username".into());
    assert_eq!(
        search(&localized, None).unwrap().items[0]
            .caption
            .as_deref(),
        Some(format!("Найдено поле {localized}").as_str())
    );
    for value in [
        "451028",
        "984677",
        "private-username",
        "otp-secret-sentinel",
        "masked-note-sentinel",
    ] {
        assert_eq!(search(value, None).unwrap().total_count, 0);
    }

    assert_eq!(
        search("secretlabel", None).unwrap().items[0]
            .caption
            .as_deref(),
        Some("Найдено поле SecretLabelSentinel")
    );

    let other = core
        .seed_offline_storage(
            "ad656aa9-a047-47d5-8ad1-8355777f27d8".into(),
            "Other".into(),
            "https://other.example.test".into(),
        )
        .unwrap();
    core.set_current_storage(other).unwrap();
    assert_eq!(search("PIN PUK", None).unwrap().total_count, 0);
    core.lock().unwrap();
    assert!(matches!(search("PIN PUK", None), Err(CoreError::Locked)));

    // Inspect the live database and sidecars as well as the checkpointed file.
    let check_disk = || {
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let entry = entry.unwrap();
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("local.sqlite")
                && entry.path().is_file()
            {
                let bytes = std::fs::read(entry.path()).unwrap();
                for sentinel in [
                    "sealed-note-phrase",
                    "SecretLabelSentinel",
                    "masked-note-sentinel",
                ] {
                    assert!(!bytes
                        .windows(sentinel.len())
                        .any(|w| w == sentinel.as_bytes()));
                }
            }
        }
    };
    check_disk();
    drop(core);
    check_disk();
}
