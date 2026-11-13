use zann_ffi::{
    build_folder_tree, category_views, create_type_for_category, device_preference_options,
    device_preferences_default, device_preferences_from_json, device_preferences_to_json,
    filter_items, item_type_schemas, normalize_server_url, CoreError, DraftErrorKindFfi,
    FieldKindFfi, FolderFilterFfi, ItemCountsFfi, ItemDetail, ItemDraftFfi, ItemFilterFfi,
    ItemSummary, ItemTypeCount, TranslationCatalogue, VaultScopeFfi,
};

fn item(title: &str, type_id: &str, path: &str, deleted: bool) -> ItemSummary {
    ItemSummary {
        id: title.into(),
        title: title.into(),
        path: path.into(),
        type_id: type_id.into(),
        caption: None,
        deleted,
    }
}

#[test]
fn categories_filter_and_folders_follow_ui_core() {
    let counts = ItemCountsFfi {
        all: 3,
        trash: 1,
        by_type: vec![ItemTypeCount {
            type_id: "login".into(),
            count: 2,
        }],
    };
    let views = category_views(counts, VaultScopeFfi::Personal);
    let login = views.iter().find(|view| view.id == "login").expect("login");
    assert_eq!(login.count, 2);
    let note = views.iter().find(|view| view.id == "note").unwrap();
    let action = note.create_action.as_ref().expect("note creation action");
    assert_eq!(action.type_id, "note");
    assert_eq!(action.label_key, "create.actions.note");
    assert!(views
        .iter()
        .find(|view| view.id == "trash")
        .unwrap()
        .create_action
        .is_none());
    assert_eq!(
        views
            .iter()
            .find(|view| view.id == "trash")
            .map(|view| view.count),
        Some(1)
    );
    assert_eq!(create_type_for_category(Some("infra".into())), "ssh_key");
    assert_eq!(create_type_for_category(None), "login");

    let items = vec![
        item("AWS root", "login", "work/aws/root", false),
        item("Mail", "login", "personal/mail", false),
        item("Scratch", "note", "scratch", false),
        item("Old", "login", "work/old", true),
    ];
    let logins = filter_items(
        items.clone(),
        ItemFilterFfi {
            category_id: Some("login".into()),
            folder: FolderFilterFfi::Path {
                path: "work".into(),
            },
            query: String::new(),
        },
    );
    assert_eq!(logins, [0]);
    let rootless = filter_items(
        items.clone(),
        ItemFilterFfi {
            category_id: None,
            folder: FolderFilterFfi::WithoutFolder,
            query: String::new(),
        },
    );
    assert_eq!(rootless, [2]);

    let tree = build_folder_tree(items);
    assert_eq!(tree.items_without_folder, 1);
    let work = tree
        .tree
        .iter()
        .find(|node| node.path == "work")
        .expect("work");
    assert_eq!(work.total_count, 1);
    assert_eq!(work.children[0].path, "work/aws");
}

#[test]
fn item_draft_validates_and_builds_the_payload() {
    assert!(item_type_schemas()
        .iter()
        .any(|schema| schema.type_id == "login" && schema.main[1].kind == FieldKindFfi::Password));

    let draft = ItemDraftFfi::create("login".into()).expect("draft");
    let keys: Vec<_> = draft.fields().into_iter().map(|field| field.key).collect();
    assert_eq!(keys, ["username", "password", "url"]);
    assert!(matches!(
        draft.create_request(),
        Err(CoreError::Draft {
            kind: DraftErrorKindFfi::Path,
            translation_key,
            ..
        }) if translation_key == "errors.path_invalid"
    ));

    draft
        .set_location("example".into(), " web ".into())
        .expect("location");
    draft.set_field_value(0, "alice".into()).expect("username");
    draft
        .set_field_value(1, "hunter2".into())
        .expect("password");
    draft.remove_field(2).expect("drop url");
    draft.add_field();
    draft.set_field_key(2, "notes".into()).expect("key");
    draft.set_field_kind(2, FieldKindFfi::Note).expect("kind");
    assert!(draft.fields()[2].multiline);
    assert!(!format!("{:?}", draft.fields()).contains("hunter2"));
    assert!(matches!(
        draft.set_field_value(9, "x".into()),
        Err(CoreError::InvalidArgument(_))
    ));
    assert!(!draft
        .set_type("note".into())
        .expect("populated draft keeps fields"));

    let request = draft.create_request().expect("request");
    assert_eq!(request.path, "web/example");
    assert_eq!(request.title, "example");
    assert_eq!(request.type_id, "note");
    let edited = ItemDraftFfi::edit(ItemDetail {
        id: "item".into(),
        title: request.title,
        path: request.path,
        type_id: request.type_id,
        payload_json: request.payload_json,
    })
    .expect("edit");
    assert_eq!(edited.type_id(), "note");
    assert_eq!(edited.name(), "example");
    assert_eq!(edited.folder().as_deref(), Some("web"));
    assert!(matches!(
        edited.set_location(String::new(), "folder".into()),
        Err(CoreError::Draft {
            kind: DraftErrorKindFfi::Name,
            ..
        })
    ));
    assert_eq!(edited.path(), "web/example");
    let values: Vec<_> = edited
        .fields()
        .into_iter()
        .map(|field| (field.key, field.value))
        .collect();
    assert_eq!(
        values,
        [
            ("username".to_string(), "alice".to_string()),
            ("password".to_string(), "hunter2".to_string()),
            ("notes".to_string(), String::new()),
        ]
    );
}

#[test]
fn shared_defaults_reach_native_shells() {
    assert_eq!(
        normalize_server_url(" zann.example ".into()),
        "https://zann.example"
    );
    let defaults = device_preferences_default();
    assert_eq!(defaults.auto_lock_minutes, 10);
    let options = device_preference_options();
    assert!(options
        .auto_lock_minutes
        .contains(&defaults.auto_lock_minutes));
    assert!(options
        .languages
        .iter()
        .any(|language| language.code == "en"));
}

#[test]
fn stored_preferences_round_trip_and_fill_shared_defaults() {
    let mut preferences = device_preferences_default();
    preferences.lock_on_focus_loss = true;
    preferences.auto_lock_minutes = 5;
    let stored = device_preferences_to_json(preferences.clone());
    assert_eq!(device_preferences_from_json(stored).unwrap(), preferences);

    let partial = device_preferences_from_json(r#"{"auto_lock_minutes":30}"#.into()).unwrap();
    assert_eq!(partial.auto_lock_minutes, 30);
    assert_eq!(
        partial.clipboard_clear_seconds,
        device_preferences_default().clipboard_clear_seconds
    );

    assert!(matches!(
        device_preferences_from_json(r#"{"auto_lock_minutes":"soon"}"#.into()),
        Err(CoreError::InvalidArgument(_))
    ));
}

#[test]
fn translation_catalogue_resolves_category_and_field_labels() {
    let catalogue = TranslationCatalogue::new("ru-RU".into());
    assert_eq!(catalogue.language(), "ru");
    assert_eq!(catalogue.get("nav.allItems".into()), "Все записи");
    assert_eq!(catalogue.field_label("password".into()), "Пароль");
    assert_eq!(catalogue.get("no.such.key".into()), "no.such.key");
    assert_eq!(catalogue.minutes_label(60), "1 час");
    assert_eq!(catalogue.seconds_label(120), "2 мин");

    let english = TranslationCatalogue::new("pt-BR".into());
    assert_eq!(english.language(), "en");
    assert_eq!(english.field_label("recovery_code".into()), "Recovery code");
}
