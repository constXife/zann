mod support;

use zann_ffi::{CoreError, ItemCreate, ItemsFilter, Page, StorageSyncStateFfi, SyncLinkFfi};

#[test]
fn ffi_projects_local_commands_results_and_errors() {
    let root = tempfile::tempdir().expect("tempdir");
    let core = support::open(&root.path().join("local.sqlite"));
    assert!(matches!(
        core.item_get("invalid".into()),
        Err(CoreError::Locked)
    ));
    assert!(matches!(
        core.unlock_remembered(),
        Err(CoreError::Unlock { kind, .. }) if kind == "keystore_not_found"
    ));
    core.seed_offline_fixture("adapter-test-password".into())
        .expect("initialize");
    let payload = r#"{"v":1,"typeId":"login","fields":{"password":{"kind":"password","value":"test-secret"}}}"#;
    let item = core
        .item_create(ItemCreate {
            path: "adapter/login".into(),
            title: "login".into(),
            type_id: "login".into(),
            payload_json: payload.into(),
        })
        .expect("create");
    assert_eq!(item.payload_json, payload);
    assert!(!format!("{item:?}").contains("test-secret"));
    let page = core
        .items_list(
            ItemsFilter {
                query: None,
                include_deleted: false,
            },
            Page {
                limit: 10,
                cursor: None,
            },
        )
        .expect("list");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, item.id);
    assert_eq!(page.counts.all, 1);
    assert!(!core.lock().expect("lock").unlocked);
    assert!(matches!(core.item_get(item.id), Err(CoreError::Locked)));
}

#[test]
fn a_listed_item_carries_its_caption_from_non_secret_fields() {
    let root = tempfile::tempdir().expect("tempdir");
    let core = support::open(&root.path().join("local.sqlite"));
    core.seed_offline_fixture("adapter-test-password".into())
        .expect("initialize");
    let create = |path: &str, payload: &str| {
        core.item_create(ItemCreate {
            path: path.into(),
            title: path.rsplit('/').next().expect("name").into(),
            type_id: "login".into(),
            payload_json: payload.into(),
        })
        .expect("create")
    };
    let with_username = create(
        "Mail",
        r#"{"v":1,"typeId":"login","fields":{"username":{"kind":"text","value":"alice"},"password":{"kind":"password","value":"test-secret"}}}"#,
    );
    let with_url = create(
        "Cloud/mail storage",
        r#"{"v":1,"typeId":"login","fields":{"url":{"kind":"url","value":"https://storage.example.net/box"}}}"#,
    );
    let secret_only = create(
        "Bank",
        r#"{"v":1,"typeId":"login","fields":{"password":{"kind":"password","value":"test-secret"}}}"#,
    );
    let list = |query: Option<&str>| {
        core.items_list(
            ItemsFilter {
                query: query.map(str::to_string),
                include_deleted: false,
            },
            Page {
                limit: 10,
                cursor: None,
            },
        )
        .expect("list")
    };

    let page = list(None);
    let caption = |id: &str| {
        page.items
            .iter()
            .find(|item| item.id == id)
            .expect("listed")
            .caption
            .clone()
    };
    assert_eq!(caption(&with_username.id).as_deref(), Some("alice"));
    assert_eq!(
        caption(&with_url.id).as_deref(),
        Some("storage.example.net · Cloud")
    );
    assert_eq!(caption(&secret_only.id), None);
    assert!(!format!("{:?}", page.items).contains("alice"));

    // A search page carries captions too.
    let found = list(Some("mail"));
    assert_eq!(found.items.len(), 2);
    assert!(found.items.iter().all(|item| item.caption.is_some()));
}

#[test]
fn a_storage_no_server_syncs_has_no_server_to_forget() {
    let root = tempfile::tempdir().expect("tempdir");
    let core = support::open(&root.path().join("local.sqlite"));
    core.seed_offline_fixture("adapter-test-password".into())
        .expect("initialize");
    let storage = core.current_storage_id().expect("selected server storage");

    assert_eq!(
        core.storage_sync_state(storage.clone())
            .expect("storage sync state")
            .link,
        SyncLinkFfi::Disconnected
    );
    assert_eq!(
        core.pending_change_count(storage.clone())
            .expect("pending count"),
        0
    );
    for _ in 0..2 {
        assert_eq!(
            core.forget_server(storage.clone()).expect("forget server"),
            None
        );
    }
    assert!(matches!(
        core.pending_change_count("not-a-storage".into()),
        Err(CoreError::InvalidArgument(_))
    ));
}

#[test]
fn a_storage_without_its_connection_projects_what_waits_for_its_server() {
    use zann_client::app::local::{StorageLink, StorageSyncState};

    assert_eq!(
        StorageSyncStateFfi::from(StorageSyncState {
            link: StorageLink::Disconnected,
            server_url: Some("https://zann.example.test".into()),
            pending_changes: 3,
            last_synced_at: Some("2026-11-13T07:15:34+00:00".into()),
        }),
        StorageSyncStateFfi {
            link: SyncLinkFfi::Disconnected,
            server_url: Some("https://zann.example.test".into()),
            pending_changes: 3,
            last_synced_at: Some("2026-11-13T07:15:34+00:00".into()),
        }
    );
}

#[test]
fn the_sync_indicator_projects_the_shared_presentation_rule() {
    use zann_ffi::{sync_indicator, SyncActionFfi, SyncIndicatorStateFfi, SyncStatusInputFfi};

    let indicator = sync_indicator(SyncStatusInputFfi {
        link: SyncLinkFfi::Connected,
        server_url: Some("https://zann.example.test/".into()),
        pending_changes: 2,
        syncing: false,
        failed: false,
    });
    assert_eq!(indicator.state, SyncIndicatorStateFfi::Pending);
    assert_eq!(indicator.label_key, "sync.pending");
    assert_eq!(
        indicator.label_args.get("server").map(String::as_str),
        Some("zann.example.test")
    );
    assert_eq!(
        indicator.label_args.get("count").map(String::as_str),
        Some("2")
    );
    assert_eq!(indicator.action, SyncActionFfi::SyncNow);
    assert!(!indicator.needs_attention);
}
