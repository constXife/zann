mod support;

use zann_ffi::{CoreError, ItemCreate, ItemsFilter, Page, StorageLinkFfi};

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
    core.initialize_master_password("adapter-test-password".into())
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
fn a_storage_no_server_syncs_has_no_server_to_forget() {
    let root = tempfile::tempdir().expect("tempdir");
    let core = support::open(&root.path().join("local.sqlite"));
    core.initialize_master_password("adapter-test-password".into())
        .expect("initialize");
    let storage = core.current_storage_id();

    assert_eq!(
        core.storage_link(storage.clone()).expect("storage link"),
        StorageLinkFfi::Local
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

    let state = |link| StorageSyncState {
        link,
        server_url: Some("https://zann.example.test".into()),
        pending_changes: 3,
        last_synced_at: None,
    };
    assert_eq!(
        StorageLinkFfi::from(state(StorageLink::Disconnected)),
        StorageLinkFfi::Disconnected {
            server_url: Some("https://zann.example.test".into()),
            pending_changes: 3,
        }
    );
    assert_eq!(
        StorageLinkFfi::from(state(StorageLink::Connected)),
        StorageLinkFfi::Connected
    );
}
