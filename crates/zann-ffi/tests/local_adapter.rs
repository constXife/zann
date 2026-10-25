use zann_ffi::{create_core_at_path, CoreError, ItemCreate, ItemsFilter, Page};

#[test]
fn ffi_projects_local_commands_results_and_errors() {
    let root = tempfile::tempdir().expect("tempdir");
    let core = create_core_at_path(&root.path().join("local.sqlite")).expect("open");
    assert!(matches!(
        core.item_get("invalid".into()),
        Err(CoreError::Locked)
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
