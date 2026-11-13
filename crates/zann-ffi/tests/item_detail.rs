mod support;

use zann_ffi::{generate_totp, CoreError, ItemCreate, SessionOperationFfi};

#[test]
fn one_read_projects_canonical_fields_without_exporting_payload_json() {
    let root = tempfile::tempdir().expect("tempdir");
    let core = support::open(&root.path().join("local.sqlite"));
    core.seed_offline_fixture("adapter-test-password".into())
        .expect("initialize");
    let payload = r#"{"v":1,"typeId":"login","fields":{
        "notes":{"kind":"note","value":"line"},
        "totp":{"kind":"otp","value":"JBSWY3DPEHPK3PXP"},
        "password":{"kind":"password","value":"hunter2"},
        "username":{"kind":"text","value":"alice"},
        "url":{"kind":"url","value":"https://example.com/"}}}"#;
    let item = core
        .item_create(ItemCreate {
            path: "Example".into(),
            title: "Example".into(),
            type_id: "login".into(),
            payload_json: payload.into(),
        })
        .expect("create");
    let operation = SessionOperationFfi::new(10_000).expect("operation");
    let detail = core
        .item_detail(item.id.clone(), operation.clone())
        .expect("detail");
    assert_eq!(detail.id, item.id);
    assert_eq!(detail.title, "Example");
    assert_eq!(detail.path, "Example");
    assert_eq!(detail.type_id, "login");
    let fields = detail.fields;
    assert_eq!(
        fields.iter().map(|f| f.key.as_str()).collect::<Vec<_>>(),
        ["username", "password", "totp", "url", "notes"]
    );
    assert!(!fields[0].masked);
    assert_eq!(fields[1].value, "hunter2");
    assert!(fields[1].masked);
    assert!(fields[1].website_url.is_none());
    assert_eq!(
        fields[3].website_url.as_deref(),
        Some("https://example.com/")
    );
    assert!(fields[4].multiline);
    assert!(!format!("{fields:?}").contains("hunter2"));
    let totp = fields[2].totp.clone().expect("totp");
    assert!(!format!("{totp:?}").contains("JBSWY3DPEHPK3PXP"));
    let code = generate_totp(totp).expect("code");
    assert_eq!(code.code.len(), 6);
    assert_eq!(code.period, 30);
    assert!(matches!(
        core.item_detail(item.id.clone(), operation),
        Err(CoreError::InvalidArgument(_))
    ));
    let operation = SessionOperationFfi::new(10_000).expect("operation");
    operation.cancel();
    assert!(matches!(
        core.item_detail(item.id.clone(), operation),
        Err(CoreError::Cancelled)
    ));
    core.lock().expect("lock");
    assert!(matches!(
        core.item_detail(item.id, SessionOperationFfi::new(10_000).unwrap()),
        Err(CoreError::Locked)
    ));
}
