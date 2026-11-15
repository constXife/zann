mod support;
use zann_ffi::{BackupRecipientFfi, BackupRecipientKindFfi, SessionOperationFfi};
fn phrase() -> BackupRecipientFfi {
    BackupRecipientFfi {
        kind: BackupRecipientKindFfi::Passphrase,
        passphrase: Some("synthetic portable passphrase".into()),
        pin: None,
        built_in_uv: false,
    }
}
#[test]
fn foreign_archive_lifecycle_preserves_separate_biometric_custody_and_has_no_plaintext_output() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let keystore = std::sync::Arc::new(support::MemoryKeystore::default());
    let core = support::open_with(&root.join("local.sqlite"), keystore.clone());
    core.seed_offline_fixture("synthetic device password".into())
        .unwrap();
    core.item_create(zann_ffi::ItemCreate{title:"Synthetic note".into(),path:"test/secret".into(),type_id:"note".into(),payload_json:r#"{"v":1,"typeId":"note","fields":{"notes":{"kind":"text","value":"sentinel plaintext secret"}}}"#.into()}).unwrap();
    let handle = core
        .backup_begin(SessionOperationFfi::new(600_000).unwrap())
        .unwrap();
    core.backup_add_recipient(handle.clone(), phrase()).unwrap();
    core.backup_add_recipient(
        handle.clone(),
        BackupRecipientFfi {
            kind: BackupRecipientKindFfi::Biometric,
            passphrase: None,
            pin: None,
            built_in_uv: false,
        },
    )
    .unwrap();
    assert!(
        keystore.dwk.lock().unwrap().is_none(),
        "backup key never arms or overwrites remembered unlock"
    );
    assert_eq!(keystore.backup_keys.lock().unwrap().len(), 1);
    let path = root.join("portable.zann");
    core.backup_export_encrypted(path.display().to_string(), handle.clone())
        .unwrap();
    assert!(core
        .backup_export_encrypted(path.display().to_string(), handle)
        .is_err());
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes
        .windows(b"sentinel plaintext secret".len())
        .any(|w| w == b"sentinel plaintext secret"));
    let handle = core
        .backup_open_encrypted(
            path.display().to_string(),
            0,
            phrase(),
            SessionOperationFfi::new(600_000).unwrap(),
        )
        .unwrap();
    let inspection = core.backup_inspect_encrypted(handle.clone()).unwrap();
    assert_eq!(inspection.items_count, 1);
    assert_eq!(inspection.storages.len(), 1);
    core.backup_cancel(handle.clone()).unwrap();
    core.backup_cancel(handle).unwrap();
    let input = BackupRecipientFfi {
        kind: BackupRecipientKindFfi::Hardware,
        passphrase: Some("sentinel phrase".into()),
        pin: Some("sentinel pin".into()),
        built_in_uv: false,
    };
    assert!(!format!("{input:?}").contains("sentinel"));
}
