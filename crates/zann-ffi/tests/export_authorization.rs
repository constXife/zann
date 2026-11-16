mod support;
use zann_ffi::{CoreError, ExportFactorFfi, ExportStepUpFfi, SessionOperationFfi};

#[test]
fn foreign_callers_need_a_fresh_opaque_single_use_authorization() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let core = support::open(&root.join("local.sqlite"));
    core.seed_offline_fixture("synthetic export fixture".into())
        .unwrap();
    let proof = || ExportStepUpFfi {
        password: Some("synthetic export fixture".into()),
        factor: ExportFactorFfi::DevicePassword,
        pin: None,
    };
    let operation = SessionOperationFfi::new(120_000).unwrap();
    let permit = core.authorize_export(proof(), operation).unwrap();
    let output = root.join("backup.json");
    core.backup_export_file(output.display().to_string(), permit.clone())
        .unwrap();
    assert!(
        matches!(core.backup_export_file(root.join("replay.json").display().to_string(), permit), Err(CoreError::Unlock { kind, .. }) if kind == "export_authorization_required")
    );
    assert!(!root.join("replay.json").exists());
    let operation = SessionOperationFfi::new(120_000).unwrap();
    let permit = core.authorize_export(proof(), operation.clone()).unwrap();
    operation.cancel();
    assert!(core
        .backup_export_file(root.join("cancelled.json").display().to_string(), permit)
        .is_err());
    assert!(!root.join("cancelled.json").exists());
    let permit = core
        .authorize_export(proof(), SessionOperationFfi::new(120_000).unwrap())
        .unwrap();
    core.lock().unwrap();
    assert!(core
        .backup_export_file(root.join("locked.json").display().to_string(), permit)
        .is_err());
    assert!(!root.join("locked.json").exists());
}
