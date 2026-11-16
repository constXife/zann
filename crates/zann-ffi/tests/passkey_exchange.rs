mod support;
use zann_ffi::*;
#[test]
fn foreign_file_projection_keeps_private_keys_out_of_dtos_and_requires_step_up_for_cxf() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let core = support::open(&root.join("local.sqlite"));
    core.seed_offline_fixture("synthetic device password".into())
        .unwrap();
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/passkey-exchange/cxf.json")
        .display()
        .to_string();
    let format = PasskeyExchangeFormatFfi::Cxf;
    assert_eq!(
        core.passkey_preflight_file(source.clone(), format)
            .unwrap()
            .credentials,
        1
    );
    let target = core.passkey_targets().unwrap().remove(0).target;
    assert_eq!(
        core.passkey_import_file(
            source.clone(),
            format,
            target.clone(),
            SessionOperationFfi::new(120_000).unwrap()
        )
        .unwrap()
        .imported,
        1
    );
    let authorization = core
        .authorize_export(
            ExportStepUpFfi {
                password: Some("synthetic device password".into()),
                factor: ExportFactorFfi::DevicePassword,
                pin: None,
            },
            SessionOperationFfi::new(120_000).unwrap(),
        )
        .unwrap();
    let output = root.join("passkeys.cxf.json").display().to_string();
    assert_eq!(
        core.passkey_export_cxf(output.clone(), target.clone(), authorization.clone())
            .unwrap()
            .items_count,
        1
    );
    assert!(core
        .passkey_export_cxf(output, target, authorization)
        .is_err());
    assert!(core.verify().unwrap().problems.is_empty());
}
