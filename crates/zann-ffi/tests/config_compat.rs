use std::fs;

use tempfile::TempDir;
use zann_ffi::create_core;

fn fixture(name: &str) -> &'static [u8] {
    match name {
        "cli-keyring" => {
            include_bytes!("../../../tests/fixtures/client-config/v1/cli-keyring.json")
        }
        "local-identity-nullable" => {
            include_bytes!("../../../tests/fixtures/client-config/v1/local-identity-nullable.json")
        }
        other => panic!("unknown config fixture: {other}"),
    }
}

fn root_with_fixture(name: &str) -> TempDir {
    let root = tempfile::tempdir().expect("tempdir");
    fs::write(root.path().join("config.json"), fixture(name)).expect("write config fixture");
    root
}

fn open_local(root: &TempDir) {
    let db_url = format!("sqlite://{}", root.path().join("local.sqlite").display());
    let core = create_core(db_url).expect("FFI/local accepts config");
    drop(core);
}

fn config_bytes(root: &TempDir) -> Vec<u8> {
    fs::read(root.path().join("config.json")).expect("read config")
}

#[test]
fn ffi_local_accepts_cli_keyring_config_without_rewriting_it() {
    let root = root_with_fixture("cli-keyring");
    let before = config_bytes(&root);

    open_local(&root);

    assert_eq!(config_bytes(&root), before, "FFI/local rewrote config.json");
}

#[test]
fn ffi_local_accepts_nullable_identity_without_rewriting_config() {
    let root = root_with_fixture("local-identity-nullable");
    let before = config_bytes(&root);

    open_local(&root);

    assert_eq!(config_bytes(&root), before, "FFI/local rewrote config.json");
}
