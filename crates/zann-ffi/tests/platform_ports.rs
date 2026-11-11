//! The shell-supplied keystore arms and serves remembered unlock, and its
//! errors keep their meaning across the boundary.

mod support;

use std::sync::Arc;

use support::{open_with, MemoryKeystore};
use zann_ffi::CoreError;

#[test]
fn foreign_keystore_remembers_unlocks_and_forgets() {
    let root = tempfile::tempdir().expect("tempdir");
    let keystore = Arc::new(MemoryKeystore::default());
    let core = open_with(&root.path().join("vault/local.sqlite"), keystore.clone());
    core.initialize_master_password("test master password".into())
        .expect("initialize");

    core.remember_with_keystore().expect("remember");
    assert!(keystore.dwk.lock().unwrap().is_some());
    assert!(core.remembered_unlock().expect("status").armed);

    assert!(!core.lock().expect("lock").unlocked);
    assert!(core.unlock_remembered().expect("unlock").unlocked);

    core.forget_remembered().expect("forget");
    assert!(keystore.dwk.lock().unwrap().is_none());
}

#[test]
fn a_dismissed_platform_prompt_is_reported_as_cancelled() {
    let root = tempfile::tempdir().expect("tempdir");
    let keystore = Arc::new(MemoryKeystore::default());
    let core = open_with(&root.path().join("local.sqlite"), keystore.clone());
    core.initialize_master_password("test master password".into())
        .expect("initialize");
    core.remember_with_keystore().expect("remember");
    core.lock().expect("lock");

    *keystore.cancel_load.lock().unwrap() = true;

    assert!(matches!(
        core.unlock_remembered(),
        Err(CoreError::Unlock { kind, .. }) if kind == "keystore_cancelled"
    ));
}

#[test]
fn a_relative_database_path_is_rejected() {
    let error = zann_ffi::create_core(
        "relative/local.sqlite".into(),
        Arc::new(MemoryKeystore::default()),
        Arc::new(support::MemorySecretStore::default()),
    )
    .err()
    .expect("relative path must be rejected");
    assert!(matches!(error, CoreError::InvalidArgument(_)));
}
