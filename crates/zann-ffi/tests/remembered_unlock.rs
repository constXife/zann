//! The remembered unlock shares `config.json` with the identity, so the risk
//! worth testing is that writing one destroys the other.
//!
//! Nothing here needs a credential store or an authenticator: those paths are
//! covered in `zann-keystore`.

use std::fs;
use std::path::PathBuf;

use uuid::Uuid;
use zann_ffi::create_core;

fn temp_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!("zann-ffi-remembered-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create temp dir");
    root
}

#[test]
fn a_fresh_device_has_nothing_remembered() {
    let root = temp_root();
    let db_url = format!("sqlite://{}", root.join("local.sqlite").display());

    let core = create_core(db_url).expect("create core");
    let remembered = core.remembered_unlock().expect("status");

    assert!(!remembered.armed);
    assert_eq!(remembered.source, "keystore");
    assert!(remembered.hardware_keys.is_empty());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn writing_the_remembered_unlock_leaves_the_identity_intact() {
    let root = temp_root();
    let db_url = format!("sqlite://{}", root.join("local.sqlite").display());
    let password = format!("test-master-password-{}", Uuid::now_v7());

    let core = create_core(db_url.clone()).expect("create core");
    core.initialize_master_password(password.clone())
        .expect("initialize master password");

    // Rewrites config.json through the remembered-unlock path.
    core.remove_hardware_key("not-enrolled".to_string())
        .expect("remove is a no-op");
    drop(core);

    let config = fs::read_to_string(root.join("config.json")).expect("config.json");
    assert!(config.contains("\"identity\""));
    assert!(config.contains("\"remembered_unlock\""));

    // The identity still derives the same master key, which is the property the
    // whole vault hangs on.
    let core = create_core(db_url).expect("reopen core");
    assert!(core.unlock(password).expect("unlock").unlocked);

    let _ = fs::remove_dir_all(&root);
}
