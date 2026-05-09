use std::fs;
use std::path::PathBuf;

use uuid::Uuid;
use zann_ffi::create_core;

fn temp_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!("zann-ffi-test-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create temp dir");
    root
}

#[test]
fn master_password_persists_across_reopen() {
    let root = temp_root();
    let db_path = root.join("local.sqlite");
    let db_url = format!("sqlite://{}", db_path.display());
    let password = format!("test-master-password-{}", Uuid::now_v7());

    let core = create_core(db_url.clone()).expect("create core");
    let status = core
        .initialize_master_password(password.clone())
        .expect("initialize master password");
    assert!(status.unlocked);
    drop(core);

    let core = create_core(db_url.clone()).expect("reopen core");
    let status = core.unlock(password).expect("unlock with same password");
    assert!(status.unlocked);

    let _ = fs::remove_file(&db_path);
    let _ = fs::remove_file(root.join("config.json"));
    let _ = fs::remove_dir_all(&root);
}
