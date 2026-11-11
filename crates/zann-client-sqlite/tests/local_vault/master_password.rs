use crate::support::CanonicalTempDir;
use std::fs;
use zann_client_sqlite::local_vault::open_vault as create_core;

use uuid::Uuid;

#[test]
fn master_password_persists_across_reopen() {
    let root = CanonicalTempDir::new();
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
}
