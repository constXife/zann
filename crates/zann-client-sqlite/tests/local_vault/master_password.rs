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

/// A sync that fails after writing its storage row leaves a server storage
/// without vaults. Opening the database again must not land there and accept
/// any password for want of a vault key to check it against.
#[test]
fn a_server_storage_without_vaults_never_opens_without_the_password() {
    let root = CanonicalTempDir::new();
    let db_path = root.join("local.sqlite");
    let db_url = format!("sqlite://{}", db_path.display());
    let password = format!("test-master-password-{}", Uuid::now_v7());

    let core = create_core(db_url.clone()).expect("create core");
    core.initialize_master_password(password.clone())
        .expect("initialize master password");
    drop(core);

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let location = zann_db::SqliteFileLocation::from_path(&db_path).expect("location");
    let pool = runtime
        .block_on(zann_db::connect_sqlite_file_with_max(&location, 1))
        .expect("connect");
    let remote = zann_db::local::LocalStorage {
        id: Uuid::now_v7(),
        kind: zann_core::StorageKind::Remote,
        name: "Remote".to_string(),
        server_url: Some("https://zann.example.test".to_string()),
        server_name: None,
        server_fingerprint: None,
        account_subject: None,
        personal_vaults_enabled: true,
        auth_method: None,
    };
    runtime
        .block_on(zann_db::local::LocalStorageRepo::new(&pool).upsert(&remote))
        .expect("insert a server storage without vaults");
    runtime.block_on(pool.close());

    let core = create_core(db_url.clone()).expect("reopen core");
    core.unlock(format!("wrong-{password}"))
        .expect_err("a wrong password must not open the vault");
    core.unlock(password).expect("the right password opens it");
    assert_eq!(core.current_storage_id(), Uuid::nil().to_string());

    // A locked session cannot change the context that will verify its password.
    core.lock().expect("lock");
    core.set_current_storage(remote.id.to_string())
        .expect_err("selection requires an unlocked session");
    assert_eq!(core.current_storage_id(), Uuid::nil().to_string());
    core.unlock("another wrong password".to_string())
        .expect_err("a wrong password must not open the vault");
}
