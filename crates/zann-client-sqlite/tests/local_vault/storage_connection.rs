//! Whether a server syncs a storage comes from the client config, not from
//! the storage row: a server storage keeps its row after its server is
//! forgotten.

use crate::support::CanonicalTempDir;
use zann_client_sqlite::local_vault::open_vault as create_core;

use uuid::Uuid;

#[test]
fn a_server_storage_without_a_connection_is_not_synced() {
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
        .expect("insert a server storage");
    runtime.block_on(pool.close());

    let core = create_core(db_url).expect("reopen core");
    core.unlock(password).expect("unlock");
    let storage_id = remote.id.to_string();

    assert!(!core
        .syncs_storage(storage_id.clone())
        .expect("no connection is an answer, not an error"));
    assert!(!core
        .syncs_storage(Uuid::nil().to_string())
        .expect("the local storage"));
    // An explicit sync still says why it cannot run.
    core.remote_sync(Some(storage_id))
        .expect_err("no server to sync with");
}
