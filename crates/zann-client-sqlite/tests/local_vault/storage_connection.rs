//! Whether a server syncs a storage comes from the client config, not from
//! the storage row: a server storage keeps its row after its server is
//! forgotten.

use crate::support::CanonicalTempDir;
use zann_client_sqlite::local_vault::open_vault as create_core;

use uuid::Uuid;
use zann_client::app::local::{StorageLink, StorageSyncState};

#[test]
fn a_server_storage_without_a_connection_is_not_synced() {
    let root = CanonicalTempDir::new();
    let db_path = root.join("local.sqlite");
    let db_url = format!("sqlite://{}", db_path.display());
    let password = format!("test-master-password-{}", Uuid::now_v7());

    let core = create_core(db_url.clone()).expect("create core");
    core.seed_offline_fixture(password.clone())
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

    assert_eq!(
        core.storage_sync_state(storage_id.clone())
            .expect("no connection is an answer, not an error"),
        StorageSyncState {
            link: StorageLink::Disconnected,
            server_url: Some("https://zann.example.test".to_string()),
            pending_changes: 0,
            last_synced_at: None,
        }
    );
    core.storage_sync_state(Uuid::nil().to_string())
        .expect_err("no phantom Local storage");
    core.storage_sync_state(Uuid::now_v7().to_string())
        .expect_err("an unknown storage is not a local one");
    // An explicit sync still says why it cannot run.
    core.remote_sync(Some(storage_id), None)
        .expect_err("no server to sync with");
}

/// A new connection to an address takes over the storage the database keeps
/// there: the factory finds it by address and releases it, as often as asked.
#[test]
fn the_storage_kept_for_an_address_is_found_and_released() {
    use std::sync::Arc;
    use zann_client::app::{AppSyncStoreFactory, ClientPaths};
    use zann_client_sqlite::SqliteSyncStoreFactory;

    let root = CanonicalTempDir::new();
    let db_path = root.join("local.sqlite");
    let core = create_core(format!("sqlite://{}", db_path.display())).expect("create core");
    core.seed_offline_fixture(format!("test-master-password-{}", Uuid::now_v7()))
        .expect("initialize master password");
    drop(core);

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let location = zann_db::SqliteFileLocation::from_path(&db_path).expect("location");
    let pool = runtime
        .block_on(zann_db::connect_sqlite_file_with_max(&location, 1))
        .expect("connect");
    let address = "https://zann.example.test/";
    let remote = zann_db::local::LocalStorage {
        id: Uuid::now_v7(),
        kind: zann_core::StorageKind::Remote,
        name: "Remote".to_string(),
        server_url: Some(address.to_string()),
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

    let factory = Arc::new(SqliteSyncStoreFactory::new(&db_path).expect("factory"));
    let paths = ClientPaths::with_local_db(root.path(), &db_path);
    let at = |address: &str| {
        runtime
            .block_on(Arc::clone(&factory).storage_at(paths.clone(), address.to_string()))
            .expect("look up storage")
    };
    assert_eq!(at(address), Some(remote.id));
    assert_eq!(at("https://other.example.test/"), None);
    for storage_id in [remote.id, remote.id, Uuid::now_v7()] {
        runtime
            .block_on(Arc::clone(&factory).release_storage(paths.clone(), storage_id))
            .expect("releasing is idempotent");
    }
}
