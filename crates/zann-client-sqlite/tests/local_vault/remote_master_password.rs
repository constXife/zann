use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zann_client_sqlite::local_vault::{open_vault as create_core, LocalVault};

use crate::support::CanonicalTempDir;
use zann_client::app::{
    AppClient, ClientId, ClientPaths, LoginPassword, PasswordLoginRequest,
    PasswordRegistrationRequest, PrepareConnectionOutcome, SessionClient, SessionOperation,
};
use zann_client::credentials::{OsCredentialStore, OsLegacyCredentialSource};
use zann_client_sqlite::SqliteSyncStoreFactory;
use zann_db::{connect_sqlite_file_with_max, migrate_local, SqliteFileLocation};

fn env_or_skip(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => {
            eprintln!("skipping: {key} not set");
            None
        }
    }
}

fn make_db_url(root: &Path) -> String {
    let path = root.join("local.sqlite");
    format!("sqlite://{}", path.display())
}

#[test]
#[ignore]
fn remote_login_create_master_then_relogin_unlock() {
    let server_url = match env_or_skip("ZANN_REMOTE_URL") {
        Some(value) => value,
        None => return,
    };
    let email = match env_or_skip("ZANN_REMOTE_EMAIL") {
        Some(value) => value,
        None => return,
    };
    let password = match env_or_skip("ZANN_REMOTE_PASSWORD") {
        Some(value) => value,
        None => return,
    };
    let master_password = match env_or_skip("ZANN_MASTER_PASSWORD") {
        Some(value) => value,
        None => return,
    };

    let dir = CanonicalTempDir::new();
    let root = dir.path().to_path_buf();
    let db_url = make_db_url(&root);

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let database = SqliteFileLocation::from_uri(&db_url).expect("database location");
    let pool = runtime
        .block_on(connect_sqlite_file_with_max(&database, 5))
        .expect("connect sqlite");
    runtime.block_on(migrate_local(&pool)).expect("migrate");
    let client = AppClient::new(
        ClientPaths::new(&root),
        Arc::new(OsCredentialStore::system_default()),
        SessionClient::new(ClientId::new("desktop").expect("client id")),
        Arc::new(SqliteSyncStoreFactory::new(database.path()).expect("sync factory")),
    );
    client
        .initialize(&OsLegacyCredentialSource::system_default())
        .expect("initialize client");
    let prepared = match runtime
        .block_on(client.prepare_connection(&server_url, "Remote", "default"))
        .expect("prepare connection")
    {
        PrepareConnectionOutcome::Ready(prepared) => prepared,
        PrepareConnectionOutcome::FingerprintChanged(_) => {
            panic!("test server fingerprint changed")
        }
    };
    let login = |email: String, password: String| {
        let request = PasswordLoginRequest::new(
            prepared.target().clone(),
            email,
            LoginPassword::new(password).expect("login password"),
        )
        .expect("login request");
        let operation = SessionOperation::new(Instant::now() + Duration::from_secs(60)).0;
        runtime
            .block_on(client.password_login(request, operation))
            .expect("login")
    };

    drop(login(email.clone(), password.clone()));

    let core = create_core(db_url.clone()).expect("create core");
    let device_password = format!("device-{master_password}");
    let init = core
        .initialize_master_password(device_password.clone())
        .expect("initialize master password");
    assert!(init.unlocked);
    core.enroll_account_key(master_password)
        .expect("enroll the account key");
    drop(core);

    drop(login(email, password));

    let core = create_core(db_url).expect("create core");
    core.unlock(device_password).expect("unlock after relogin");
    assert!(core.activate_connected_account().expect("activate account"));
}

fn select_personal_vault(core: &LocalVault, storage_id: &str) {
    core.set_current_storage(storage_id.to_string())
        .expect("select the server's storage");
    let vault = core
        .list_vaults()
        .expect("list vaults")
        .into_iter()
        .find(|vault| vault.kind == zann_core::VaultKind::Personal)
        .expect("the server's personal vault is synced");
    core.set_current_vault(vault.id)
        .expect("select the personal vault");
}

/// One account, two devices. Device A registers, publishes the personal vault
/// and pushes an item created in it; device B starts from an empty root, logs
/// in, enrolls the same account key under a different device password,
/// syncs and decrypts the item. Device B opens its database before login;
/// its device KDF must remain independent from the account KDF.
#[test]
#[ignore]
fn second_device_unlocks_the_synced_personal_vault() {
    let server_url = match env_or_skip("ZANN_REMOTE_URL") {
        Some(value) => value,
        None => return,
    };
    let email = format!("device-{}@example.test", uuid::Uuid::now_v7());
    let password = format!("account-password-{}", uuid::Uuid::now_v7());
    let master_password = format!("master-password-{}", uuid::Uuid::now_v7());
    let runtime = tokio::runtime::Runtime::new().expect("runtime");

    let connect = |root: &Path| {
        let database = SqliteFileLocation::from_uri(&make_db_url(root)).expect("location");
        let client = AppClient::new(
            ClientPaths::new(root),
            Arc::new(OsCredentialStore::system_default()),
            SessionClient::new(ClientId::new("desktop").expect("client id")),
            Arc::new(SqliteSyncStoreFactory::new(database.path()).expect("sync factory")),
        );
        client
            .initialize(&OsLegacyCredentialSource::system_default())
            .expect("initialize client");
        let prepared = match runtime
            .block_on(client.prepare_connection(&server_url, "Remote", "default"))
            .expect("prepare connection")
        {
            PrepareConnectionOutcome::Ready(prepared) => prepared,
            PrepareConnectionOutcome::FingerprintChanged(_) => {
                panic!("test server fingerprint changed")
            }
        };
        (client, prepared)
    };
    let operation = || SessionOperation::new(Instant::now() + Duration::from_secs(60)).0;

    let device_a = CanonicalTempDir::new();
    let core = create_core(make_db_url(device_a.path())).expect("open device A");
    let (client, prepared) = connect(device_a.path());
    let request = PasswordRegistrationRequest::new(
        prepared.target().clone(),
        email.clone(),
        LoginPassword::new(password.clone()).expect("password"),
        None,
    )
    .expect("registration request");
    let access = runtime
        .block_on(client.password_register(request, operation()))
        .expect("device A registers");
    let status = runtime
        .block_on(client.personal_vault_status(&access))
        .expect("personal vault status");
    assert!(!status.personal_key_envelopes_present());
    let storage_id = prepared.storage_id().to_string();
    drop(core);

    let core = create_core(make_db_url(device_a.path())).expect("reopen device A");
    core.initialize_master_password("device A unlock password".into())
        .expect("device A initializes its unlock password");
    core.enroll_account_key(master_password.clone())
        .expect("device A enrolls the account key");
    core.remote_sync(Some(storage_id.clone()), None)
        .expect("device A publishes the personal vault");
    select_personal_vault(&core, &storage_id);
    let item_id = core
        .debug_create_kv_item("pushed".to_string(), "key".to_string(), "value".to_string())
        .expect("device A creates an item");
    core.remote_sync(Some(storage_id.clone()), None)
        .expect("device A pushes the created item");
    core.remote_sync(Some(storage_id), None)
        .expect("device A has nothing left to push");
    drop(core);

    let device_b = CanonicalTempDir::new();
    let core = create_core(make_db_url(device_b.path())).expect("open device B");
    let (client, prepared) = connect(device_b.path());
    let request = PasswordLoginRequest::new(
        prepared.target().clone(),
        email,
        LoginPassword::new(password).expect("password"),
    )
    .expect("login request");
    let access = runtime
        .block_on(client.password_login(request, operation()))
        .expect("device B logs in without an identity conflict");
    let status = runtime
        .block_on(client.personal_vault_status(&access))
        .expect("personal vault status");
    assert!(status.personal_key_envelopes_present());
    drop(core);

    let core = create_core(make_db_url(device_b.path())).expect("reopen device B");
    let device_password = "device B unlock password";
    core.initialize_master_password(device_password.into())
        .expect("device B initializes its own unlock password");
    core.enroll_account_key(format!("wrong-{master_password}"))
        .expect_err("wrong account key cannot enroll");
    assert!(!core.activate_connected_account().expect("not enrolled"));
    core.enroll_account_key(master_password)
        .expect("device B enrolls the account key");
    core.remote_sync(Some(prepared.storage_id().to_string()), None)
        .expect("device B syncs");
    select_personal_vault(&core, prepared.storage_id());

    // Restarting the device session opens its enrolled account key locally.
    core.lock().expect("lock");
    core.unlock(format!("wrong-{device_password}"))
        .expect_err("another password must not unlock this device");
    core.unlock(device_password.into())
        .expect("device B opens its enrolled account key");
    select_personal_vault(&core, prepared.storage_id());
    let item = core
        .item_get(item_id)
        .expect("device B decrypts device A's item");
    assert_eq!(item.path, "pushed");
    assert!(item.payload_json.contains("\"value\""));
}
