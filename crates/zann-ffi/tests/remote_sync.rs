//! A shell's whole server flow through the FFI surface, against a live
//! server: one core per device, never reopened, exactly as the Apple shell
//! drives it. Ignored unless `ZANN_REMOTE_URL` names a server with open
//! registration.

mod support;

use std::sync::Arc;

use zann_ffi::{
    CoreFacade, PrepareConnectionOutcomeFfi, PreparedConnectionFfi, SessionOperationFfi,
};

/// The core runs one sync per process, so these tests take turns.
static SERVER: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn server_url() -> Option<String> {
    std::env::var("ZANN_REMOTE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn connect(core: &CoreFacade, url: &str) -> Arc<PreparedConnectionFfi> {
    let session = core.remote_session().expect("remote session");
    match session
        .prepare_connection(url.to_string(), "Remote".into(), "default".into())
        .expect("prepare connection")
    {
        PrepareConnectionOutcomeFfi::Ready { connection } => connection,
        PrepareConnectionOutcomeFfi::FingerprintChanged { .. } => {
            panic!("a fresh device has nothing pinned")
        }
    }
}

fn operation() -> Arc<SessionOperationFfi> {
    SessionOperationFfi::new(60_000).expect("operation")
}

/// After the first sync the core moves the empty session to the server's
/// personal vault; the shell never picks a storage.
fn assert_in_personal_vault(core: &CoreFacade, storage_id: &str) {
    assert_eq!(core.current_storage_id(), storage_id);
    let current = core.current_vault_id().expect("a vault is open");
    let vault = core
        .list_vaults()
        .expect("list vaults")
        .into_iter()
        .find(|vault| vault.id == current)
        .expect("the open vault is in the server's storage");
    assert_eq!(vault.kind, "personal");
}

#[test]
#[ignore]
fn a_second_device_opens_the_vault_the_first_one_published() {
    let Some(url) = server_url() else {
        eprintln!("skipping: ZANN_REMOTE_URL not set");
        return;
    };
    let _turn = SERVER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let email = format!("ffi-{suffix}@example.test");
    let account_password = format!("account-password-{suffix}");
    let master_password = format!("master-password-{suffix}");

    let device_a = tempfile::tempdir().expect("tempdir");
    let database_a = device_a.path().join("local.sqlite");
    let secrets_a = Arc::new(support::MemorySecretStore::default());
    let core = support::open_with_secrets(&database_a, Arc::default(), Arc::clone(&secrets_a));
    let connection = connect(&core, &url);
    let session = core.remote_session().expect("remote session");
    let access = session
        .password_register(
            Arc::clone(&connection),
            email.clone(),
            account_password.clone(),
            None,
            operation(),
        )
        .expect("device A registers");
    let status = session.personal_vault_status(access).expect("status");
    assert!(!status.personal_key_envelopes_present);
    let storage_id = connection.storage_id();
    core.initialize_master_password(master_password.clone())
        .expect("device A creates the vault");
    core.remote_sync(None)
        .expect("device A publishes the personal vault");
    core.follow_preferred_storage().expect("follow the server");
    assert_in_personal_vault(&core, &storage_id);

    // Every storage is still empty; a restart keeps the server's vault
    // rather than the local one creating the master password made.
    drop(core);
    let core = support::open_with_secrets(&database_a, Arc::default(), secrets_a);
    core.unlock(master_password.clone())
        .expect("device A unlocks again");
    assert_in_personal_vault(&core, &storage_id);
    let item_id = core
        .debug_create_kv_item("pushed".into(), "key".into(), "value".into())
        .expect("device A creates an item");
    core.remote_sync(None).expect("device A pushes it");

    let device_b = tempfile::tempdir().expect("tempdir");
    let database_b = device_b.path().join("local.sqlite");
    let core = support::open(&database_b);
    let status = core.app_status().expect("status");
    assert!(!status.initialized);
    assert!(!status.server_connected);
    let connection = connect(&core, &url);
    let session = core.remote_session().expect("remote session");
    let access = session
        .password_login(
            Arc::clone(&connection),
            email,
            account_password,
            operation(),
        )
        .expect("device B logs in");
    let status = session.personal_vault_status(access).expect("status");
    assert!(status.personal_key_envelopes_present);
    assert!(core.app_status().expect("status").server_connected);
    let storage_id = connection.storage_id();
    core.unlock(master_password.clone())
        .expect("device B derives the account's master key");
    core.remote_sync(None).expect("device B pulls");
    core.follow_preferred_storage().expect("follow the server");
    assert_in_personal_vault(&core, &storage_id);
    let item = core
        .item_get(item_id.clone())
        .expect("device B decrypts the item");
    assert_eq!(item.path, "pushed");

    // A restart lands in the same vault before any sync.
    drop(core);
    let core = support::open(&database_b);
    core.unlock(master_password)
        .expect("device B unlocks again");
    assert_in_personal_vault(&core, &storage_id);
    core.item_get(item_id).expect("the item is still there");
}

struct Account {
    email: String,
    account_password: String,
    master_password: String,
    item_id: String,
}

/// A new account whose first device published one item.
fn publish_account(url: &str) -> Account {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let account = Account {
        email: format!("ffi-{suffix}@example.test"),
        account_password: format!("account-password-{suffix}"),
        master_password: format!("master-password-{suffix}"),
        item_id: String::new(),
    };
    let device = tempfile::tempdir().expect("tempdir");
    let core = support::open(&device.path().join("local.sqlite"));
    let connection = connect(&core, url);
    core.remote_session()
        .expect("remote session")
        .password_register(
            connection,
            account.email.clone(),
            account.account_password.clone(),
            None,
            operation(),
        )
        .expect("register");
    core.initialize_master_password(account.master_password.clone())
        .expect("create the vault");
    core.remote_sync(None).expect("publish the vault");
    core.follow_preferred_storage().expect("follow the server");
    let item_id = core
        .debug_create_kv_item("pushed".into(), "key".into(), "value".into())
        .expect("create an item");
    core.remote_sync(None).expect("push it");
    Account { item_id, ..account }
}

/// A mistyped master password on a fresh device must bind nothing: the right
/// password still opens the account's vault afterwards, and the typo never
/// opens anything.
#[test]
#[ignore]
fn a_mistyped_master_password_never_binds_a_new_device() {
    let Some(url) = server_url() else {
        eprintln!("skipping: ZANN_REMOTE_URL not set");
        return;
    };
    let _turn = SERVER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let account = publish_account(&url);
    let typo = format!("{}x", account.master_password);

    let device = tempfile::tempdir().expect("tempdir");
    let database = device.path().join("local.sqlite");
    let secrets = Arc::new(support::MemorySecretStore::default());
    let core = support::open_with_secrets(&database, Arc::default(), Arc::clone(&secrets));
    let connection = connect(&core, &url);
    core.remote_session()
        .expect("remote session")
        .password_login(
            connection,
            account.email.clone(),
            account.account_password.clone(),
            operation(),
        )
        .expect("log in");

    // The key is checked against the account's vault key before anything
    // is stored under it, so the device stays as fresh as before.
    core.unlock(typo.clone())
        .expect_err("the typo opens nothing on a new device");
    assert!(!core.app_status().expect("status").initialized);

    drop(core);
    let core = support::open_with_secrets(&database, Arc::default(), secrets);
    core.unlock(typo)
        .expect_err("the typo opens nothing after a restart either");
    core.unlock(account.master_password.clone())
        .expect("the right password still opens the device");
    core.remote_sync(None)
        .expect("and syncs the account's vault");
    core.follow_preferred_storage().expect("follow the server");
    let item = core
        .item_get(account.item_id)
        .expect("the account's item is readable");
    assert_eq!(item.path, "pushed");
}
