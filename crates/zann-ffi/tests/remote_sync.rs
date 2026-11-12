//! A shell's whole server flow through the FFI surface, against a live
//! server: one core per device, never reopened, exactly as the Apple shell
//! drives it. Ignored unless `ZANN_REMOTE_URL` names a server with open
//! registration.

mod support;

use std::sync::Arc;

use zann_ffi::{
    CoreFacade, PrepareConnectionOutcomeFfi, PreparedConnectionFfi, SessionOperationFfi,
};

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
