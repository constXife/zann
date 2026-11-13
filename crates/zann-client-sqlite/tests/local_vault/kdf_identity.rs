//! Config v2 keeps the account KDF identity committed by server login.
//! Opening a database or requesting local initialization never invents one.

use crate::support::CanonicalTempDir;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use uuid::Uuid;
use zann_client::app::local::LocalError;
use zann_client::app::{
    AppClient, ClientId, ClientPaths, ConfigIdentity, ConfigKdfParams, SessionClient,
};
use zann_client::credentials::{OsCredentialStore, OsLegacyCredentialSource};
use zann_client_sqlite::local_vault::open_vault as create_core;
use zann_client_sqlite::SqliteSyncStoreFactory;

fn db_url(root: &Path) -> String {
    format!("sqlite://{}", root.join("local.sqlite").display())
}

fn app_client(root: &Path) -> AppClient {
    let client = AppClient::new(
        ClientPaths::new(root),
        Arc::new(OsCredentialStore::system_default()),
        SessionClient::new(ClientId::new("desktop").expect("client id")),
        Arc::new(SqliteSyncStoreFactory::new(&root.join("local.sqlite")).expect("sync factory")),
    );
    client
        .initialize(&OsLegacyCredentialSource::system_default())
        .expect("initialize client config");
    client
}

fn committed_identity(root: &Path) -> Option<ConfigIdentity> {
    app_client(root).kdf_identity().expect("read identity")
}

/// Stands in for the identity a login reads from `/v1/auth/prelogin`.
fn account_identity() -> ConfigIdentity {
    ConfigIdentity {
        kdf_salt: "c2VydmVyLXNhbHQtZm9yLXRoZS1hY2NvdW50AAA=".to_string(),
        kdf_params: ConfigKdfParams {
            algorithm: "argon2id".to_string(),
            iterations: 2,
            memory_kb: 19456,
            parallelism: 1,
        },
        salt_fingerprint: None,
        first_seen_at: None,
        email: Some("user@example.test".to_string()),
    }
}

#[test]
fn opening_a_fresh_database_commits_no_identity() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("open core");
    core.snapshot_create_if_due(24, None)
        .expect("start-up snapshot");
    drop(core);

    assert!(
        !root.join("config.json").exists(),
        "the legacy identity writer is gone"
    );
    assert_eq!(
        committed_identity(&root),
        None,
        "opening must leave the salt to server login"
    );
}

#[test]
fn initializing_without_server_login_stores_nothing() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("open core");
    core.initialize_master_password("correct horse battery".into())
        .expect_err("server required");
    assert!(core.list_storages().expect("storages").is_empty());
    assert!(core.current_storage_id().is_none());
    assert!(core.current_vault_id().is_none());
    assert!(committed_identity(&root).is_none());
}

/// The account's identity outlives the session that committed it, for
/// instance after a logout. Without a session the account cannot confirm the
/// master password, so nothing may be stored under an unchecked key: its
/// first sync would bind that key to the connection for good.
#[test]
fn an_account_identity_without_a_session_stores_nothing() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("open core");

    // The login lands after the database was opened, exactly as a client
    // shows its welcome screen first.
    app_client(&root)
        .replace_kdf_identity_if_matches(None, account_identity())
        .expect("a fresh device has no conflicting salt");

    let password = format!("pw-{}", Uuid::now_v7());
    for refused in [
        core.initialize_master_password(password.clone()),
        core.unlock(password),
    ] {
        match refused {
            Err(LocalError::Sync { kind, .. }) => assert_eq!(kind, "session_expired"),
            other => panic!("expected a sign-in request, got {other:?}"),
        }
    }
    assert!(!core.app_status().expect("status").initialized);
    assert_eq!(
        committed_identity(&root),
        Some(account_identity()),
        "the account's salt stays untouched"
    );
}

#[test]
fn a_second_device_unlocks_with_the_account_identity() {
    let password = format!("pw-{}", Uuid::now_v7());

    let first = CanonicalTempDir::new();
    let core = create_core(db_url(&first)).expect("open device A");
    core.seed_offline_fixture(password.clone())
        .expect("device A replica");
    let identity = committed_identity(&first).expect("account identity");
    // A consistent copy of device A's database, independent of its WAL.
    let synced = core.snapshot_create(None).expect("device A snapshot");
    drop(core);

    let second = CanonicalTempDir::new();
    let core = create_core(db_url(&second)).expect("open device B");
    drop(core);
    app_client(&second)
        .replace_kdf_identity_if_matches(None, identity)
        .expect("device B login adopts the account's salt");

    // Stand in for a sync: device B receives device A's encrypted vault.
    fs::copy(&synced.path, second.join("local.sqlite")).expect("copy the synced database");
    for sidecar in ["local.sqlite-wal", "local.sqlite-shm"] {
        let _ = fs::remove_file(second.join(sidecar));
    }
    let core = create_core(db_url(&second)).expect("reopen device B");
    assert!(
        core.unlock(password)
            .expect("device B derives device A's master key")
            .unlocked
    );
}

#[test]
fn unlocking_before_any_identity_is_refused() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("open core");

    core.unlock(format!("pw-{}", Uuid::now_v7()))
        .expect_err("there is no salt to derive a key from");
    assert_eq!(committed_identity(&root), None);
}
