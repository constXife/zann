use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::tempdir;
use zann_client::app::{
    AppClient, ClientId, ClientPaths, LoginPassword, PasswordLoginRequest,
    PrepareConnectionOutcome, SessionClient, SessionOperation,
};
use zann_client::credentials::{OsCredentialStore, OsLegacyCredentialSource};
use zann_client_sqlite::SqliteSyncStoreFactory;
use zann_db::{connect_sqlite_file_with_max, migrate_local, SqliteFileLocation};
use zann_ffi::create_core;

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
    let path = root.join("zann.sqlite");
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

    let dir = tempdir().expect("tempdir");
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
    let init = core
        .initialize_master_password(master_password.clone())
        .expect("initialize master password");
    assert!(init.unlocked);
    drop(core);

    drop(login(email, password));

    let core = create_core(db_url).expect("create core");
    core.unlock(master_password).expect("unlock after relogin");
}
