use std::path::PathBuf;

use tempfile::tempdir;
use zann_client::auth_password::password_login;
use zann_client::state::ClientState;
use zann_db::{connect_sqlite_with_max, migrate_local};
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

fn make_db_url(root: &PathBuf) -> String {
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
    let pool = runtime
        .block_on(connect_sqlite_with_max(&db_url, 5))
        .expect("connect sqlite");
    runtime.block_on(migrate_local(&pool)).expect("migrate");

    let state = ClientState::new(pool.clone(), root.clone());

    let first_login = runtime
        .block_on(password_login(
            server_url.clone(),
            email.clone(),
            password.clone(),
            &state,
        ))
        .expect("login");
    assert!(first_login.ok, "login failed");
    assert_eq!(
        first_login.data.as_ref().map(|data| data.status.as_str()),
        Some("success")
    );

    let core = create_core(db_url.clone()).expect("create core");
    let init = core
        .initialize_master_password(master_password.clone())
        .expect("initialize master password");
    assert!(init.unlocked);
    drop(core);

    let second_login = runtime
        .block_on(password_login(server_url, email, password, &state))
        .expect("login");
    assert!(second_login.ok, "login failed");
    assert_eq!(
        second_login.data.as_ref().map(|data| data.status.as_str()),
        Some("success")
    );

    let core = create_core(db_url).expect("create core");
    core.unlock(master_password).expect("unlock after relogin");
}
