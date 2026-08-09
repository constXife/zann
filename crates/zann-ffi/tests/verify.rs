//! Verification through the facade.
//!
//! The point of `verify` is to answer "is my data still intact" without the
//! user having to take it on faith. These tests hold it to that: a clean vault
//! must report clean, and a damaged one must be caught rather than shrugged at.

use std::fs;
use std::path::PathBuf;

use uuid::Uuid;
use zann_ffi::create_core;

fn temp_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("zann-ffi-verify-{}-{}", tag, Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create temp dir");
    root
}

fn db_url(root: &std::path::Path) -> String {
    format!("sqlite://{}", root.join("local.sqlite").display())
}

#[test]
fn a_healthy_vault_reports_clean() {
    let root = temp_root("clean");
    let core = create_core(db_url(&root)).expect("create core");
    core.initialize_master_password(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");
    core.debug_create_kv_item("secrets/one".into(), "token".into(), "first".into())
        .expect("create item");
    core.debug_create_kv_item("secrets/two".into(), "token".into(), "second".into())
        .expect("create item");

    let report = core.verify().expect("verify");

    assert!(report.database_ok);
    assert_eq!(report.items_checked, 2);
    assert_eq!(report.items_ok, 2);
    assert_eq!(report.vaults_checked, 1);
    assert!(
        report.problems.is_empty(),
        "unexpected problems: {:?}",
        report.problems
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_locked_vault_cannot_be_verified() {
    let root = temp_root("locked");
    let core = create_core(db_url(&root)).expect("create core");
    core.initialize_master_password(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");
    core.lock().expect("lock");

    // Unlike a snapshot, verification has to read the payloads, so it needs the
    // key and must say so rather than reporting a hollow pass.
    core.verify()
        .expect_err("a locked vault must not report on data it cannot read");

    let _ = fs::remove_dir_all(&root);
}

/// The whole reason this exists: damage in the file must surface, and it must
/// survive the round trip through the facade with a usable `kind`.
#[test]
fn a_damaged_payload_is_reported_through_the_facade() {
    let root = temp_root("damaged");
    let password = format!("pw-{}", Uuid::now_v7());
    let core = create_core(db_url(&root)).expect("create core");
    core.initialize_master_password(password.clone())
        .expect("initialize master password");
    core.debug_create_kv_item("secrets/one".into(), "token".into(), "first".into())
        .expect("create item");
    assert!(core.verify().expect("verify").problems.is_empty());
    drop(core);

    // Corrupt the stored payload behind the app's back, the way a bad disk
    // would, then reopen and ask. Done straight against the file, because the
    // app is exactly what must not be trusted to notice.
    let changed = tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            let pool = zann_db::connect_sqlite_with_max(&db_url(&root), 1)
                .await
                .expect("open the database directly");
            let changed = sqlx_core::query::query("UPDATE items_cache SET payload_enc = ?")
                .bind(vec![0u8; 64])
                .execute(&pool)
                .await
                .expect("corrupt the payload")
                .rows_affected();
            pool.close().await;
            changed
        });
    assert_eq!(changed, 1, "the test did not actually corrupt anything");

    let core = create_core(db_url(&root)).expect("reopen core");
    core.unlock(password).expect("unlock");
    let report = core.verify().expect("verify");

    assert_eq!(report.items_ok, 0);
    assert_eq!(report.problems.len(), 1);
    assert_eq!(report.problems[0].kind, "checksum_mismatch");
    assert_eq!(report.problems[0].item_path.as_deref(), Some("secrets/one"));

    let _ = fs::remove_dir_all(&root);
}
