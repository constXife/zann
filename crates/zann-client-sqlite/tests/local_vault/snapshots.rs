//! Snapshots through the facade.
//!
//! A snapshot answers a different question from an export: not "how do I take
//! my data elsewhere" but "how do I get back to before this went wrong". These
//! tests pin the properties that make the answer trustworthy — the copy opens
//! as a database, it still holds the data, and taking one does not disturb the
//! vault it was taken from.

use crate::support::CanonicalTempDir;
use zann_client_sqlite::local_vault::open_vault as create_core;

use std::fs;
use std::path::PathBuf;

use uuid::Uuid;
use zann_client::app::local::{ItemsFilter, Page, Retention};

static RESTORE_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn db_url(root: &std::path::Path) -> String {
    format!("sqlite://{}", root.join("local.sqlite").display())
}

fn all_items() -> (ItemsFilter, Page) {
    (
        ItemsFilter {
            query: None,
            include_deleted: false,
        },
        Page {
            limit: 50,
            cursor: None,
        },
    )
}

#[test]
fn a_snapshot_is_a_working_copy_that_still_holds_the_data() {
    let _restore = RESTORE_TESTS
        .lock()
        .expect("serialize process-wide maintenance admission");
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    let password = format!("pw-{}", Uuid::now_v7());
    core.seed_offline_fixture(password.clone())
        .expect("initialize master password");
    core.debug_create_kv_item("secrets/api".into(), "token".into(), "s3cr3t".into())
        .expect("create item");

    let snapshot = core.snapshot_create(None).expect("snapshot");
    assert!(PathBuf::from(&snapshot.path).exists());
    assert!(snapshot.size_bytes > 0);

    // The point of a snapshot: put it somewhere fresh and find the data again.
    let restored_root = CanonicalTempDir::new();
    let restored = create_core(db_url(&restored_root)).expect("fresh device");
    let _outcome = restored
        .snapshot_restore(snapshot.path.clone())
        .expect("restore into the fresh vault");
    restored
        .unlock(password)
        .expect("unlock the restored vault");
    let (filter, page) = all_items();
    let items = restored.items_list(filter, page).expect("list items");
    assert_eq!(items.items.len(), 1, "the snapshot lost the data");
    assert_eq!(items.items[0].path, "secrets/api");
}

#[test]
fn taking_a_snapshot_leaves_the_original_usable() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    core.seed_offline_fixture(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");
    core.debug_create_kv_item("secrets/one".into(), "token".into(), "first".into())
        .expect("create item");

    core.snapshot_create(None).expect("snapshot");

    // Still writable and readable afterwards — `VACUUM INTO` must not have left
    // the pool wedged.
    core.debug_create_kv_item("secrets/two".into(), "token".into(), "second".into())
        .expect("write after snapshot");
    let (filter, page) = all_items();
    let items = core.items_list(filter, page).expect("list after snapshot");
    assert_eq!(items.items.len(), 2);
}

/// A locked vault must still be able to snapshot: the copy is encrypted either
/// way, and a client that wants one on startup has no key yet.
#[test]
fn a_locked_vault_can_still_be_snapshotted() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    core.seed_offline_fixture(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");
    core.lock().expect("lock");

    let snapshot = core.snapshot_create(None).expect("snapshot while locked");
    assert!(PathBuf::from(&snapshot.path).exists());
}

#[test]
fn listing_reports_what_was_taken() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    core.seed_offline_fixture(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");

    assert!(core.snapshot_list().expect("list").is_empty());
    let taken = core.snapshot_create(None).expect("snapshot");

    let listed = core.snapshot_list().expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].path, taken.path);
}

#[test]
fn nothing_is_due_right_after_a_snapshot() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    core.seed_offline_fixture(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");

    // Nothing taken yet, so the first call takes one.
    assert!(core
        .snapshot_create_if_due(24, None)
        .expect("first due check")
        .is_some());
    // And the second does not.
    assert!(core
        .snapshot_create_if_due(24, None)
        .expect("second due check")
        .is_none());
    assert_eq!(core.snapshot_list().expect("list").len(), 1);
}

#[test]
fn retention_bounds_how_many_are_kept() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    core.seed_offline_fixture(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");

    let keep_one = Some(Retention {
        max_count: Some(1),
        max_age_days: None,
    });
    // Two in the same second: the filename has a second's resolution, and the
    // stamp moves forward to the next free slot rather than failing.
    core.snapshot_create(keep_one).expect("first snapshot");
    core.snapshot_create(keep_one).expect("second snapshot");

    let listed = core.snapshot_list().expect("list");
    assert_eq!(listed.len(), 1, "retention did not drop the older snapshot");
}

#[test]
fn the_restore_target_is_the_live_database() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    assert_eq!(
        core.snapshot_restore_target(),
        root.join("local.sqlite").display().to_string()
    );
}

/// The point of restoring in the app: the same facade keeps working afterwards.
/// Copying the file by hand needs every client closed first, which is exactly
/// the moment a user is least able to follow instructions.
#[test]
fn restoring_brings_back_the_snapshotted_items_without_reopening() {
    let _restore = RESTORE_TESTS
        .lock()
        .expect("serialize process-wide maintenance admission");
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    let password = format!("pw-{}", Uuid::now_v7());
    core.seed_offline_fixture(password.clone())
        .expect("initialize master password");
    core.debug_create_kv_item("secrets/keep".into(), "token".into(), "kept".into())
        .expect("create item");

    let snapshot = core.snapshot_create(None).expect("snapshot");

    core.debug_create_kv_item("secrets/oops".into(), "token".into(), "mistake".into())
        .expect("create the mistake");
    let (filter, page) = all_items();
    assert_eq!(core.items_list(filter, page).expect("list").items.len(), 2);

    let outcome = core
        .snapshot_restore(snapshot.path.clone())
        .expect("restore");
    assert_eq!(outcome.restored_from, snapshot.path);
    assert!(
        PathBuf::from(&outcome.replaced_saved_to).exists(),
        "the state that was replaced was not kept"
    );

    // Restoring locks the vault: the copy may have been written under another
    // key, so the one in memory cannot be assumed to fit.
    let (filter, page) = all_items();
    assert!(
        core.items_list(filter, page).is_err(),
        "the vault was left unlocked over a database it may not match"
    );

    core.unlock(password).expect("unlock after restore");
    let (filter, page) = all_items();
    let items = core.items_list(filter, page).expect("list after restore");
    assert_eq!(items.items.len(), 1, "the restore did not take effect");
    assert_eq!(items.items[0].path, "secrets/keep");
}

/// Undoing a restore is a restore of what it displaced.
#[test]
fn a_restore_can_itself_be_undone() {
    let _restore = RESTORE_TESTS
        .lock()
        .expect("serialize process-wide maintenance admission");
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    let password = format!("pw-{}", Uuid::now_v7());
    core.seed_offline_fixture(password.clone())
        .expect("initialize master password");
    core.debug_create_kv_item("secrets/one".into(), "token".into(), "first".into())
        .expect("create item");
    let snapshot = core.snapshot_create(None).expect("snapshot");
    core.debug_create_kv_item("secrets/two".into(), "token".into(), "second".into())
        .expect("create the second item");

    let outcome = core.snapshot_restore(snapshot.path).expect("restore");
    core.unlock(password.clone()).expect("unlock after restore");
    let (filter, page) = all_items();
    assert_eq!(core.items_list(filter, page).expect("list").items.len(), 1);

    core.snapshot_restore(outcome.replaced_saved_to)
        .expect("restore the replaced state");
    core.unlock(password).expect("unlock after undo");
    let (filter, page) = all_items();
    assert_eq!(
        core.items_list(filter, page).expect("list").items.len(),
        2,
        "undoing the restore did not bring the newer state back"
    );
}

/// The salt saved beside a snapshot is read before the database moves, so a
/// damaged one is refused rather than discovered after the swap — at which point
/// the vault would be a database whose password nobody knows.
#[test]
fn a_damaged_salt_beside_a_snapshot_stops_the_restore() {
    let _restore = RESTORE_TESTS
        .lock()
        .expect("serialize process-wide maintenance admission");
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    let password = format!("pw-{}", Uuid::now_v7());
    core.seed_offline_fixture(password.clone())
        .expect("initialize master password");
    core.debug_create_kv_item("secrets/one".into(), "token".into(), "first".into())
        .expect("create item");

    let snapshot = core.snapshot_create(None).expect("snapshot");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let pool = zann_db::connect_sqlite_with_max(&format!("sqlite://{}", snapshot.path), 1)
            .await
            .expect("snapshot");
        zann_db::local::MetadataRepo::new(&pool)
            .set_value("device_keyring", "{invalid JSON")
            .await
            .expect("corrupt keyring");
        pool.close().await;
    });

    core.snapshot_restore(snapshot.path)
        .expect_err("a snapshot whose salt cannot be read must be refused");

    // Nothing moved, and the facade still has a live connection.
    core.unlock(password).expect("unlock after the refusal");
    let (filter, page) = all_items();
    assert_eq!(
        core.items_list(filter, page).expect("list").items.len(),
        1,
        "a refused restore damaged the vault"
    );
}

/// A path that is not a vault database must be refused before anything is
/// replaced, and the vault must be usable afterwards.
#[test]
fn restoring_something_that_is_not_a_vault_is_refused() {
    let _restore = RESTORE_TESTS
        .lock()
        .expect("serialize process-wide maintenance admission");
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    let password = format!("pw-{}", Uuid::now_v7());
    core.seed_offline_fixture(password.clone())
        .expect("initialize master password");
    core.debug_create_kv_item("secrets/one".into(), "token".into(), "first".into())
        .expect("create item");

    let junk = root.join("notes.txt");
    fs::write(&junk, b"not a database").expect("write junk");

    core.snapshot_restore(junk.display().to_string())
        .expect_err("a file that is not a vault must be refused");

    core.unlock(password).expect("unlock after the refusal");
    let (filter, page) = all_items();
    assert_eq!(
        core.items_list(filter, page).expect("list").items.len(),
        1,
        "a refused restore damaged the vault"
    );
}
