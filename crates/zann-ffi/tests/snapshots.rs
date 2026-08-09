//! Snapshots through the facade.
//!
//! A snapshot answers a different question from an export: not "how do I take
//! my data elsewhere" but "how do I get back to before this went wrong". These
//! tests pin the properties that make the answer trustworthy — the copy opens
//! as a database, it still holds the data, and taking one does not disturb the
//! vault it was taken from.

use std::fs;
use std::path::PathBuf;

use uuid::Uuid;
use zann_ffi::{create_core, ItemsFilter, Page, RetentionFfi};

fn temp_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("zann-ffi-snap-{}-{}", tag, Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create temp dir");
    root
}

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
    let root = temp_root("copy");
    let core = create_core(db_url(&root)).expect("create core");
    let password = format!("pw-{}", Uuid::now_v7());
    core.initialize_master_password(password.clone())
        .expect("initialize master password");
    core.debug_create_kv_item("secrets/api".into(), "token".into(), "s3cr3t".into())
        .expect("create item");

    let snapshot = core.snapshot_create(None).expect("snapshot");
    assert!(PathBuf::from(&snapshot.path).exists());
    assert!(snapshot.size_bytes > 0);

    // The point of a snapshot: put it somewhere fresh and find the data again.
    // The salt travels with it — without that the copy is unopenable, which is
    // the whole reason `identity_path` exists.
    let restored_root = temp_root("restored");
    let restored_db = restored_root.join("local.sqlite");
    fs::copy(&snapshot.path, &restored_db).expect("copy snapshot into place");

    let identity_path = snapshot
        .identity_path
        .as_ref()
        .expect("a snapshot of an initialised vault must carry its salt");
    let identity: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(identity_path).expect("read identity"))
            .expect("parse identity");
    fs::write(
        restored_root.join("config.json"),
        serde_json::to_string_pretty(&serde_json::json!({ "identity": identity }))
            .expect("render config"),
    )
    .expect("write config");

    let restored = create_core(format!("sqlite://{}", restored_db.display()))
        .expect("open the restored vault");
    restored
        .unlock(password)
        .expect("unlock the restored vault");
    let (filter, page) = all_items();
    let items = restored.items_list(filter, page).expect("list items");
    assert_eq!(items.items.len(), 1, "the snapshot lost the data");
    assert_eq!(items.items[0].path, "secrets/api");

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&restored_root);
}

#[test]
fn taking_a_snapshot_leaves_the_original_usable() {
    let root = temp_root("live");
    let core = create_core(db_url(&root)).expect("create core");
    core.initialize_master_password(format!("pw-{}", Uuid::now_v7()))
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

    let _ = fs::remove_dir_all(&root);
}

/// A locked vault must still be able to snapshot: the copy is encrypted either
/// way, and a client that wants one on startup has no key yet.
#[test]
fn a_locked_vault_can_still_be_snapshotted() {
    let root = temp_root("locked");
    let core = create_core(db_url(&root)).expect("create core");
    core.initialize_master_password(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");
    core.lock().expect("lock");

    let snapshot = core.snapshot_create(None).expect("snapshot while locked");
    assert!(PathBuf::from(&snapshot.path).exists());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn listing_reports_what_was_taken() {
    let root = temp_root("list");
    let core = create_core(db_url(&root)).expect("create core");
    core.initialize_master_password(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");

    assert!(core.snapshot_list().expect("list").is_empty());
    let taken = core.snapshot_create(None).expect("snapshot");

    let listed = core.snapshot_list().expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].path, taken.path);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn nothing_is_due_right_after_a_snapshot() {
    let root = temp_root("due");
    let core = create_core(db_url(&root)).expect("create core");
    core.initialize_master_password(format!("pw-{}", Uuid::now_v7()))
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

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn retention_bounds_how_many_are_kept() {
    let root = temp_root("retention");
    let core = create_core(db_url(&root)).expect("create core");
    core.initialize_master_password(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");

    let keep_one = Some(RetentionFfi {
        max_count: Some(1),
        max_age_days: None,
    });
    // Two in the same second: the filename has a second's resolution, and the
    // stamp moves forward to the next free slot rather than failing.
    core.snapshot_create(keep_one).expect("first snapshot");
    core.snapshot_create(keep_one).expect("second snapshot");

    let listed = core.snapshot_list().expect("list");
    assert_eq!(listed.len(), 1, "retention did not drop the older snapshot");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_restore_target_is_the_live_database() {
    let root = temp_root("target");
    let core = create_core(db_url(&root)).expect("create core");
    assert_eq!(
        core.snapshot_restore_target(),
        root.join("local.sqlite").display().to_string()
    );
    let _ = fs::remove_dir_all(&root);
}

/// The point of restoring in the app: the same facade keeps working afterwards.
/// Copying the file by hand needs every client closed first, which is exactly
/// the moment a user is least able to follow instructions.
#[test]
fn restoring_brings_back_the_snapshotted_items_without_reopening() {
    let root = temp_root("restore");
    let core = create_core(db_url(&root)).expect("create core");
    let password = format!("pw-{}", Uuid::now_v7());
    core.initialize_master_password(password.clone())
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

    let _ = fs::remove_dir_all(&root);
}

/// Undoing a restore is a restore of what it displaced.
#[test]
fn a_restore_can_itself_be_undone() {
    let root = temp_root("undo");
    let core = create_core(db_url(&root)).expect("create core");
    let password = format!("pw-{}", Uuid::now_v7());
    core.initialize_master_password(password.clone())
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

    let _ = fs::remove_dir_all(&root);
}

/// The salt saved beside a snapshot is read before the database moves, so a
/// damaged one is refused rather than discovered after the swap — at which point
/// the vault would be a database whose password nobody knows.
#[test]
fn a_damaged_salt_beside_a_snapshot_stops_the_restore() {
    let root = temp_root("badsalt");
    let core = create_core(db_url(&root)).expect("create core");
    let password = format!("pw-{}", Uuid::now_v7());
    core.initialize_master_password(password.clone())
        .expect("initialize master password");
    core.debug_create_kv_item("secrets/one".into(), "token".into(), "first".into())
        .expect("create item");

    let snapshot = core.snapshot_create(None).expect("snapshot");
    let identity_path = snapshot
        .identity_path
        .as_ref()
        .expect("a snapshot of an initialised vault carries its salt");
    fs::write(identity_path, b"{ this is not json").expect("damage the salt");

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

    let _ = fs::remove_dir_all(&root);
}

/// A path that is not a vault database must be refused before anything is
/// replaced, and the vault must be usable afterwards.
#[test]
fn restoring_something_that_is_not_a_vault_is_refused() {
    let root = temp_root("foreign");
    let core = create_core(db_url(&root)).expect("create core");
    let password = format!("pw-{}", Uuid::now_v7());
    core.initialize_master_password(password.clone())
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

    let _ = fs::remove_dir_all(&root);
}
