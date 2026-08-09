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
    core.snapshot_create(keep_one).expect("first snapshot");
    // Same-second names collide by design, so wait out the one-second
    // resolution rather than papering over it.
    std::thread::sleep(std::time::Duration::from_millis(1100));
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
