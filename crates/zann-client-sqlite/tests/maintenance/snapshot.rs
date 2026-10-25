use super::*;
use uuid::Uuid;

fn temp_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!("zann-snapshot-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root).expect("create temp root");
    root
}

async fn seeded_pool(root: &Path) -> SqlitePool {
    let url = format!("sqlite://{}", root.join("local.sqlite").display());
    let pool = zann_db::connect_sqlite_with_max(&url, 2)
        .await
        .expect("connect");
    zann_db::migrate_local(&pool).await.expect("migrate");
    pool
}

fn touch(root: &Path, name: &str) {
    let dir = snapshots_dir(root);
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::write(dir.join(name), b"x").expect("write");
}

#[tokio::test]
async fn creates_a_readable_copy_of_the_database() {
    let root = temp_root();
    let pool = seeded_pool(&root).await;

    let snapshot = create(&pool, &root, &RetentionPolicy::default())
        .await
        .expect("snapshot");

    assert!(snapshot.path.exists(), "no file at the reported path");
    assert!(snapshot.size_bytes > 0, "snapshot is empty");

    // The copy has to be a working database, not just bytes on disk.
    let url = format!("sqlite://{}", snapshot.path.display());
    let copy = zann_db::connect_sqlite_with_max(&url, 1)
        .await
        .expect("open the snapshot");
    copy.close().await;

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn listing_a_vault_with_no_snapshots_is_empty_not_an_error() {
    let root = temp_root();
    assert!(list(&root).expect("list").is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn lists_newest_first_and_ignores_foreign_files() {
    let root = temp_root();
    touch(&root, "local-20260101-000000.sqlite");
    touch(&root, "local-20260601-120000.sqlite");
    touch(&root, "notes.txt");
    touch(&root, "local-nonsense.sqlite");

    let found = list(&root).expect("list");
    assert_eq!(found.len(), 2, "foreign files must not be listed");
    assert!(found[0].created_at.starts_with("2026-06-01"));
    assert!(found[1].created_at.starts_with("2026-01-01"));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn retention_keeps_the_newest_and_drops_the_rest() {
    let root = temp_root();
    for day in 1..=5 {
        touch(&root, &format!("local-202606{day:02}-120000.sqlite"));
    }

    let removed = prune(
        &root,
        &RetentionPolicy {
            max_count: Some(2),
            max_age_days: None,
        },
    )
    .expect("prune");

    assert_eq!(removed.len(), 3);
    let left = list(&root).expect("list");
    assert_eq!(left.len(), 2);
    assert!(left[0].created_at.starts_with("2026-06-05"));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn retention_drops_whatever_has_aged_out() {
    let root = temp_root();
    let old = chrono::Utc::now() - chrono::Duration::days(90);
    touch(&root, &format!("local-{}.sqlite", old.format(STAMP)));
    let fresh = chrono::Utc::now();
    touch(&root, &format!("local-{}.sqlite", fresh.format(STAMP)));

    let removed = prune(
        &root,
        &RetentionPolicy {
            max_count: None,
            max_age_days: Some(30),
        },
    )
    .expect("prune");

    assert_eq!(removed.len(), 1, "only the aged-out snapshot goes");
    assert_eq!(list(&root).expect("list").len(), 1);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_vault_with_no_snapshots_is_always_due() {
    let root = temp_root();
    assert!(is_due(&root, Duration::from_secs(3600)));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn a_recent_snapshot_means_nothing_is_due() {
    let root = temp_root();
    let pool = seeded_pool(&root).await;
    create(&pool, &root, &RetentionPolicy::default())
        .await
        .expect("snapshot");

    assert!(!is_due(&root, Duration::from_secs(3600)));
    assert!(
        create_if_due(
            &pool,
            &root,
            Duration::from_secs(3600),
            &RetentionPolicy::default()
        )
        .await
        .expect("create_if_due")
        .is_none(),
        "a second snapshot was taken while one was still fresh"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Marker rows, so a restore can be seen to have actually moved the data
/// back rather than just moved a file. The storage the migration creates is
/// filtered out — only what a test added is of interest.
async fn storage_names(pool: &SqlitePool) -> Vec<String> {
    let mut names = zann_db::local::LocalStorageRepo::new(pool)
        .list()
        .await
        .expect("list storages")
        .into_iter()
        .map(|storage| storage.name)
        .filter(|name| name == "before" || name == "after" || name == "live")
        .collect::<Vec<_>>();
    names.sort();
    names
}

async fn add_storage(pool: &SqlitePool, name: &str) {
    zann_db::local::LocalStorageRepo::new(pool)
        .upsert(&zann_db::local::LocalStorage {
            id: Uuid::now_v7(),
            kind: zann_core::StorageKind::Remote,
            name: name.to_string(),
            server_url: Some(format!("https://{name}.snapshot.test")),
            server_name: Some(format!("Snapshot {name}")),
            server_fingerprint: Some(format!("snapshot-fingerprint-{name}")),
            account_subject: Some(format!("snapshot-account-{name}")),
            personal_vaults_enabled: true,
            auth_method: Some(zann_core::AuthMethod::Password),
        })
        .await
        .expect("add storage");
}

async fn reopen(root: &Path) -> SqlitePool {
    let url = format!("sqlite://{}", root.join("local.sqlite").display());
    zann_db::connect_sqlite_with_max(&url, 2)
        .await
        .expect("reopen")
}

#[tokio::test]
async fn restoring_puts_the_snapshotted_rows_back() {
    let root = temp_root();
    let pool = seeded_pool(&root).await;
    add_storage(&pool, "before").await;

    let snapshot = create(&pool, &root, &RetentionPolicy::default())
        .await
        .expect("snapshot");

    add_storage(&pool, "after").await;
    assert_eq!(storage_names(&pool).await.len(), 2);

    restore(pool, &root, &snapshot.path).await.expect("restore");

    let pool = reopen(&root).await;
    assert_eq!(
        storage_names(&pool).await,
        vec!["before".to_string()],
        "the restored database is not the snapshotted one"
    );
    pool.close().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// A restore is itself reversible: what it replaced is kept as a snapshot.
#[tokio::test]
async fn restoring_keeps_what_it_replaced() {
    let root = temp_root();
    let pool = seeded_pool(&root).await;
    add_storage(&pool, "before").await;
    let snapshot = create(&pool, &root, &RetentionPolicy::default())
        .await
        .expect("snapshot");
    add_storage(&pool, "after").await;

    let outcome = restore(pool, &root, &snapshot.path).await.expect("restore");

    assert!(
        outcome.replaced_saved_to.exists(),
        "the replaced database was not kept"
    );
    let url = format!("sqlite://{}", outcome.replaced_saved_to.display());
    let kept = zann_db::connect_sqlite_with_max(&url, 1)
        .await
        .expect("open the kept copy");
    assert_eq!(
        storage_names(&kept).await,
        vec!["after".to_string(), "before".to_string()],
        "the kept copy is not the state that was replaced"
    );
    kept.close().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// Restoring must not leave the write-ahead log of the database it
/// replaced: SQLite would replay it on the next open and undo the restore.
#[tokio::test]
async fn restoring_clears_the_write_ahead_log() {
    let root = temp_root();
    let pool = seeded_pool(&root).await;
    add_storage(&pool, "before").await;
    let snapshot = create(&pool, &root, &RetentionPolicy::default())
        .await
        .expect("snapshot");
    add_storage(&pool, "after").await;

    restore(pool, &root, &snapshot.path).await.expect("restore");

    assert!(
        !root.join("local.sqlite-wal").exists(),
        "a stale write-ahead log was left beside the restored database"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn the_kdf_salt_comes_back_with_the_snapshot() {
    let root = temp_root();
    std::fs::write(
        root.join("config.json"),
        r#"{"identity":{"kdf_salt":"old"},"refresh_token":"secret"}"#,
    )
    .expect("write config");
    let pool = seeded_pool(&root).await;
    let snapshot = create(&pool, &root, &RetentionPolicy::default())
        .await
        .expect("snapshot");

    // The vault is re-initialised: a new salt, and the old one now only
    // exists beside the snapshot.
    std::fs::write(
        root.join("config.json"),
        r#"{"identity":{"kdf_salt":"new"},"refresh_token":"secret"}"#,
    )
    .expect("rewrite config");

    let outcome = restore(pool, &root, &snapshot.path).await.expect("restore");

    assert!(outcome.identity_replaced, "the salt was not restored");
    let config: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("config.json")).expect("read identity"),
    )
    .expect("config json");
    assert_eq!(
        config["identity"]["kdf_salt"], "old",
        "the restored database cannot be opened: its salt was not put back"
    );
    assert_eq!(
        config["refresh_token"], "secret",
        "restoring the salt clobbered the rest of the config"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn a_file_that_is_not_a_vault_is_refused() {
    let root = temp_root();
    let pool = seeded_pool(&root).await;
    add_storage(&pool, "live").await;

    let stranger = root.join("stranger.sqlite");
    let url = format!("sqlite://{}", stranger.display());
    let other = zann_db::connect_sqlite_with_max(&url, 1)
        .await
        .expect("create stranger");
    other.close().await;

    let err = restore(pool, &root, &stranger)
        .await
        .expect_err("a foreign database must be refused");
    assert_eq!(err.kind, "snapshot_not_a_vault");

    // Nothing was touched, so the live database still opens and still has
    // its rows.
    let pool = reopen(&root).await;
    assert_eq!(storage_names(&pool).await, vec!["live".to_string()]);
    pool.close().await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn a_missing_snapshot_is_refused() {
    let root = temp_root();
    let pool = seeded_pool(&root).await;

    let err = restore(pool, &root, &root.join("nope.sqlite"))
        .await
        .expect_err("a missing file must be refused");
    assert_eq!(err.kind, "snapshot_not_found");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn restoring_the_live_database_over_itself_is_refused() {
    let root = temp_root();
    let pool = seeded_pool(&root).await;

    let err = restore(pool, &root, &restore_target(&root))
        .await
        .expect_err("the live database is not a snapshot");
    assert_eq!(err.kind, "snapshot_is_live_database");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn a_stale_snapshot_makes_one_due_again() {
    let root = temp_root();
    let pool = seeded_pool(&root).await;
    let old = chrono::Utc::now() - chrono::Duration::days(2);
    touch(&root, &format!("local-{}.sqlite", old.format(STAMP)));

    let taken = create_if_due(
        &pool,
        &root,
        Duration::from_secs(24 * 3600),
        &RetentionPolicy::default(),
    )
    .await
    .expect("create_if_due");

    assert!(taken.is_some(), "a day-old snapshot should be due");
    let _ = std::fs::remove_dir_all(&root);
}
