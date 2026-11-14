#![cfg(feature = "sqlite")]
use sqlx_core::{query::query, query_scalar::query_scalar};
#[tokio::test]
async fn every_pinned_connection_rejects_writes_after_logical_identity_rotation() {
    let dir = tempfile::tempdir().expect("root");
    let root = dir.path().canonicalize().expect("canonical path");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root");
    }
    let path = root.join("local.sqlite");
    let location = zann_db::SqliteFileLocation::from_path(&path).expect("location");
    let maintenance = zann_db::connect_sqlite_file_with_max(&location, 2)
        .await
        .expect("maintenance");
    zann_db::migrate_local(&maintenance)
        .await
        .expect("migrations");
    let pinned = zann_db::open_existing_sqlite_with_max(&path, 2)
        .await
        .expect("pinned");
    let mut first = pinned
        .pool()
        .acquire()
        .await
        .expect("hold existing connection");
    query("UPDATE local_database_identity SET instance_uuid = ? WHERE singleton = 1")
        .bind(uuid::Uuid::now_v7().as_bytes().as_slice())
        .execute(&maintenance)
        .await
        .expect("explicit maintenance");
    for table in [
        "storages",
        "local_vaults",
        "items_cache",
        "pending_changes",
        "item_history",
        "sync_cursors",
        "metadata",
        "local_database_identity",
    ] {
        let sql = format!("INSERT INTO {table} DEFAULT VALUES");
        let original = query(&sql)
            .execute(&mut *first)
            .await
            .expect_err("old connection rejects");
        assert!(
            original
                .to_string()
                .contains("local database instance changed"),
            "{table}: {original}"
        );
        let reopened = query(&sql)
            .execute(pinned.pool())
            .await
            .expect_err("new connection in old pool rejects");
        assert!(
            reopened
                .to_string()
                .contains("local database instance changed"),
            "{table}: {reopened}"
        );
    }
    assert!(pinned.verify_identity().await.is_err());
    let fresh = zann_db::open_existing_sqlite(&path)
        .await
        .expect("new pool adopts explicit new identity");
    query("INSERT INTO metadata(key,value) VALUES ('fresh','yes')")
        .execute(fresh.pool())
        .await
        .expect("fresh write");
    let snapshot = root.join("snapshot.sqlite");
    zann_db::local::maintenance::snapshot_into(&maintenance, &snapshot)
        .await
        .expect("snapshot");
    let triggers: i64 = query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'zann_pin_%'",
    )
    .fetch_one(&maintenance)
    .await
    .expect("persistent schema");
    assert_eq!(triggers, 0);
}
