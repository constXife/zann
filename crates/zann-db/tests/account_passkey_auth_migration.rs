#![cfg(feature = "sqlite")]
use sqlx_core::{raw_sql::raw_sql, row::Row};
use sqlx_sqlite::Sqlite;
use uuid::Uuid;
use zann_db::{connect_sqlite_with_max, SqlitePool};
const MIGRATION: &str = include_str!("../migrations/0011_account_passkey_auth.sql");
async fn previous() -> (tempfile::TempDir, SqlitePool, Uuid, Uuid) {
    let root = tempfile::tempdir().unwrap();
    let pool = connect_sqlite_with_max(
        &format!("sqlite://{}", root.path().join("cache.sqlite").display()),
        1,
    )
    .await
    .unwrap();
    for sql in [
        include_str!("../migrations/0001_init.sql"),
        include_str!("../migrations/0002_sync_cursor_last_seq.sql"),
        include_str!("../migrations/0003_storage_scoped_keys.sql"),
        include_str!("../migrations/0004_server_replicas.sql"),
        include_str!("../migrations/0005_item_metadata.sql"),
        include_str!("../migrations/0006_browser_login_index.sql"),
        include_str!("../migrations/0007_account_scoped_replicas.sql"),
        include_str!("../migrations/0008_export_step_up.sql"),
        include_str!("../migrations/0009_active_item_type_index.sql"),
        include_str!("../migrations/0010_passkey_rp_index.sql"),
    ] {
        raw_sql(sql).execute(&pool).await.unwrap();
    }
    let storage = Uuid::now_v7();
    let vault = Uuid::now_v7();
    sqlx_core::query::query::<Sqlite>("INSERT INTO storages(id,kind,name,server_url,account_subject,auth_method,sync_config_repository_fp,sync_stable_target_fp,sync_config_revision,sync_config_content_fp) VALUES(?1,2,'Account','https://example.test',?2,1,zeroblob(32),zeroblob(32),zeroblob(8),zeroblob(32))").bind(storage).bind(Uuid::now_v7().to_string()).execute(&pool).await.unwrap();
    sqlx_core::query::query::<Sqlite>("INSERT INTO local_vaults(id,storage_id,name,kind,is_default,vault_key_enc,key_wrap_type,slug) VALUES(?1,?2,'Personal',1,1,?3,1,'personal')").bind(vault).bind(storage).bind(vec![7u8;72]).execute(&pool).await.unwrap();
    sqlx_core::query::query::<Sqlite>("INSERT INTO items_cache(id,storage_id,vault_id,path,name,type_id,payload_enc,checksum,version,sync_status) VALUES(?1,?2,?3,'saved','Saved','note',?4,?5,1,1)").bind(Uuid::now_v7()).bind(storage).bind(vault).bind(vec![8u8;90]).bind("a".repeat(64)).execute(&pool).await.unwrap();
    (root, pool, storage, vault)
}
async fn payload(pool: &SqlitePool) -> Vec<u8> {
    sqlx_core::query::query::<Sqlite>("SELECT payload_enc FROM items_cache")
        .fetch_one(pool)
        .await
        .unwrap()
        .get("payload_enc")
}
#[tokio::test]
async fn forward_auth_migration_preserves_ciphertext_scope_and_atomic_rollback() {
    let (_root, pool, storage, vault) = previous().await;
    let before = payload(&pool).await;
    let failing = MIGRATION.replace(
        "ALTER TABLE storages_next RENAME TO storages;",
        "SELECT * FROM _missing_rollback_tripwire;",
    );
    let mut tx = pool.begin().await.unwrap();
    assert!(raw_sql(&failing).execute(&mut *tx).await.is_err());
    tx.rollback().await.unwrap();
    assert_eq!(payload(&pool).await, before);
    let mut tx = pool.begin().await.unwrap();
    raw_sql(MIGRATION).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(payload(&pool).await, before);
    let row = sqlx_core::query::query::<Sqlite>(
        "SELECT id,sync_config_repository_fp,sync_config_revision FROM storages",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<Uuid, _>("id"), storage);
    assert_eq!(
        row.get::<Vec<u8>, _>("sync_config_repository_fp"),
        vec![0; 32]
    );
    assert_eq!(row.get::<Vec<u8>, _>("sync_config_revision"), vec![0; 8]);
    let key =
        sqlx_core::query::query::<Sqlite>("SELECT vault_key_enc FROM local_vaults WHERE id=?1")
            .bind(vault)
            .fetch_one(&pool)
            .await
            .unwrap()
            .get::<Vec<u8>, _>("vault_key_enc");
    assert_eq!(key, vec![7; 72]);
    sqlx_core::query::query::<Sqlite>("UPDATE storages SET auth_method=4 WHERE id=?1")
        .bind(storage)
        .execute(&pool)
        .await
        .unwrap();
    let saved = zann_db::local::LocalStorageRepo::new(&pool)
        .get(storage)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.auth_method, Some(zann_core::AuthMethod::Passkey));
    assert!(
        sqlx_core::query::query::<Sqlite>("UPDATE storages SET auth_method=5")
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(sqlx_core::query::query::<Sqlite>(
        "UPDATE storages SET sync_config_revision=zeroblob(9)"
    )
    .execute(&pool)
    .await
    .is_err());
    assert!(sqlx_core::query::query::<Sqlite>(
        "INSERT INTO storages(id,kind,name) VALUES(zeroblob(16),1,'Local')"
    )
    .execute(&pool)
    .await
    .is_err());
    let objects=sqlx_core::query::query::<Sqlite>("SELECT COUNT(*) AS n FROM sqlite_schema WHERE tbl_name='storages' AND type IN ('index','trigger') AND sql IS NOT NULL").fetch_one(&pool).await.unwrap().get::<i64,_>("n");
    assert_eq!(objects, 6);
}
#[tokio::test]
async fn malformed_large_headers_abort_before_rebuilding_any_storage() {
    let (_root, pool, _, _) = previous().await;
    let before = payload(&pool).await;
    sqlx_core::query::query::<Sqlite>("UPDATE storages SET server_name=zeroblob(8388608)")
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    assert!(raw_sql(MIGRATION).execute(&mut *tx).await.is_err());
    tx.rollback().await.unwrap();
    assert_eq!(payload(&pool).await, before);
    assert_eq!(
        sqlx_core::query::query::<Sqlite>("SELECT auth_method FROM storages")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get::<i32, _>("auth_method"),
        1
    );
}
