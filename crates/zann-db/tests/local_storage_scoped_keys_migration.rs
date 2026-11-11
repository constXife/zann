#![cfg(feature = "sqlite")]

use sqlx_core::raw_sql::raw_sql;
use sqlx_core::row::Row;
use sqlx_sqlite::Sqlite;
use uuid::Uuid;
use zann_db::{connect_sqlite_with_max, SqlitePool};

const LOCAL_STORAGE: Uuid = Uuid::nil();

async fn v2_pool() -> SqlitePool {
    let path = std::env::temp_dir().join(format!(
        "zann-storage-scoped-keys-migration-{}.sqlite",
        Uuid::now_v7().simple()
    ));
    let url = format!("sqlite://{}", path.display());
    let pool = connect_sqlite_with_max(&url, 1)
        .await
        .expect("connect v2 sqlite");
    raw_sql(include_str!("../migrations/0001_init.sql"))
        .execute(&pool)
        .await
        .expect("apply v1 schema");
    let mut tx = pool.begin().await.expect("begin v2 migration");
    raw_sql(include_str!("../migrations/0002_sync_cursor_last_seq.sql"))
        .execute(&mut *tx)
        .await
        .expect("apply v2 migration");
    tx.commit().await.expect("commit v2 migration");
    pool
}

async fn apply_v3(pool: &SqlitePool) -> Result<(), sqlx_core::Error> {
    let mut tx = pool.begin().await?;
    match raw_sql(include_str!("../migrations/0003_storage_scoped_keys.sql"))
        .execute(&mut *tx)
        .await
    {
        Ok(_) => tx.commit().await,
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

async fn insert_remote_storage(pool: &SqlitePool, storage_id: Uuid, url: &str) {
    sqlx_core::query::query::<Sqlite>(
        "INSERT INTO storages (id, kind, name, server_url) VALUES (?1, 2, 'Remote', ?2)",
    )
    .bind(storage_id)
    .bind(url)
    .execute(pool)
    .await
    .expect("insert remote storage");
}

async fn insert_vault(pool: &SqlitePool, storage_id: Uuid, vault_id: Uuid, name: &str) {
    sqlx_core::query::query::<Sqlite>(
        r#"
        INSERT INTO local_vaults (
            id, storage_id, slug, name, kind, is_default, vault_key_enc, key_wrap_type,
            cache_key_fp, last_synced_at
        )
        VALUES (?1, ?2, ?3, ?4, 1, 0, X'0102', 1, NULL, 7)
        "#,
    )
    .bind(vault_id)
    .bind(storage_id)
    .bind(format!("local::{}", vault_id.simple()))
    .bind(name)
    .execute(pool)
    .await
    .expect("insert vault");
}

async fn insert_item(
    pool: &SqlitePool,
    storage_id: Uuid,
    vault_id: Uuid,
    item_id: Uuid,
    name: &str,
) -> Result<(), sqlx_core::Error> {
    sqlx_core::query::query::<Sqlite>(
        r#"
        INSERT INTO items_cache (
            id, storage_id, vault_id, path, name, type_id, payload_enc, checksum,
            cache_key_fp, version, deleted_at, updated_at, sync_status
        )
        VALUES (?1, ?2, ?3, ?4, ?4, 'login', X'0A0B0C', 'checksum', NULL, 3, NULL, 11, 1)
        "#,
    )
    .bind(item_id)
    .bind(storage_id)
    .bind(vault_id)
    .bind(name)
    .execute(pool)
    .await
    .map(|_| ())
}

async fn insert_history(
    pool: &SqlitePool,
    storage_id: Uuid,
    vault_id: Uuid,
    item_id: Uuid,
    history_id: Uuid,
) -> Result<(), sqlx_core::Error> {
    sqlx_core::query::query::<Sqlite>(
        r#"
        INSERT INTO item_history (
            id, storage_id, vault_id, item_id, payload_enc, checksum, version,
            change_type, changed_by_email, source, sync_status, created_at
        )
        VALUES (?1, ?2, ?3, ?4, X'0D0E', 'history-checksum', 2, 2, 'user@example.test',
                2, 2, '2026-01-01T00:00:00.000Z')
        "#,
    )
    .bind(history_id)
    .bind(storage_id)
    .bind(vault_id)
    .bind(item_id)
    .execute(pool)
    .await
    .map(|_| ())
}

async fn count(pool: &SqlitePool, sql: &str) -> i64 {
    sqlx_core::query::query::<Sqlite>(sql)
        .fetch_one(pool)
        .await
        .expect("count rows")
        .try_get("count")
        .expect("decode count")
}

async fn primary_key(pool: &SqlitePool, table: &str) -> Vec<String> {
    let rows = sqlx_core::query::query::<Sqlite>(
        "SELECT name FROM pragma_table_info(?1) WHERE pk > 0 ORDER BY pk",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .expect("read primary key");
    rows.iter()
        .map(|row| row.try_get::<String, _>("name").expect("decode pk column"))
        .collect()
}

async fn vault_foreign_key(pool: &SqlitePool, table: &str) -> Vec<(String, String, String)> {
    let rows = sqlx_core::query::query::<Sqlite>(
        r#"SELECT "table" AS parent, "from" AS child, "to" AS target
           FROM pragma_foreign_key_list(?1)
           ORDER BY seq"#,
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .expect("read foreign keys");
    rows.iter()
        .map(|row| {
            (
                row.try_get("parent").expect("decode parent"),
                row.try_get("child").expect("decode child"),
                row.try_get("target").expect("decode target"),
            )
        })
        .collect()
}

#[tokio::test]
async fn migration_rekeys_a_populated_database_and_preserves_every_row() {
    let pool = v2_pool().await;
    let remote = Uuid::now_v7();
    insert_remote_storage(&pool, remote, "https://remote.example.test").await;
    let local_vault = Uuid::now_v7();
    let remote_vault = Uuid::now_v7();
    insert_vault(&pool, LOCAL_STORAGE, local_vault, "Local").await;
    insert_vault(&pool, remote, remote_vault, "Remote").await;
    let local_item = Uuid::now_v7();
    let remote_item = Uuid::now_v7();
    insert_item(&pool, LOCAL_STORAGE, local_vault, local_item, "alpha")
        .await
        .expect("insert local item");
    insert_item(&pool, remote, remote_vault, remote_item, "bravo")
        .await
        .expect("insert remote item");
    insert_history(&pool, remote, remote_vault, remote_item, Uuid::now_v7())
        .await
        .expect("insert remote history");

    apply_v3(&pool).await.expect("apply v3 migration");

    for table in ["local_vaults", "items_cache", "item_history"] {
        assert_eq!(
            primary_key(&pool, table).await,
            vec!["storage_id".to_string(), "id".to_string()],
            "{table} is keyed by (storage_id, id)"
        );
    }
    for table in ["items_cache", "item_history"] {
        assert_eq!(
            vault_foreign_key(&pool, table).await,
            vec![
                (
                    "local_vaults".to_string(),
                    "storage_id".to_string(),
                    "storage_id".to_string()
                ),
                (
                    "local_vaults".to_string(),
                    "vault_id".to_string(),
                    "id".to_string()
                ),
            ],
            "{table} references its vault by (storage_id, id)"
        );
    }
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) AS count FROM pragma_foreign_key_check"
        )
        .await,
        0
    );

    assert_eq!(
        count(&pool, "SELECT COUNT(*) AS count FROM local_vaults").await,
        2,
        "both fixture vaults survive"
    );
    let vault = sqlx_core::query::query::<Sqlite>(
        "SELECT slug, vault_key_enc, last_synced_at FROM local_vaults WHERE storage_id = ?1 AND id = ?2",
    )
    .bind(remote)
    .bind(remote_vault)
    .fetch_one(&pool)
    .await
    .expect("read migrated vault");
    assert_eq!(
        vault.try_get::<String, _>("slug").expect("decode slug"),
        format!("local::{}", remote_vault.simple())
    );
    assert_eq!(
        vault
            .try_get::<Vec<u8>, _>("vault_key_enc")
            .expect("decode envelope"),
        vec![1, 2]
    );
    assert_eq!(
        vault
            .try_get::<Option<i64>, _>("last_synced_at")
            .expect("decode sync time"),
        Some(7)
    );
    let item = sqlx_core::query::query::<Sqlite>(
        "SELECT payload_enc, version FROM items_cache WHERE storage_id = ?1 AND id = ?2",
    )
    .bind(remote)
    .bind(remote_item)
    .fetch_one(&pool)
    .await
    .expect("read migrated item");
    assert_eq!(
        item.try_get::<Vec<u8>, _>("payload_enc")
            .expect("decode payload"),
        vec![0x0a, 0x0b, 0x0c]
    );
    assert_eq!(
        item.try_get::<i64, _>("version").expect("decode version"),
        3
    );
    assert_eq!(
        count(&pool, "SELECT COUNT(*) AS count FROM item_history").await,
        1
    );

    // The external-content full-text index still resolves the copied rowids.
    let matched = sqlx_core::query::query::<Sqlite>(
        r#"SELECT items_cache.id AS id
           FROM items_cache
           JOIN items_cache_fts ON items_cache_fts.rowid = items_cache.rowid
           WHERE items_cache_fts MATCH 'bravo'"#,
    )
    .fetch_all(&pool)
    .await
    .expect("search migrated items");
    assert_eq!(matched.len(), 1);
    assert_eq!(
        matched[0].try_get::<Uuid, _>("id").expect("decode match"),
        remote_item
    );
}

#[tokio::test]
async fn migrated_schema_isolates_identical_ids_across_storages() {
    let pool = v2_pool().await;
    apply_v3(&pool).await.expect("apply v3 migration");
    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    insert_remote_storage(&pool, first, "https://first.example.test").await;
    insert_remote_storage(&pool, second, "https://second.example.test").await;
    let vault_id = Uuid::now_v7();
    let item_id = Uuid::now_v7();
    let history_id = Uuid::now_v7();
    for storage_id in [LOCAL_STORAGE, first, second] {
        insert_vault(&pool, storage_id, vault_id, "Shared id").await;
        insert_item(&pool, storage_id, vault_id, item_id, "shared")
            .await
            .expect("same item id in another storage");
        insert_history(&pool, storage_id, vault_id, item_id, history_id)
            .await
            .expect("same history id in another storage");
    }

    sqlx_core::query::query::<Sqlite>("DELETE FROM local_vaults WHERE storage_id = ?1 AND id = ?2")
        .bind(first)
        .bind(vault_id)
        .execute(&pool)
        .await
        .expect("delete one storage's vault");

    for (storage_id, expected) in [(LOCAL_STORAGE, 1), (first, 0), (second, 1)] {
        for table in ["items_cache", "item_history"] {
            let present: i64 = sqlx_core::query::query::<Sqlite>(&format!(
                "SELECT COUNT(*) AS count FROM {table} WHERE storage_id = ?1"
            ))
            .bind(storage_id)
            .fetch_one(&pool)
            .await
            .expect("count storage rows")
            .try_get("count")
            .expect("decode count");
            assert_eq!(
                present, expected,
                "the cascade stays inside one storage ({table})"
            );
        }
    }
}

#[tokio::test]
async fn migration_rejects_a_child_row_referencing_another_storages_vault() {
    for child in ["item", "history"] {
        let pool = v2_pool().await;
        let remote = Uuid::now_v7();
        insert_remote_storage(&pool, remote, "https://remote.example.test").await;
        let vault_id = Uuid::now_v7();
        insert_vault(&pool, LOCAL_STORAGE, vault_id, "Local").await;
        let inserted = match child {
            "item" => insert_item(&pool, remote, vault_id, Uuid::now_v7(), "foreign").await,
            _ => insert_history(&pool, remote, vault_id, Uuid::now_v7(), Uuid::now_v7()).await,
        };
        inserted.expect("the v2 foreign key is not storage-scoped");

        assert!(
            apply_v3(&pool).await.is_err(),
            "a cross-storage {child} reference must abort the migration"
        );
        assert_eq!(
            primary_key(&pool, "items_cache").await,
            vec!["id".to_string()],
            "the failed migration is transactional"
        );
    }
}
