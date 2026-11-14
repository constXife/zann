#![cfg(feature = "sqlite")]

use sqlx_core::{raw_sql::raw_sql, row::Row};
use sqlx_sqlite::Sqlite;
use uuid::Uuid;
use zann_db::{connect_sqlite_with_max, migrate_local, SqlitePool};

async fn legacy_pool() -> (tempfile::TempDir, SqlitePool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite://{}", dir.path().join("cache.sqlite").display());
    let pool = connect_sqlite_with_max(&url, 1).await.expect("pool");
    for sql in [
        include_str!("../migrations/0001_init.sql"),
        include_str!("../migrations/0002_sync_cursor_last_seq.sql"),
        include_str!("../migrations/0003_storage_scoped_keys.sql"),
    ] {
        raw_sql(sql).execute(&pool).await.expect("legacy schema");
    }
    (dir, pool)
}

async fn cutover(pool: &SqlitePool) -> Result<(), sqlx_core::Error> {
    let mut tx = pool.begin().await?;
    raw_sql(include_str!("../migrations/0004_server_replicas.sql"))
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

async fn storage_count(pool: &SqlitePool) -> i64 {
    sqlx_core::query::query::<Sqlite>("SELECT COUNT(*) AS n FROM storages")
        .fetch_one(pool)
        .await
        .expect("count")
        .get("n")
}

#[tokio::test]
async fn fresh_databases_have_no_phantom_storage_and_migration_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite://{}", dir.path().join("cache.sqlite").display());
    let pool = connect_sqlite_with_max(&url, 1).await.expect("pool");
    migrate_local(&pool).await.expect("migrate");
    migrate_local(&pool).await.expect("already migrated");
    assert_eq!(storage_count(&pool).await, 0);
    assert!(sqlx_core::query::query::<Sqlite>(
        "INSERT INTO storages (id, kind, name) VALUES (zeroblob(16), 1, 'Local')"
    )
    .execute(&pool)
    .await
    .is_err());
}

#[tokio::test]
async fn empty_legacy_local_rows_are_removed_and_remote_rows_survive() {
    let (_dir, pool) = legacy_pool().await;
    let remote = Uuid::now_v7();
    sqlx_core::query::query::<Sqlite>(
        "INSERT INTO storages (id, kind, name, server_url) VALUES (?1, 2, 'Remote', 'https://server.example.test')"
    ).bind(remote).execute(&pool).await.expect("remote");
    cutover(&pool).await.expect("cutover");
    assert_eq!(storage_count(&pool).await, 1);
    assert!(zann_db::local::LocalStorageRepo::new(&pool)
        .get(remote)
        .await
        .expect("remote")
        .is_some());
}

#[tokio::test]
async fn legacy_local_vaults_abort_without_losing_encrypted_data() {
    for storage in [Uuid::nil(), Uuid::from_u128(42)] {
        let (_dir, pool) = legacy_pool().await;
        if !storage.is_nil() {
            sqlx_core::query::query::<Sqlite>(
                "INSERT INTO storages (id, kind, name) VALUES (?1, 1, 'Old local')",
            )
            .bind(storage)
            .execute(&pool)
            .await
            .expect("legacy local");
        }
        let vault = Uuid::now_v7();
        let envelope = vec![7u8; 72];
        sqlx_core::query::query::<Sqlite>(
            "INSERT INTO local_vaults (id, storage_id, name, kind, is_default, vault_key_enc, key_wrap_type, slug) VALUES (?1, ?2, 'Personal', 1, 1, ?3, 1, 'personal')"
        ).bind(vault).bind(storage).bind(&envelope).execute(&pool).await.expect("legacy vault");
        let error = cutover(&pool).await.expect_err("export old data first");
        assert!(error
            .to_string()
            .contains("legacy_local_data_requires_export"));
        let row = sqlx_core::query::query::<Sqlite>(
            "SELECT vault_key_enc FROM local_vaults WHERE id = ?1",
        )
        .bind(vault)
        .fetch_one(&pool)
        .await
        .expect("vault preserved");
        assert_eq!(row.get::<Vec<u8>, _>("vault_key_enc"), envelope);
        assert!(storage_count(&pool).await >= 1);
        // A second attempt fails identically; the failed transaction leaves no guard table.
        assert!(cutover(&pool).await.is_err());
    }
}

#[tokio::test]
async fn remote_ciphertext_and_pending_changes_survive_the_cutover() {
    use zann_core::{StorageKind, VaultKind};
    use zann_crypto::{crypto::SecretKey, vault_crypto};
    use zann_db::local::{
        KeyWrapType, LocalItemRepo, LocalStorage, LocalStorageRepo, LocalVault, LocalVaultRepo,
        PendingChangeRepo,
    };
    let (_dir, pool) = legacy_pool().await;
    let storage_id = Uuid::now_v7();
    LocalStorageRepo::new(&pool)
        .upsert(&LocalStorage {
            id: storage_id,
            kind: StorageKind::Remote,
            name: "Remote".into(),
            server_url: Some("https://replica.example.test".into()),
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: true,
            auth_method: None,
        })
        .await
        .expect("remote storage");
    let master = SecretKey::generate();
    let vault_key = SecretKey::generate();
    let vault_id = Uuid::now_v7();
    LocalVaultRepo::new(&pool)
        .create(&LocalVault {
            id: vault_id,
            storage_id,
            slug: "personal".into(),
            name: "Personal".into(),
            kind: VaultKind::Personal,
            is_default: true,
            vault_key_enc: vault_crypto::encrypt_vault_key(&master, vault_id, &vault_key)
                .expect("wrap"),
            key_wrap_type: KeyWrapType::Master,
            cache_key_fp: None,
            last_synced_at: None,
        })
        .await
        .expect("vault");
    let item = Uuid::now_v7();
    let ciphertext = zann_crypto::encrypt_payload(
        &vault_key,
        vault_id,
        item,
        &zann_core::EncryptedPayload::new("note"),
    )
    .expect("encrypt old item");
    let checksum = zann_crypto::payload_checksum(&ciphertext);
    sqlx_core::query::query::<Sqlite>("INSERT INTO items_cache (id,storage_id,vault_id,path,name,type_id,payload_enc,checksum,version,updated_at,sync_status) VALUES (?1,?2,?3,'offline/note','note','note',?4,?5,1,?6,2)")
        .bind(item).bind(storage_id).bind(vault_id).bind(&ciphertext).bind(&checksum).bind(chrono::Utc::now()).execute(&pool).await.expect("legacy item");
    sqlx_core::query::query::<Sqlite>("INSERT INTO pending_changes (id,storage_id,vault_id,item_id,operation,payload_enc,checksum,path,name,type_id,created_at) VALUES (?1,?2,?3,?4,1,?5,?6,'offline/note','note','note',?7)")
        .bind(Uuid::now_v7()).bind(storage_id).bind(vault_id).bind(item).bind(&ciphertext).bind(checksum).bind(chrono::Utc::now()).execute(&pool).await.expect("legacy pending edit");
    cutover(&pool).await.expect("cutover");
    raw_sql(include_str!("../migrations/0005_item_metadata.sql"))
        .execute(&pool)
        .await
        .expect("metadata migration");
    assert!(
        LocalItemRepo::new(&pool)
            .get_by_id(storage_id, item)
            .await
            .unwrap()
            .unwrap()
            .metadata
            .is_none(),
        "old attributes remain unknown rather than fabricated"
    );
    assert!(PendingChangeRepo::new(&pool)
        .list_by_storage_vault(storage_id, vault_id)
        .await
        .unwrap()[0]
        .metadata
        .is_none());
    assert_eq!(
        LocalItemRepo::new(&pool)
            .get_by_id(storage_id, item)
            .await
            .expect("read")
            .expect("item")
            .payload_enc,
        ciphertext
    );
    assert_eq!(
        PendingChangeRepo::new(&pool)
            .count_by_storage(storage_id)
            .await
            .expect("pending"),
        1
    );
    assert_eq!(storage_count(&pool).await, 1);
}

#[tokio::test]
async fn orphaned_legacy_pending_changes_also_block_the_cutover() {
    let (_dir, pool) = legacy_pool().await;
    sqlx_core::query::query::<Sqlite>(
        "INSERT INTO pending_changes (id, storage_id, vault_id, item_id, operation) VALUES (?1, zeroblob(16), ?2, ?3, 3)"
    ).bind(Uuid::now_v7()).bind(Uuid::now_v7()).bind(Uuid::now_v7()).execute(&pool).await.expect("legacy pending");
    assert!(cutover(&pool).await.is_err());
    let count: i64 = sqlx_core::query::query::<Sqlite>("SELECT COUNT(*) AS n FROM pending_changes")
        .fetch_one(&pool)
        .await
        .expect("preserved pending")
        .get("n");
    assert_eq!(count, 1);
    assert_eq!(storage_count(&pool).await, 1);
}
