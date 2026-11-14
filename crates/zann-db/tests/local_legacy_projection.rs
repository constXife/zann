#![cfg(feature = "sqlite")]
//! MIG-009: a remote vault that predates migration 0002 keeps the projection
//! its legacy client synced under the internal `local::<id>` slug and no bound
//! key. The first authorized catalog claims it in place, adopting the
//! catalog's slug and key, only when every cached item proves that key.

use chrono::Utc;
use sqlx_core::row::Row;
use sqlx_sqlite::Sqlite;
use uuid::Uuid;
use zann_core::{AuthMethod, ChangeType, StorageKind, SyncStatus, VaultKind};
use zann_db::local::{
    CacheKeyFingerprintBinding, KeyWrapType, LocalItem, LocalPendingChange, LocalStorage,
    LocalStorageProof, LocalStorageRepo, LocalSyncGenerationProof, LocalVault,
    LocalVaultKeyBindError, LocalVaultRepo,
};
use zann_db::local::{LocalItemRepo, PendingChangeRepo, SyncCursorRepo};
use zann_db::{connect_sqlite_path_with_max, migrate_local, SqlitePool};

const CACHE_FP: &str = "001122aabbcc";
const OTHER_FP: &str = "ffeeddccbbaa";
const CATALOG_SLUG: &str = "personal";

struct Legacy {
    pool: SqlitePool,
    storage: LocalStorage,
    vault: LocalVault,
}

async fn legacy(item_fingerprints: &[&str]) -> Legacy {
    let path = std::env::temp_dir().join(format!(
        "zann-legacy-projection-{}.sqlite",
        Uuid::now_v7().simple()
    ));
    let pool = connect_sqlite_path_with_max(&path, 1)
        .await
        .expect("connect SQLite fixture");
    migrate_local(&pool).await.expect("migrate SQLite fixture");
    let storage = LocalStorage {
        id: Uuid::now_v7(),
        kind: StorageKind::Remote,
        name: "Legacy".to_string(),
        server_url: Some("https://legacy.example".to_string()),
        server_name: None,
        server_fingerprint: Some("server-fingerprint".to_string()),
        account_subject: Some(Uuid::now_v7().to_string()),
        personal_vaults_enabled: true,
        auth_method: Some(AuthMethod::Password),
    };
    LocalStorageRepo::new(&pool)
        .upsert(&storage)
        .await
        .expect("insert legacy storage");
    let id = Uuid::now_v7();
    let vault = LocalVault {
        id,
        storage_id: storage.id,
        slug: LocalVault::local_slug(id),
        name: "Personal".to_string(),
        kind: VaultKind::Personal,
        is_default: false,
        vault_key_enc: vec![7, 8, 9],
        key_wrap_type: KeyWrapType::RemoteStrict,
        cache_key_fp: None,
        last_synced_at: None,
    };
    LocalVaultRepo::new(&pool)
        .create(&vault)
        .await
        .expect("insert legacy vault");
    for (index, fingerprint) in item_fingerprints.iter().enumerate() {
        let item = LocalItem {
            metadata: Some(Default::default()),
            id: Uuid::now_v7(),
            storage_id: storage.id,
            vault_id: vault.id,
            path: format!("legacy/item-{index}"),
            name: format!("item-{index}"),
            type_id: "login".to_string(),
            payload_enc: vec![1, 2, 3],
            checksum: blake3::hash(format!("item-{index}").as_bytes())
                .to_hex()
                .to_string(),
            cache_key_fp: Some((*fingerprint).to_string()),
            version: 1,
            deleted_at: None,
            updated_at: Utc::now(),
            sync_status: SyncStatus::Modified,
        };
        LocalItemRepo::new(&pool)
            .create(&item)
            .await
            .expect("insert legacy item");
        PendingChangeRepo::new(&pool)
            .create(&LocalPendingChange {
                metadata: Some(Default::default()),
                id: Uuid::now_v7(),
                storage_id: storage.id,
                vault_id: vault.id,
                item_id: item.id,
                operation: ChangeType::Create,
                payload_enc: Some(item.payload_enc.clone()),
                checksum: Some(item.checksum.clone()),
                path: Some(item.path.clone()),
                name: Some(item.name.clone()),
                type_id: Some(item.type_id.clone()),
                base_seq: None,
                created_at: Utc::now(),
            })
            .await
            .expect("insert legacy pending create");
    }
    Legacy {
        pool,
        storage,
        vault,
    }
}

fn catalog(vault: &LocalVault) -> CacheKeyFingerprintBinding<'_> {
    CacheKeyFingerprintBinding {
        storage_id: vault.storage_id,
        vault_id: vault.id,
        expected_slug: CATALOG_SLUG,
        expected_name: &vault.name,
        expected_kind: vault.kind,
        expected_is_default: vault.is_default,
        expected_vault_key_enc: &vault.vault_key_enc,
        expected_key_wrap_type: vault.key_wrap_type,
        target_cache_key_fp: CACHE_FP,
    }
}

async fn claim(legacy: &Legacy) -> Result<(), LocalVaultKeyBindError> {
    LocalVaultRepo::new(&legacy.pool)
        .bind_cache_key_fingerprints_leased(
            &LocalStorageProof::try_from(&legacy.storage).expect("storage proof"),
            &LocalSyncGenerationProof::new([0x11; 32], [0x22; 32], 1, [0x33; 32]),
            &[catalog(&legacy.vault)],
        )
        .await
        .map(|_| ())
}

/// The vault row's slug and key, and whether the storage is claimed.
async fn state(legacy: &Legacy) -> (String, Option<String>, bool) {
    let row = sqlx_core::query::query::<Sqlite>(
        r#"
        SELECT local_vaults.slug, local_vaults.cache_key_fp,
               storages.sync_config_repository_fp IS NOT NULL AS claimed
        FROM local_vaults JOIN storages ON storages.id = local_vaults.storage_id
        WHERE local_vaults.id = ?1
        "#,
    )
    .bind(legacy.vault.id)
    .fetch_one(&legacy.pool)
    .await
    .expect("read vault state");
    (
        row.try_get("slug").expect("slug"),
        row.try_get("cache_key_fp").expect("fingerprint"),
        row.try_get::<i64, _>("claimed").expect("claimed") == 1,
    )
}

async fn pending_count(legacy: &Legacy) -> u64 {
    PendingChangeRepo::new(&legacy.pool)
        .count_by_storage(legacy.storage.id)
        .await
        .expect("count pending")
}

#[tokio::test]
async fn a_legacy_vault_whose_items_prove_the_key_is_claimed_in_place() {
    let legacy = legacy(&[CACHE_FP, CACHE_FP]).await;

    claim(&legacy).await.expect("the items prove the key");
    assert_eq!(
        state(&legacy).await,
        (CATALOG_SLUG.to_string(), Some(CACHE_FP.to_string()), true)
    );
    assert_eq!(
        pending_count(&legacy).await,
        2,
        "unsent changes stay to push"
    );

    claim(&legacy)
        .await
        .expect("a second catalog with the same generation finds it bound");
}

#[tokio::test]
async fn a_legacy_vault_with_an_item_under_another_key_is_refused() {
    let legacy = legacy(&[CACHE_FP, OTHER_FP]).await;

    assert!(matches!(
        claim(&legacy).await,
        Err(LocalVaultKeyBindError::ProjectionNotEmpty)
    ));
    assert_eq!(
        state(&legacy).await,
        (LocalVault::local_slug(legacy.vault.id), None, false),
        "nothing is adopted or claimed"
    );
}

#[tokio::test]
async fn a_legacy_vault_without_cached_items_proves_nothing() {
    let legacy = legacy(&[]).await;
    sqlx_core::query::query::<Sqlite>(
        "INSERT INTO sync_cursors (storage_id, vault_id, cursor, last_seq) VALUES (?1, ?2, 'kept', 1)",
    )
    .bind(legacy.storage.id)
    .bind(legacy.vault.id)
    .execute(&legacy.pool)
    .await
    .expect("insert a legacy cursor");

    assert!(matches!(
        claim(&legacy).await,
        Err(LocalVaultKeyBindError::ProjectionNotEmpty)
    ));
    assert_eq!(
        state(&legacy).await,
        (LocalVault::local_slug(legacy.vault.id), None, false)
    );
}

#[tokio::test]
async fn a_legacy_cursor_records_its_sequence_once() {
    let legacy = legacy(&[]).await;
    sqlx_core::query::query::<Sqlite>(
        "INSERT INTO sync_cursors (storage_id, vault_id, cursor, last_seq) VALUES (?1, ?2, 'legacy-44', NULL)",
    )
    .bind(legacy.storage.id)
    .bind(legacy.vault.id)
    .execute(&legacy.pool)
    .await
    .expect("insert a cursor written before last_seq existed");
    let cursors = SyncCursorRepo::new(&legacy.pool);

    assert!(!cursors
        .adopt_legacy_last_seq(legacy.storage.id, legacy.vault.id, "another", 44)
        .await
        .expect("a cursor that changed is left alone"));
    assert!(cursors
        .adopt_legacy_last_seq(legacy.storage.id, legacy.vault.id, "legacy-44", 44)
        .await
        .expect("record the sequence"));
    assert!(!cursors
        .adopt_legacy_last_seq(legacy.storage.id, legacy.vault.id, "legacy-44", 44)
        .await
        .expect("a recorded sequence is kept"));
    let checkpoint = cursors
        .get_checkpoint(legacy.storage.id, legacy.vault.id)
        .await
        .expect("read checkpoint")
        .expect("checkpoint kept");
    assert_eq!(checkpoint.last_seq, Some(44));
}
