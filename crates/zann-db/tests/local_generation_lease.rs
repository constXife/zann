#![cfg(feature = "sqlite")]

use chrono::Utc;
use sqlx_core::row::Row;
use sqlx_sqlite::Sqlite;
use uuid::Uuid;
use zann_core::{AuthMethod, StorageKind, VaultKind};
use zann_db::local::{
    CacheKeyFingerprintBinding, KeyWrapType, LocalStorage, LocalStorageProof, LocalStorageRepo,
    LocalSyncError, LocalSyncGenerationProof, LocalSyncRepo, LocalSyncScope, LocalVault,
    LocalVaultKeyBindError, LocalVaultRepo, PullPage,
};
use zann_db::{connect_sqlite_path_with_max, migrate_local, SqlitePool};

const CACHE_FP: &str = "001122aabbcc";

struct Fixture {
    pool: SqlitePool,
    storage: LocalStorage,
    vault: LocalVault,
}

async fn fixture(max_connections: u32) -> Fixture {
    let path = std::env::temp_dir().join(format!(
        "zann-local-generation-{}.sqlite",
        Uuid::now_v7().simple()
    ));
    let pool = connect_sqlite_path_with_max(&path, max_connections)
        .await
        .expect("connect SQLite fixture");
    migrate_local(&pool).await.expect("migrate SQLite fixture");
    let storage = LocalStorage {
        id: Uuid::now_v7(),
        kind: StorageKind::Remote,
        name: "Generation target".to_string(),
        server_url: Some("https://generation.example".to_string()),
        server_name: Some("Generation server".to_string()),
        server_fingerprint: Some("server-fingerprint".to_string()),
        account_subject: Some(Uuid::now_v7().to_string()),
        personal_vaults_enabled: true,
        auth_method: Some(AuthMethod::Password),
    };
    LocalStorageRepo::new(&pool)
        .upsert(&storage)
        .await
        .expect("insert remote storage");
    let vault = LocalVault {
        id: Uuid::now_v7(),
        storage_id: storage.id,
        slug: "primary".to_string(),
        name: "Primary".to_string(),
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
        .expect("insert unbound vault");
    Fixture {
        pool,
        storage,
        vault,
    }
}

fn proof(storage: &LocalStorage) -> LocalStorageProof {
    LocalStorageProof::try_from(storage).expect("valid storage proof")
}

fn generation(revision: u64, content: u8) -> LocalSyncGenerationProof {
    LocalSyncGenerationProof::new([0x11; 32], [0x22; 32], revision, [content; 32])
}

fn binding(vault: &LocalVault) -> CacheKeyFingerprintBinding<'_> {
    CacheKeyFingerprintBinding {
        storage_id: vault.storage_id,
        vault_id: vault.id,
        expected_slug: &vault.slug,
        expected_name: &vault.name,
        expected_kind: vault.kind,
        expected_is_default: vault.is_default,
        expected_vault_key_enc: &vault.vault_key_enc,
        expected_key_wrap_type: vault.key_wrap_type,
        target_cache_key_fp: CACHE_FP,
    }
}

async fn stored_generation(
    pool: &SqlitePool,
    storage_id: Uuid,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let row = sqlx_core::query::query::<Sqlite>(
        r#"
        SELECT sync_config_repository_fp, sync_stable_target_fp,
               sync_config_revision, sync_config_content_fp
        FROM storages
        WHERE id = ?1
        "#,
    )
    .bind(storage_id)
    .fetch_one(pool)
    .await
    .expect("read stored generation");
    (
        row.try_get("sync_config_repository_fp")
            .expect("decode repo fp"),
        row.try_get("sync_stable_target_fp")
            .expect("decode target fp"),
        row.try_get("sync_config_revision")
            .expect("decode revision"),
        row.try_get("sync_config_content_fp")
            .expect("decode content fp"),
    )
}

#[tokio::test]
async fn catalog_claim_is_atomic_idempotent_and_monotonically_advances() {
    let fixture = fixture(1).await;
    let storage_proof = proof(&fixture.storage);
    let initial = generation(7, 0x33);
    let debug = format!("{initial:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("repository_fingerprint"));
    assert!(!debug.contains("config_content_fingerprint"));
    let bindings = [binding(&fixture.vault)];

    let claimed = LocalVaultRepo::new(&fixture.pool)
        .bind_cache_key_fingerprints_leased(&storage_proof, &initial, &bindings)
        .await
        .expect("claim generation and bind catalog");
    assert_eq!(claimed.bound(), 1);
    assert_eq!(claimed.already_bound(), 0);
    let stored = stored_generation(&fixture.pool, fixture.storage.id).await;
    assert_eq!(stored.0, vec![0x11; 32]);
    assert_eq!(stored.1, vec![0x22; 32]);
    assert_eq!(stored.2, 7_u64.to_be_bytes());
    assert_eq!(stored.3, vec![0x33; 32]);

    let repeated = LocalVaultRepo::new(&fixture.pool)
        .bind_cache_key_fingerprints_leased(&storage_proof, &initial, &bindings)
        .await
        .expect("repeat exact generation");
    assert_eq!(repeated.bound(), 0);
    assert_eq!(repeated.already_bound(), 1);

    let advanced = generation(u64::MAX - 1, 0x44);
    LocalVaultRepo::new(&fixture.pool)
        .bind_cache_key_fingerprints_leased(&storage_proof, &advanced, &bindings)
        .await
        .expect("advance authorized generation");
    let stored = stored_generation(&fixture.pool, fixture.storage.id).await;
    assert_eq!(stored.2, (u64::MAX - 1).to_be_bytes());
    assert_eq!(stored.3, vec![0x44; 32]);

    for stale in [generation(7, 0x33), generation(u64::MAX - 1, 0x55)] {
        assert!(matches!(
            LocalVaultRepo::new(&fixture.pool)
                .bind_cache_key_fingerprints_leased(&storage_proof, &stale, &bindings)
                .await,
            Err(LocalVaultKeyBindError::GenerationChanged)
        ));
    }
    let stored_after_rejections = stored_generation(&fixture.pool, fixture.storage.id).await;
    assert_eq!(stored_after_rejections, stored);

    let mut ordinary_update = fixture.storage.clone();
    ordinary_update.name = "Renamed projection".to_string();
    LocalStorageRepo::new(&fixture.pool)
        .upsert(&ordinary_update)
        .await
        .expect("ordinary storage upsert preserves generation columns");
    assert_eq!(
        stored_generation(&fixture.pool, fixture.storage.id).await,
        stored,
        "ordinary upsert must not clear or replace the generation lease"
    );
}

#[tokio::test]
async fn initial_claim_rejects_nonempty_projection_without_partial_writes() {
    let fixture = fixture(1).await;
    sqlx_core::query::query::<Sqlite>(
        r#"
        INSERT INTO sync_cursors (storage_id, vault_id, cursor, last_seq)
        VALUES (?1, ?2, 'occupied', 1)
        "#,
    )
    .bind(fixture.storage.id)
    .bind(fixture.vault.id)
    .execute(&fixture.pool)
    .await
    .expect("insert existing projection");

    let bindings = [binding(&fixture.vault)];
    assert!(matches!(
        LocalVaultRepo::new(&fixture.pool)
            .bind_cache_key_fingerprints_leased(
                &proof(&fixture.storage),
                &generation(1, 0x33),
                &bindings,
            )
            .await,
        Err(LocalVaultKeyBindError::ProjectionNotEmpty)
    ));
    let row = sqlx_core::query::query::<Sqlite>(
        "SELECT sync_config_repository_fp, cache_key_fp FROM storages JOIN local_vaults ON local_vaults.storage_id = storages.id WHERE storages.id = ?1",
    )
    .bind(fixture.storage.id)
    .fetch_one(&fixture.pool)
    .await
    .expect("read rolled-back claim");
    assert!(row
        .try_get::<Option<Vec<u8>>, _>("sync_config_repository_fp")
        .expect("repo fp")
        .is_none());
    assert!(row
        .try_get::<Option<String>, _>("cache_key_fp")
        .expect("cache fp")
        .is_none());
}

#[tokio::test]
async fn pull_requires_claimed_generation_and_advances_with_projection_atomically() {
    let fixture = fixture(1).await;
    let storage_proof = proof(&fixture.storage);
    let first = generation(1, 0x33);
    let scope = LocalSyncScope {
        storage_id: fixture.storage.id,
        vault_id: fixture.vault.id,
    };
    let page = PullPage::new(
        scope,
        CACHE_FP.to_string(),
        None,
        None,
        "cursor-1".to_string(),
        Some(1),
        Utc::now(),
        Vec::new(),
    )
    .expect("valid empty pull page");
    assert!(matches!(
        LocalSyncRepo::new(&fixture.pool)
            .commit_pull_page_leased(&page, &storage_proof, &first)
            .await,
        Err(LocalSyncError::StorageGenerationChanged { .. })
    ));

    LocalVaultRepo::new(&fixture.pool)
        .bind_cache_key_fingerprints_leased(&storage_proof, &first, &[binding(&fixture.vault)])
        .await
        .expect("claim catalog");
    let second = generation(2, 0x44);
    let receipt = LocalSyncRepo::new(&fixture.pool)
        .commit_pull_page_leased(&page, &storage_proof, &second)
        .await
        .expect("commit leased pull");
    assert_eq!(receipt.cursor(), "cursor-1");
    assert_eq!(receipt.last_seq(), Some(1));
    let stored = stored_generation(&fixture.pool, fixture.storage.id).await;
    assert_eq!(stored.2, 2_u64.to_be_bytes());
    assert_eq!(stored.3, vec![0x44; 32]);
}

#[tokio::test]
async fn concurrent_first_claims_cannot_mix_generations() {
    let fixture = fixture(2).await;
    let storage_proof = proof(&fixture.storage);
    let first = generation(9, 0x33);
    let conflicting = generation(9, 0x44);
    let first_bindings = [binding(&fixture.vault)];
    let conflicting_bindings = [binding(&fixture.vault)];
    let first_repo = LocalVaultRepo::new(&fixture.pool);
    let conflicting_repo = LocalVaultRepo::new(&fixture.pool);

    let (left, right) = tokio::join!(
        first_repo.bind_cache_key_fingerprints_leased(&storage_proof, &first, &first_bindings),
        conflicting_repo.bind_cache_key_fingerprints_leased(
            &storage_proof,
            &conflicting,
            &conflicting_bindings
        )
    );
    assert_ne!(left.is_ok(), right.is_ok(), "exactly one claim must win");
    let rejected = if left.is_err() { left } else { right };
    assert!(matches!(
        rejected,
        Err(LocalVaultKeyBindError::GenerationChanged)
    ));
    let stored = stored_generation(&fixture.pool, fixture.storage.id).await;
    assert!(stored.3 == vec![0x33; 32] || stored.3 == vec![0x44; 32]);
}

#[tokio::test]
async fn corrupt_partial_generation_is_rejected_before_catalog_or_pull_mutation() {
    let fixture = fixture(1).await;
    sqlx_core::query::query::<Sqlite>("DROP TRIGGER storages_sync_generation_validate_update")
        .execute(&fixture.pool)
        .await
        .expect("drop defense-in-depth trigger for corruption fixture");
    sqlx_core::query::query::<Sqlite>("PRAGMA ignore_check_constraints = ON")
        .execute(&fixture.pool)
        .await
        .expect("enable corruption fixture");
    sqlx_core::query::query::<Sqlite>(
        "UPDATE storages SET sync_config_repository_fp = zeroblob(32) WHERE id = ?1",
    )
    .bind(fixture.storage.id)
    .execute(&fixture.pool)
    .await
    .expect("install partial generation");

    let bindings = [binding(&fixture.vault)];
    assert!(LocalVaultRepo::new(&fixture.pool)
        .bind_cache_key_fingerprints_leased(
            &proof(&fixture.storage),
            &generation(1, 0x33),
            &bindings,
        )
        .await
        .is_err());
    let vault = LocalVaultRepo::new(&fixture.pool)
        .get_by_id(fixture.storage.id, fixture.vault.id)
        .await
        .expect("read vault")
        .expect("vault exists");
    assert!(vault.cache_key_fp.is_none());
}
