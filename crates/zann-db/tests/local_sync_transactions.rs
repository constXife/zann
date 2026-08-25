#![cfg(feature = "sqlite")]

use chrono::{DateTime, TimeZone, Utc};
use sqlx_core::row::Row;
use sqlx_sqlite::Sqlite;
use uuid::Uuid;
use zann_core::{AuthMethod, ChangeType, StorageKind, SyncStatus, VaultKind};
use zann_db::local::{
    CacheKeyFingerprintBind, CacheKeyFingerprintBinding, HistorySource, HistorySyncStatus,
    KeyWrapType, LocalItem, LocalItemExpectation, LocalItemHistory, LocalItemHistoryRepo,
    LocalItemProof, LocalItemRepo, LocalPendingChange, LocalPendingProof, LocalProjectionReadError,
    LocalStorage, LocalStorageProof, LocalStorageRepo, LocalSyncCheckpoint, LocalSyncCursor,
    LocalSyncError, LocalSyncRepo, LocalSyncScope, LocalVault, LocalVaultKeyBindError,
    LocalVaultRepo, PendingChangeRepo, PullChange, PullPage, PushCommit, PushOutcome,
    ResetProjection, SyncCursorRepo,
};
use zann_db::{connect_sqlite_with_max, migrate_local, SqlitePool};

struct Fixture {
    pool: SqlitePool,
    scope: LocalSyncScope,
    storage: LocalStorage,
    url: String,
}

async fn fixture() -> Fixture {
    fixture_with_max_connections(1).await
}

async fn fixture_with_max_connections(max_connections: u32) -> Fixture {
    let path = std::env::temp_dir().join(format!(
        "zann-local-sync-transactions-{}.sqlite",
        Uuid::now_v7().simple()
    ));
    let url = format!("sqlite://{}", path.display());
    let pool = connect_sqlite_with_max(&url, max_connections)
        .await
        .expect("connect sqlite");
    migrate_local(&pool).await.expect("migrate sqlite");

    let storage = remote_storage(Uuid::now_v7(), "https://one.example", "fingerprint-one");
    LocalStorageRepo::new(&pool)
        .upsert(&storage)
        .await
        .expect("insert storage");
    let scope = LocalSyncScope {
        storage_id: storage.id,
        vault_id: Uuid::now_v7(),
    };
    LocalVaultRepo::new(&pool)
        .create(&vault(scope, "Primary"))
        .await
        .expect("insert vault");
    SyncCursorRepo::new(&pool)
        .upsert_checkpoint(&LocalSyncCheckpoint {
            storage_id: scope.storage_id,
            vault_id: scope.vault_id,
            cursor: Some("cursor-1".to_string()),
            last_seq: Some(1),
            last_sync_at: Some(timestamp(1)),
        })
        .await
        .expect("insert cursor");

    Fixture {
        pool,
        scope,
        storage,
        url,
    }
}

async fn empty_migrated_pool(max_connections: u32) -> SqlitePool {
    let path = std::env::temp_dir().join(format!(
        "zann-local-vault-safety-{}.sqlite",
        Uuid::now_v7().simple()
    ));
    let url = format!("sqlite://{}", path.display());
    let pool = connect_sqlite_with_max(&url, max_connections)
        .await
        .expect("connect sqlite");
    migrate_local(&pool).await.expect("migrate sqlite");
    pool
}

async fn disable_storage_update_validation_for_corruption_fixture(pool: &SqlitePool) {
    sqlx_core::query::query::<Sqlite>(
        "DROP TRIGGER IF EXISTS storages_sync_generation_validate_update",
    )
    .execute(pool)
    .await
    .expect("disable storage generation trigger for corruption fixture");
}

fn remote_storage(id: Uuid, url: &str, fingerprint: &str) -> LocalStorage {
    LocalStorage {
        id,
        kind: StorageKind::Remote,
        name: format!("Remote {fingerprint}"),
        server_url: Some(url.to_string()),
        server_name: Some("Test Server".to_string()),
        server_fingerprint: Some(fingerprint.to_string()),
        account_subject: Some("account-subject".to_string()),
        personal_vaults_enabled: true,
        auth_method: Some(AuthMethod::Password),
    }
}

fn vault(scope: LocalSyncScope, name: &str) -> LocalVault {
    LocalVault {
        id: scope.vault_id,
        storage_id: scope.storage_id,
        slug: format!("vault_{}", scope.vault_id.simple()),
        name: name.to_string(),
        kind: VaultKind::Personal,
        is_default: true,
        vault_key_enc: vec![7, 8, 9],
        key_wrap_type: KeyWrapType::RemoteStrict,
        cache_key_fp: Some("001122aabbcc".to_string()),
        last_synced_at: None,
    }
}

fn default_local_personal_candidate(id: Uuid) -> LocalVault {
    LocalVault {
        id,
        storage_id: Uuid::nil(),
        slug: LocalVault::local_slug(id),
        name: "Personal (Local)".to_string(),
        kind: VaultKind::Personal,
        is_default: true,
        vault_key_enc: vec![1, 2, 3],
        key_wrap_type: KeyWrapType::Master,
        cache_key_fp: None,
        last_synced_at: None,
    }
}

fn item(
    scope: LocalSyncScope,
    id: Uuid,
    path: &str,
    checksum: &str,
    version: i64,
    status: SyncStatus,
) -> LocalItem {
    LocalItem {
        id,
        storage_id: scope.storage_id,
        vault_id: scope.vault_id,
        path: path.to_string(),
        name: path.rsplit('/').next().expect("path basename").to_string(),
        type_id: "login".to_string(),
        payload_enc: vec![version as u8, 20, 30],
        checksum: canonical_checksum(checksum),
        cache_key_fp: Some("001122aabbcc".to_string()),
        version,
        deleted_at: None,
        updated_at: timestamp(version),
        sync_status: status,
    }
}

fn history(scope: LocalSyncScope, item_id: Uuid, version: i64, checksum: &str) -> LocalItemHistory {
    LocalItemHistory {
        id: Uuid::now_v7(),
        storage_id: scope.storage_id,
        vault_id: scope.vault_id,
        item_id,
        payload_enc: vec![version as u8, 4, 5],
        checksum: canonical_checksum(checksum),
        version,
        change_type: ChangeType::Update,
        changed_by_email: "sync@example.test".to_string(),
        changed_by_name: Some("Sync User".to_string()),
        changed_by_device_id: Some(Uuid::now_v7()),
        changed_by_device_name: Some("Test Device".to_string()),
        source: HistorySource::Server,
        sync_status: HistorySyncStatus::Confirmed,
        created_at: timestamp(version),
    }
}

fn pending(scope: LocalSyncScope, item: &LocalItem, operation: ChangeType) -> LocalPendingChange {
    let (payload_enc, checksum, base_seq) = match operation {
        ChangeType::Create => (
            Some(item.payload_enc.clone()),
            Some(item.checksum.clone()),
            None,
        ),
        ChangeType::Update | ChangeType::Restore => (
            Some(item.payload_enc.clone()),
            Some(item.checksum.clone()),
            Some(item.version.saturating_sub(1)),
        ),
        ChangeType::Delete => (None, None, Some(item.version.saturating_sub(1))),
    };
    LocalPendingChange {
        id: Uuid::now_v7(),
        storage_id: scope.storage_id,
        vault_id: scope.vault_id,
        item_id: item.id,
        operation,
        payload_enc,
        checksum,
        path: Some(item.path.clone()),
        name: Some(item.name.clone()),
        type_id: Some(item.type_id.clone()),
        base_seq,
        created_at: item.updated_at,
    }
}

fn exact(item: &LocalItem) -> LocalItemExpectation {
    LocalItemExpectation::Exact(Box::new(
        LocalItemProof::try_from(item).expect("valid item proof"),
    ))
}

fn advancing_pull_page(scope: LocalSyncScope, original: &LocalItem) -> PullPage {
    let mut projected = original.clone();
    projected.version += 1;
    projected.payload_enc = vec![9, 8, 7];
    projected.checksum = canonical_checksum("writer-preflight-next");
    projected.updated_at = timestamp(projected.version);
    projected.sync_status = SyncStatus::Synced;
    let change = PullChange::new(scope, exact(original), projected, Vec::new())
        .expect("valid writer-preflight pull change");
    PullPage::new(
        scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(1),
        "cursor-2".to_string(),
        Some(2),
        timestamp(2),
        vec![change],
    )
    .expect("valid writer-preflight pull page")
}

fn storage_proof(storage: &LocalStorage) -> LocalStorageProof {
    LocalStorageProof::try_from(storage).expect("valid storage proof")
}

fn cache_binding<'a>(
    vault: &'a LocalVault,
    target_cache_key_fp: &'a str,
) -> CacheKeyFingerprintBinding<'a> {
    CacheKeyFingerprintBinding {
        storage_id: vault.storage_id,
        vault_id: vault.id,
        expected_slug: &vault.slug,
        expected_name: &vault.name,
        expected_kind: vault.kind,
        expected_is_default: vault.is_default,
        expected_vault_key_enc: &vault.vault_key_enc,
        expected_key_wrap_type: vault.key_wrap_type,
        target_cache_key_fp,
    }
}

fn canonical_checksum(label: &str) -> String {
    blake3::hash(label.as_bytes()).to_hex().to_string()
}

fn expect_sync_error<T>(
    result: Result<T, LocalSyncError>,
    message: &'static str,
) -> LocalSyncError {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

fn expect_corrupt_projection<T>(result: Result<T, LocalProjectionReadError>) {
    assert!(matches!(
        result,
        Err(LocalProjectionReadError::CorruptProjection)
    ));
}

async fn stored_proof(pool: &SqlitePool, storage_id: Uuid, item_id: Uuid) -> LocalPendingProof {
    let rows = PendingChangeRepo::new(pool)
        .list_by_item(storage_id, item_id)
        .await
        .expect("read pending proof");
    assert_eq!(rows.len(), 1, "expected one pending proof row");
    LocalPendingProof::try_from(&rows[0]).expect("valid stored pending proof")
}

fn timestamp(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000 + seconds, 0)
        .single()
        .expect("valid timestamp")
}

async fn insert_item(pool: &SqlitePool, item: &LocalItem) {
    LocalItemRepo::new(pool)
        .create(item)
        .await
        .expect("insert item");
}

async fn insert_pending(pool: &SqlitePool, pending: &LocalPendingChange) {
    PendingChangeRepo::new(pool)
        .create(pending)
        .await
        .expect("insert pending");
}

#[tokio::test]
async fn remote_storage_count_is_capped_without_materializing_rows() {
    let pool = empty_migrated_pool(1).await;
    let repository = LocalStorageRepo::new(&pool);
    assert_eq!(
        repository
            .remote_count_up_to_two()
            .await
            .expect("count initial remote storages"),
        0
    );
    for index in 0..3 {
        let storage = remote_storage(
            Uuid::now_v7(),
            &format!("https://remote-count-{index}.example"),
            &format!("remote-count-{index}"),
        );
        repository
            .upsert(&storage)
            .await
            .expect("insert remote storage");
        assert_eq!(
            repository
                .remote_count_up_to_two()
                .await
                .expect("count capped remote storages"),
            u8::try_from(index + 1).expect("small count").min(2)
        );
    }
}

#[tokio::test]
async fn storage_list_accepts_its_exact_cap_and_rejects_cap_plus_one() {
    let pool = empty_migrated_pool(1).await;
    sqlx_core::query::query::<Sqlite>(
        r#"
        WITH RECURSIVE seq(n) AS (
            SELECT 1
            UNION ALL
            SELECT n + 1 FROM seq WHERE n < 256
        )
        INSERT INTO storages (
            id, kind, name, server_url, personal_vaults_enabled
        )
        SELECT
            randomblob(16), 2,
            printf('Remote %03d', n),
            printf('https://bounded-storage-%03d.test', n),
            1
        FROM seq
        "#,
    )
    .execute(&pool)
    .await
    .expect("insert the maximum 256 remote storage rows");
    let repository = LocalStorageRepo::new(&pool);
    assert_eq!(
        repository
            .list()
            .await
            .expect("list exact storage cap")
            .len(),
        257
    );

    repository
        .upsert(&remote_storage(
            Uuid::now_v7(),
            "https://bounded-storage-overflow.test",
            "bounded-overflow",
        ))
        .await
        .expect("insert cap plus one");
    assert!(repository.list().await.is_err(), "list must not truncate");
}

#[tokio::test]
async fn storage_list_rejects_unsupported_local_and_remote_topologies() {
    let local_pool = empty_migrated_pool(1).await;
    LocalStorageRepo::new(&local_pool)
        .upsert(&LocalStorage {
            id: Uuid::now_v7(),
            kind: StorageKind::LocalOnly,
            name: "Second local".to_string(),
            server_url: None,
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: true,
            auth_method: None,
        })
        .await
        .expect("insert unsupported second local row");
    assert!(LocalStorageRepo::new(&local_pool).list().await.is_err());

    let remote_pool = empty_migrated_pool(1).await;
    LocalStorageRepo::new(&remote_pool)
        .delete(Uuid::nil())
        .await
        .expect("remove local row for isolated remote-cap fixture");
    sqlx_core::query::query::<Sqlite>(
        r#"
        WITH RECURSIVE seq(n) AS (
            SELECT 1
            UNION ALL
            SELECT n + 1 FROM seq WHERE n < 257
        )
        INSERT INTO storages (
            id, kind, name, server_url, personal_vaults_enabled
        )
        SELECT
            randomblob(16), 2,
            printf('Remote %03d', n),
            printf('https://remote-topology-%03d.test', n),
            1
        FROM seq
        "#,
    )
    .execute(&remote_pool)
    .await
    .expect("insert unsupported 257 remote rows");
    assert!(LocalStorageRepo::new(&remote_pool).list().await.is_err());
}

#[tokio::test]
async fn storage_exact_and_list_reads_fail_before_decoding_huge_dynamic_bodies() {
    const HUGE_BODY_BYTES: i64 = 8 * 1024 * 1024;

    let pool = empty_migrated_pool(1).await;
    let repository = LocalStorageRepo::new(&pool);
    assert!(repository
        .get(Uuid::nil())
        .await
        .expect("generic get supports the local-only row")
        .is_some());
    assert!(repository
        .get_bounded(Uuid::nil())
        .await
        .expect("typed bounded get supports the local-only row")
        .is_some());

    sqlx_core::query::query::<Sqlite>("UPDATE storages SET name = zeroblob(?1) WHERE id = ?2")
        .bind(HUGE_BODY_BYTES)
        .bind(Uuid::nil())
        .execute(&pool)
        .await
        .expect("install huge dynamically typed blob");
    assert!(repository.get(Uuid::nil()).await.is_err());
    expect_corrupt_projection(repository.get_bounded(Uuid::nil()).await);
    assert!(repository.list().await.is_err());

    sqlx_core::query::query::<Sqlite>(
        "UPDATE storages SET name = CAST(zeroblob(?1) AS TEXT) WHERE id = ?2",
    )
    .bind(HUGE_BODY_BYTES)
    .bind(Uuid::nil())
    .execute(&pool)
    .await
    .expect("install huge dynamically typed text");
    assert!(repository.get(Uuid::nil()).await.is_err());
    expect_corrupt_projection(repository.get_bounded(Uuid::nil()).await);
    assert!(repository.list().await.is_err());

    repository
        .delete(Uuid::nil())
        .await
        .expect("delete corrupt local row");
    assert!(repository
        .list()
        .await
        .expect("empty storage list remains valid")
        .is_empty());
}

#[tokio::test]
async fn checkpoint_pending_reader_materializes_at_most_the_requested_limit() {
    let fixture = fixture().await;
    for index in 0..66 {
        let projected = item(
            fixture.scope,
            Uuid::now_v7(),
            &format!("accounts/pending-{index}"),
            &format!("pending-{index}"),
            1,
            SyncStatus::Modified,
        );
        insert_pending(
            &fixture.pool,
            &pending(fixture.scope, &projected, ChangeType::Create),
        )
        .await;
    }
    let (checkpoint, pending) = PendingChangeRepo::new(&fixture.pool)
        .load_checkpoint_with_pending_limit(fixture.scope.storage_id, fixture.scope.vault_id, 65)
        .await
        .expect("load bounded checkpoint and pending rows");
    assert_eq!(
        checkpoint.and_then(|value| value.cursor).as_deref(),
        Some("cursor-1")
    );
    assert_eq!(pending.len(), 65);
    assert!(matches!(
        PendingChangeRepo::new(&fixture.pool)
            .load_checkpoint_with_pending_max(fixture.scope.storage_id, fixture.scope.vault_id, 64,)
            .await,
        Err(LocalProjectionReadError::TooManyRows)
    ));
    sqlx_core::query::query::<Sqlite>(
        r#"
        UPDATE pending_changes
        SET payload_enc = zeroblob(1048576)
        WHERE rowid = (
            SELECT rowid FROM pending_changes
            WHERE storage_id = ?1 AND vault_id = ?2
            LIMIT 1
        )
        "#,
    )
    .bind(fixture.scope.storage_id)
    .bind(fixture.scope.vault_id)
    .execute(&fixture.pool)
    .await
    .expect("install oversized pending overflow sentinel");
    assert!(matches!(
        PendingChangeRepo::new(&fixture.pool)
            .load_checkpoint_with_pending_max(fixture.scope.storage_id, fixture.scope.vault_id, 64,)
            .await,
        Err(LocalProjectionReadError::TooManyRows)
    ));
    assert!(PendingChangeRepo::new(&fixture.pool)
        .load_checkpoint_with_pending_limit(fixture.scope.storage_id, fixture.scope.vault_id, 0,)
        .await
        .is_err());
}

#[tokio::test]
async fn bounded_projection_readers_reject_oversized_sqlite_bodies_before_decode() {
    let fixture = fixture().await;
    sqlx_core::query::query::<Sqlite>("PRAGMA ignore_check_constraints = ON")
        .execute(&fixture.pool)
        .await
        .expect("allow legacy-corruption fixtures");
    sqlx_core::query::query::<Sqlite>("PRAGMA foreign_keys = OFF")
        .execute(&fixture.pool)
        .await
        .expect("allow legacy foreign-key corruption fixtures");
    disable_storage_update_validation_for_corruption_fixture(&fixture.pool).await;

    sqlx_core::query::query::<Sqlite>("UPDATE storages SET kind = zeroblob(1048576) WHERE id = ?1")
        .bind(Uuid::nil())
        .execute(&fixture.pool)
        .await
        .expect("install oversized unrelated storage kind");
    expect_corrupt_projection(
        LocalStorageRepo::new(&fixture.pool)
            .get_bounded(fixture.scope.storage_id)
            .await,
    );
    assert!(LocalStorageRepo::new(&fixture.pool)
        .remote_count_up_to_two()
        .await
        .is_err());
    sqlx_core::query::query::<Sqlite>("UPDATE storages SET kind = ?2 WHERE id = ?1")
        .bind(Uuid::nil())
        .bind(StorageKind::LocalOnly.as_i32())
        .execute(&fixture.pool)
        .await
        .expect("restore unrelated storage kind");

    sqlx_core::query::query::<Sqlite>("UPDATE storages SET id = zeroblob(1048576) WHERE id = ?1")
        .bind(Uuid::nil())
        .execute(&fixture.pool)
        .await
        .expect("install oversized unrelated storage id");
    expect_corrupt_projection(
        LocalStorageRepo::new(&fixture.pool)
            .get_bounded(fixture.scope.storage_id)
            .await,
    );
    sqlx_core::query::query::<Sqlite>(
        "UPDATE storages SET id = ?1 WHERE octet_length(id) = 1048576",
    )
    .bind(Uuid::nil())
    .execute(&fixture.pool)
    .await
    .expect("restore unrelated storage id");

    for (column, bytes) in [
        ("name", 201_i64),
        ("server_url", 2_049),
        ("account_subject", 513),
    ] {
        let sql = format!("UPDATE storages SET {column} = printf('%.*c', ?2, 'x') WHERE id = ?1");
        sqlx_core::query::query::<Sqlite>(&sql)
            .bind(fixture.scope.storage_id)
            .bind(bytes)
            .execute(&fixture.pool)
            .await
            .expect("install oversized storage field");
        expect_corrupt_projection(
            LocalStorageRepo::new(&fixture.pool)
                .get_bounded(fixture.scope.storage_id)
                .await,
        );
        LocalStorageRepo::new(&fixture.pool)
            .upsert(&fixture.storage)
            .await
            .expect("restore bounded storage row");
    }

    sqlx_core::query::query::<Sqlite>("DROP TRIGGER local_vaults_v2_validate_update")
        .execute(&fixture.pool)
        .await
        .expect("disable vault validation for legacy identifier fixtures");
    sqlx_core::query::query::<Sqlite>(
        "UPDATE local_vaults SET storage_id = zeroblob(1048576) WHERE id = ?1",
    )
    .bind(fixture.scope.vault_id)
    .execute(&fixture.pool)
    .await
    .expect("install oversized vault storage id");
    expect_corrupt_projection(
        LocalVaultRepo::new(&fixture.pool)
            .exists_bounded(fixture.scope.storage_id, fixture.scope.vault_id)
            .await,
    );
    expect_corrupt_projection(
        LocalVaultRepo::new(&fixture.pool)
            .list_by_storage_bounded(fixture.scope.storage_id)
            .await,
    );
    sqlx_core::query::query::<Sqlite>("UPDATE local_vaults SET storage_id = ?2 WHERE id = ?1")
        .bind(fixture.scope.vault_id)
        .bind(fixture.scope.storage_id)
        .execute(&fixture.pool)
        .await
        .expect("restore bounded vault storage id");

    sqlx_core::query::query::<Sqlite>(
        r#"UPDATE sync_cursors SET cursor = printf('%.*c', 4097, 'x')
           WHERE storage_id = ?1 AND vault_id = ?2"#,
    )
    .bind(fixture.scope.storage_id)
    .bind(fixture.scope.vault_id)
    .execute(&fixture.pool)
    .await
    .expect("install oversized cursor");
    expect_corrupt_projection(
        PendingChangeRepo::new(&fixture.pool)
            .load_checkpoint_with_pending_max(fixture.scope.storage_id, fixture.scope.vault_id, 64)
            .await,
    );
    SyncCursorRepo::new(&fixture.pool)
        .upsert_checkpoint(&LocalSyncCheckpoint {
            storage_id: fixture.scope.storage_id,
            vault_id: fixture.scope.vault_id,
            cursor: Some("cursor-1".to_string()),
            last_seq: Some(1),
            last_sync_at: Some(timestamp(1)),
        })
        .await
        .expect("restore bounded cursor");
    for column in ["storage_id", "vault_id"] {
        let sql = format!(
            "UPDATE sync_cursors SET {column} = zeroblob(1048576) \
             WHERE storage_id = ?1 AND vault_id = ?2"
        );
        sqlx_core::query::query::<Sqlite>(&sql)
            .bind(fixture.scope.storage_id)
            .bind(fixture.scope.vault_id)
            .execute(&fixture.pool)
            .await
            .expect("install oversized cursor identifier");
        expect_corrupt_projection(
            PendingChangeRepo::new(&fixture.pool)
                .load_checkpoint_with_pending_max(
                    fixture.scope.storage_id,
                    fixture.scope.vault_id,
                    64,
                )
                .await,
        );
        let restore =
            format!("UPDATE sync_cursors SET {column} = ?1 WHERE octet_length({column}) = 1048576");
        let value = if column == "storage_id" {
            fixture.scope.storage_id
        } else {
            fixture.scope.vault_id
        };
        sqlx_core::query::query::<Sqlite>(&restore)
            .bind(value)
            .execute(&fixture.pool)
            .await
            .expect("restore cursor identifier");
    }

    let pending_item = item(
        fixture.scope,
        Uuid::now_v7(),
        "accounts/bounded-pending",
        "bounded-pending",
        1,
        SyncStatus::Modified,
    );
    let pending = pending(fixture.scope, &pending_item, ChangeType::Create);
    insert_pending(&fixture.pool, &pending).await;
    for statement in [
        "UPDATE pending_changes SET payload_enc = zeroblob(262401) WHERE id = ?1",
        "UPDATE pending_changes SET path = printf('%.*c', 501, 'x') WHERE id = ?1",
        "UPDATE pending_changes SET checksum = printf('%.*c', 257, 'x') WHERE id = ?1",
    ] {
        sqlx_core::query::query::<Sqlite>(statement)
            .bind(pending.id)
            .execute(&fixture.pool)
            .await
            .expect("install oversized pending field");
        expect_corrupt_projection(
            PendingChangeRepo::new(&fixture.pool)
                .load_checkpoint_with_pending_max(
                    fixture.scope.storage_id,
                    fixture.scope.vault_id,
                    64,
                )
                .await,
        );
        PendingChangeRepo::new(&fixture.pool)
            .delete_by_item(fixture.scope.storage_id, pending.item_id)
            .await
            .expect("remove corrupt pending row");
        insert_pending(&fixture.pool, &pending).await;
    }
    for column in ["storage_id", "vault_id", "item_id"] {
        let sql = format!("UPDATE pending_changes SET {column} = zeroblob(1048576) WHERE id = ?1");
        sqlx_core::query::query::<Sqlite>(&sql)
            .bind(pending.id)
            .execute(&fixture.pool)
            .await
            .expect("install oversized pending identifier");
        expect_corrupt_projection(
            PendingChangeRepo::new(&fixture.pool)
                .load_checkpoint_with_pending_max(
                    fixture.scope.storage_id,
                    fixture.scope.vault_id,
                    64,
                )
                .await,
        );
        expect_corrupt_projection(
            PendingChangeRepo::new(&fixture.pool)
                .get_by_item_bounded(fixture.scope.storage_id, pending.item_id)
                .await,
        );
        sqlx_core::query::query::<Sqlite>("DELETE FROM pending_changes WHERE id = ?1")
            .bind(pending.id)
            .execute(&fixture.pool)
            .await
            .expect("remove corrupt pending identifier row");
        insert_pending(&fixture.pool, &pending).await;
    }
    PendingChangeRepo::new(&fixture.pool)
        .delete_by_item(fixture.scope.storage_id, pending.item_id)
        .await
        .expect("remove pending fixture");

    let projected = item(
        fixture.scope,
        Uuid::now_v7(),
        "accounts/bounded-item",
        "bounded-item",
        1,
        SyncStatus::Synced,
    );
    insert_item(&fixture.pool, &projected).await;
    for statement in [
        "UPDATE items_cache SET payload_enc = zeroblob(262401) WHERE id = ?1",
        "UPDATE items_cache SET path = printf('%.*c', 501, 'x') WHERE id = ?1",
        "UPDATE items_cache SET checksum = printf('%.*c', 257, 'x') WHERE id = ?1",
        "UPDATE items_cache SET cache_key_fp = printf('%.*c', 13, 'a') WHERE id = ?1",
    ] {
        sqlx_core::query::query::<Sqlite>(statement)
            .bind(projected.id)
            .execute(&fixture.pool)
            .await
            .expect("install oversized item field");
        expect_corrupt_projection(
            LocalItemRepo::new(&fixture.pool)
                .get_by_id_bounded(fixture.scope.storage_id, projected.id)
                .await,
        );
        LocalItemRepo::new(&fixture.pool)
            .update(&projected)
            .await
            .expect("restore bounded item row");
    }
    for column in ["storage_id", "vault_id"] {
        let sql = format!("UPDATE items_cache SET {column} = zeroblob(1048576) WHERE id = ?1");
        sqlx_core::query::query::<Sqlite>(&sql)
            .bind(projected.id)
            .execute(&fixture.pool)
            .await
            .expect("install oversized item identifier");
        expect_corrupt_projection(
            LocalItemRepo::new(&fixture.pool)
                .get_by_id_bounded(fixture.scope.storage_id, projected.id)
                .await,
        );
        LocalItemRepo::new(&fixture.pool)
            .update(&projected)
            .await
            .expect("restore bounded item identifier");
    }
}

#[tokio::test]
async fn pull_writer_preflights_corrupt_storage_vault_cursor_item_and_pending_rows() {
    #[derive(Clone, Copy)]
    enum Corruption {
        Storage,
        StorageId,
        StorageKind,
        StorageDrift,
        SecondRemote,
        Vault,
        VaultStorageId,
        Cursor,
        CursorStorageId,
        Item,
        ItemVaultId,
        PendingId,
        PendingVaultId,
        HistoryAuthority,
        HistoryVaultId,
    }

    for corruption in [
        Corruption::Storage,
        Corruption::StorageId,
        Corruption::StorageKind,
        Corruption::StorageDrift,
        Corruption::SecondRemote,
        Corruption::Vault,
        Corruption::VaultStorageId,
        Corruption::Cursor,
        Corruption::CursorStorageId,
        Corruption::Item,
        Corruption::ItemVaultId,
        Corruption::PendingId,
        Corruption::PendingVaultId,
        Corruption::HistoryAuthority,
        Corruption::HistoryVaultId,
    ] {
        let fixture = fixture().await;
        sqlx_core::query::query::<Sqlite>("PRAGMA ignore_check_constraints = ON")
            .execute(&fixture.pool)
            .await
            .expect("allow writer corruption fixture");
        sqlx_core::query::query::<Sqlite>("PRAGMA foreign_keys = OFF")
            .execute(&fixture.pool)
            .await
            .expect("allow writer foreign-key corruption fixture");
        disable_storage_update_validation_for_corruption_fixture(&fixture.pool).await;
        let original = item(
            fixture.scope,
            Uuid::now_v7(),
            "accounts/writer-preflight",
            "writer-preflight",
            1,
            SyncStatus::Synced,
        );
        insert_item(&fixture.pool, &original).await;
        let page = advancing_pull_page(fixture.scope, &original);
        let expected_storage = storage_proof(&fixture.storage);

        match corruption {
            Corruption::Storage => {
                sqlx_core::query::query::<Sqlite>(
                    "UPDATE storages SET name = printf('%.*c', 201, 's') WHERE id = ?1",
                )
                .bind(fixture.scope.storage_id)
                .execute(&fixture.pool)
                .await
                .expect("install oversized storage name");
            }
            Corruption::StorageId => {
                sqlx_core::query::query::<Sqlite>(
                    "UPDATE storages SET id = zeroblob(1048576) WHERE id = ?1",
                )
                .bind(Uuid::nil())
                .execute(&fixture.pool)
                .await
                .expect("install oversized unrelated storage id");
            }
            Corruption::StorageKind => {
                sqlx_core::query::query::<Sqlite>(
                    "UPDATE storages SET kind = zeroblob(1048576) WHERE id = ?1",
                )
                .bind(Uuid::nil())
                .execute(&fixture.pool)
                .await
                .expect("install oversized unrelated storage kind");
            }
            Corruption::StorageDrift => {
                sqlx_core::query::query::<Sqlite>(
                    "UPDATE storages SET auth_method = ?2 WHERE id = ?1",
                )
                .bind(fixture.scope.storage_id)
                .bind(AuthMethod::Oidc.as_i32())
                .execute(&fixture.pool)
                .await
                .expect("install exact storage-binding drift");
            }
            Corruption::SecondRemote => {
                LocalStorageRepo::new(&fixture.pool)
                    .upsert(&remote_storage(
                        Uuid::now_v7(),
                        "https://second-writer-cache.example",
                        "second-writer-cache",
                    ))
                    .await
                    .expect("install second remote storage");
            }
            Corruption::Vault => {
                sqlx_core::query::query::<Sqlite>("DROP TRIGGER local_vaults_v2_validate_update")
                    .execute(&fixture.pool)
                    .await
                    .expect("disable vault validation for legacy corruption fixture");
                sqlx_core::query::query::<Sqlite>(
                    "UPDATE local_vaults SET vault_key_enc = zeroblob(65537) WHERE id = ?1",
                )
                .bind(fixture.scope.vault_id)
                .execute(&fixture.pool)
                .await
                .expect("install oversized vault envelope");
            }
            Corruption::VaultStorageId => {
                sqlx_core::query::query::<Sqlite>("DROP TRIGGER local_vaults_v2_validate_update")
                    .execute(&fixture.pool)
                    .await
                    .expect("disable vault validation for legacy id corruption");
                sqlx_core::query::query::<Sqlite>(
                    "UPDATE local_vaults SET storage_id = zeroblob(1048576) WHERE id = ?1",
                )
                .bind(fixture.scope.vault_id)
                .execute(&fixture.pool)
                .await
                .expect("install oversized vault storage id");
            }
            Corruption::Cursor => {
                sqlx_core::query::query::<Sqlite>(
                    r#"UPDATE sync_cursors SET cursor = printf('%.*c', 4097, 'c')
                       WHERE storage_id = ?1 AND vault_id = ?2"#,
                )
                .bind(fixture.scope.storage_id)
                .bind(fixture.scope.vault_id)
                .execute(&fixture.pool)
                .await
                .expect("install oversized writer cursor");
            }
            Corruption::CursorStorageId => {
                sqlx_core::query::query::<Sqlite>(
                    r#"UPDATE sync_cursors SET storage_id = zeroblob(1048576)
                       WHERE storage_id = ?1 AND vault_id = ?2"#,
                )
                .bind(fixture.scope.storage_id)
                .bind(fixture.scope.vault_id)
                .execute(&fixture.pool)
                .await
                .expect("install oversized writer cursor storage id");
            }
            Corruption::Item => {
                sqlx_core::query::query::<Sqlite>(
                    "UPDATE items_cache SET payload_enc = zeroblob(262401) WHERE id = ?1",
                )
                .bind(original.id)
                .execute(&fixture.pool)
                .await
                .expect("install oversized writer item");
            }
            Corruption::ItemVaultId => {
                sqlx_core::query::query::<Sqlite>(
                    "UPDATE items_cache SET vault_id = zeroblob(1048576) WHERE id = ?1",
                )
                .bind(original.id)
                .execute(&fixture.pool)
                .await
                .expect("install oversized writer item vault id");
            }
            Corruption::PendingId => {
                let pending = pending(fixture.scope, &original, ChangeType::Update);
                insert_pending(&fixture.pool, &pending).await;
                sqlx_core::query::query::<Sqlite>(
                    "UPDATE pending_changes SET id = printf('%.*c', 1000, 'p') WHERE id = ?1",
                )
                .bind(pending.id)
                .execute(&fixture.pool)
                .await
                .expect("install oversized pending id");
            }
            Corruption::PendingVaultId => {
                let pending = pending(fixture.scope, &original, ChangeType::Update);
                insert_pending(&fixture.pool, &pending).await;
                sqlx_core::query::query::<Sqlite>(
                    "UPDATE pending_changes SET vault_id = zeroblob(1048576) WHERE id = ?1",
                )
                .bind(pending.id)
                .execute(&fixture.pool)
                .await
                .expect("install oversized pending vault id");
            }
            Corruption::HistoryAuthority => {
                LocalItemHistoryRepo::new(&fixture.pool)
                    .create(&history(
                        fixture.scope,
                        original.id,
                        1,
                        "writer-preflight-history",
                    ))
                    .await
                    .expect("insert writer-preflight history");
                sqlx_core::query::query::<Sqlite>(
                    "UPDATE item_history SET source = zeroblob(1048576) WHERE item_id = ?1",
                )
                .bind(original.id)
                .execute(&fixture.pool)
                .await
                .expect("install oversized history authority");
            }
            Corruption::HistoryVaultId => {
                LocalItemHistoryRepo::new(&fixture.pool)
                    .create(&history(
                        fixture.scope,
                        original.id,
                        1,
                        "writer-preflight-history-vault-id",
                    ))
                    .await
                    .expect("insert writer-preflight history");
                sqlx_core::query::query::<Sqlite>(
                    "UPDATE item_history SET vault_id = zeroblob(1048576) WHERE item_id = ?1",
                )
                .bind(original.id)
                .execute(&fixture.pool)
                .await
                .expect("install oversized history vault id");
            }
        }

        let error = expect_sync_error(
            LocalSyncRepo::new(&fixture.pool)
                .commit_pull_page_bound(&page, &expected_storage)
                .await,
            "corrupt writer row must reject pull before mutation",
        );
        match corruption {
            Corruption::Storage
            | Corruption::StorageId
            | Corruption::StorageKind
            | Corruption::StorageDrift
            | Corruption::SecondRemote => {
                assert!(matches!(
                    error,
                    LocalSyncError::StorageBindingChanged { .. }
                ))
            }
            Corruption::Vault => {
                assert!(matches!(error, LocalSyncError::StaleVaultKey { .. }))
            }
            Corruption::VaultStorageId => {
                assert!(matches!(error, LocalSyncError::InvalidPlan { .. }))
            }
            Corruption::Cursor | Corruption::CursorStorageId => {
                assert!(matches!(error, LocalSyncError::StaleCursor { .. }))
            }
            Corruption::Item | Corruption::ItemVaultId => {
                assert!(matches!(error, LocalSyncError::StaleItem { .. }))
            }
            Corruption::PendingId | Corruption::PendingVaultId => {
                assert!(matches!(error, LocalSyncError::InvalidPlan { .. }))
            }
            Corruption::HistoryAuthority | Corruption::HistoryVaultId => {
                assert!(matches!(error, LocalSyncError::InvalidPlan { .. }))
            }
        }

        let item_state = sqlx_core::query::query::<Sqlite>(
            "SELECT version, length(payload_enc) AS payload_len FROM items_cache WHERE id = ?1",
        )
        .bind(original.id)
        .fetch_one(&fixture.pool)
        .await
        .expect("read scalar item state after rejected pull");
        assert_eq!(item_state.try_get::<i64, _>("version").expect("version"), 1);
        let expected_payload_len = if matches!(corruption, Corruption::Item) {
            262_401
        } else {
            3
        };
        assert_eq!(
            item_state
                .try_get::<i64, _>("payload_len")
                .expect("payload length"),
            expected_payload_len
        );
        let expected_history_rows = if matches!(
            corruption,
            Corruption::HistoryAuthority | Corruption::HistoryVaultId
        ) {
            1
        } else {
            0
        };
        assert_eq!(
            row_count(&fixture.pool, "item_history", fixture.scope.storage_id).await,
            expected_history_rows
        );
        let checkpoint = sqlx_core::query::query::<Sqlite>(
            r#"SELECT octet_length(cursor) AS cursor_len,
                      octet_length(storage_id) AS storage_id_len,
                      last_seq
               FROM sync_cursors LIMIT 1"#,
        )
        .fetch_one(&fixture.pool)
        .await
        .expect("read scalar checkpoint after rejected pull");
        assert_eq!(
            checkpoint.try_get::<i64, _>("last_seq").expect("last seq"),
            1
        );
        let expected_cursor_len = if matches!(corruption, Corruption::Cursor) {
            4_097
        } else {
            8
        };
        assert_eq!(
            checkpoint
                .try_get::<i64, _>("cursor_len")
                .expect("cursor length"),
            expected_cursor_len
        );
        let expected_storage_id_len = if matches!(corruption, Corruption::CursorStorageId) {
            1_048_576
        } else {
            16
        };
        assert_eq!(
            checkpoint
                .try_get::<i64, _>("storage_id_len")
                .expect("cursor storage id length"),
            expected_storage_id_len
        );
    }
}

#[tokio::test]
async fn push_writer_preflights_corrupt_pending_body_before_item_or_delete_cas() {
    let fixture = fixture().await;
    let original = item(
        fixture.scope,
        Uuid::now_v7(),
        "accounts/pending-writer-preflight",
        "pending-writer-preflight",
        4,
        SyncStatus::Modified,
    );
    insert_item(&fixture.pool, &original).await;
    let pending = pending(fixture.scope, &original, ChangeType::Update);
    insert_pending(&fixture.pool, &pending).await;
    let pending_proof = LocalPendingProof::try_from(&pending).expect("valid pending proof");
    let mut projected = original.clone();
    projected.version = 5;
    projected.updated_at = timestamp(5);
    projected.sync_status = SyncStatus::Synced;
    let outcome = PushOutcome::applied(fixture.scope, pending_proof, exact(&original), projected)
        .expect("valid pre-corruption push outcome");
    let commit = PushCommit::new(
        fixture.scope,
        Some("cursor-1".to_string()),
        Some(1),
        "server-head-5".to_string(),
        vec![outcome],
    )
    .expect("valid pre-corruption push plan");
    sqlx_core::query::query::<Sqlite>(
        "UPDATE pending_changes SET payload_enc = zeroblob(262401) WHERE id = ?1",
    )
    .bind(pending.id)
    .execute(&fixture.pool)
    .await
    .expect("install oversized pending payload");

    let error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool).commit_push(&commit).await,
        "corrupt pending body must reject push before mutation",
    );
    assert!(matches!(error, LocalSyncError::StalePending { .. }));
    let item_state = sqlx_core::query::query::<Sqlite>(
        "SELECT version, sync_status FROM items_cache WHERE id = ?1",
    )
    .bind(original.id)
    .fetch_one(&fixture.pool)
    .await
    .expect("read unchanged push item");
    assert_eq!(item_state.try_get::<i64, _>("version").expect("version"), 4);
    assert_eq!(
        item_state
            .try_get::<i64, _>("sync_status")
            .expect("sync status"),
        SyncStatus::Modified.as_i32() as i64
    );
    let pending_len = sqlx_core::query::query::<Sqlite>(
        "SELECT length(payload_enc) AS payload_len FROM pending_changes WHERE item_id = ?1",
    )
    .bind(original.id)
    .fetch_one(&fixture.pool)
    .await
    .expect("read unchanged pending scalar")
    .try_get::<i64, _>("payload_len")
    .expect("pending payload length");
    assert_eq!(pending_len, 262_401);
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-1")
    );
}

async fn cursor(pool: &SqlitePool, scope: LocalSyncScope) -> Option<String> {
    SyncCursorRepo::new(pool)
        .get(scope.storage_id, scope.vault_id)
        .await
        .expect("read cursor")
        .and_then(|row| row.cursor)
}

async fn row_count(pool: &SqlitePool, table: &str, storage_id: Uuid) -> i64 {
    let sql = format!("SELECT COUNT(*) AS count FROM {table} WHERE storage_id = ?1");
    sqlx_core::query::query::<Sqlite>(&sql)
        .bind(storage_id)
        .fetch_one(pool)
        .await
        .expect("count rows")
        .try_get("count")
        .expect("decode count")
}

async fn history_checksums(pool: &SqlitePool, scope: LocalSyncScope, item_id: Uuid) -> Vec<String> {
    sqlx_core::query::query::<Sqlite>(
        r#"
        SELECT checksum
        FROM item_history
        WHERE storage_id = ?1 AND vault_id = ?2 AND item_id = ?3
        ORDER BY version
        "#,
    )
    .bind(scope.storage_id)
    .bind(scope.vault_id)
    .bind(item_id)
    .fetch_all(pool)
    .await
    .expect("read scoped history")
    .into_iter()
    .map(|row| row.try_get("checksum").expect("decode history checksum"))
    .collect()
}

#[test]
fn local_projection_debug_output_redacts_payload_and_binding_values() {
    let scope = LocalSyncScope {
        storage_id: Uuid::now_v7(),
        vault_id: Uuid::now_v7(),
    };
    let local_item = item(
        scope,
        Uuid::now_v7(),
        "accounts/debug-secret-path",
        "debug-secret-checksum",
        2,
        SyncStatus::Modified,
    );
    let local_pending = pending(scope, &local_item, ChangeType::Update);
    let local_history = history(scope, local_item.id, 1, "debug-secret-history");
    let local_storage = remote_storage(
        scope.storage_id,
        "https://debug-secret.example",
        "debug-secret-fingerprint",
    );

    let item_debug = format!("{local_item:?}");
    assert!(!item_debug.contains("debug-secret-path"));
    assert!(!item_debug.contains(local_item.checksum.as_str()));
    assert!(!item_debug.contains("[2, 20, 30]"));
    let pending_debug = format!("{local_pending:?}");
    assert!(!pending_debug.contains("debug-secret-path"));
    assert!(!pending_debug.contains(local_item.checksum.as_str()));
    let history_debug = format!("{local_history:?}");
    assert!(!history_debug.contains(local_history.checksum.as_str()));
    assert!(!history_debug.contains("sync@example.test"));
    let storage_debug = format!("{local_storage:?}");
    assert!(!storage_debug.contains("debug-secret.example"));
    assert!(!storage_debug.contains("debug-secret-fingerprint"));
}

#[tokio::test]
async fn local_vault_round_trip_uses_slug_identity_and_allows_duplicate_display_names() {
    let fixture = fixture().await;
    let second_scope = LocalSyncScope {
        storage_id: fixture.scope.storage_id,
        vault_id: Uuid::now_v7(),
    };
    let mut second = vault(second_scope, "Primary");
    second.slug = "second_remote_vault".to_string();
    second.cache_key_fp = Some("ffeeddccbbaa".to_string());
    LocalVaultRepo::new(&fixture.pool)
        .create(&second)
        .await
        .expect("duplicate display name with a distinct slug");

    let stored = LocalVaultRepo::new(&fixture.pool)
        .get_by_slug(fixture.scope.storage_id, &second.slug)
        .await
        .expect("lookup vault by slug")
        .expect("vault exists");
    assert_eq!(stored.id, second.id);
    assert_eq!(stored.slug, second.slug);
    assert_eq!(stored.name, "Primary");
    assert_eq!(stored.cache_key_fp.as_deref(), Some("ffeeddccbbaa"));

    let mut duplicate_slug = vault(
        LocalSyncScope {
            storage_id: fixture.scope.storage_id,
            vault_id: Uuid::now_v7(),
        },
        "Another display name",
    );
    duplicate_slug.slug = second.slug.clone();
    assert!(LocalVaultRepo::new(&fixture.pool)
        .create(&duplicate_slug)
        .await
        .is_err());
}

#[tokio::test]
async fn local_vault_create_rejects_the_201st_row_without_poisoning_bounded_list() {
    let fixture = fixture().await;
    let repo = LocalVaultRepo::new(&fixture.pool);
    for index in 0..199 {
        let scope = LocalSyncScope {
            storage_id: fixture.scope.storage_id,
            vault_id: Uuid::now_v7(),
        };
        let mut extra = vault(scope, "Duplicate display name");
        extra.slug = format!("bounded_{index:03}");
        repo.create(&extra).await.expect("insert bounded vault row");
    }

    let overflow_scope = LocalSyncScope {
        storage_id: fixture.scope.storage_id,
        vault_id: Uuid::now_v7(),
    };
    let mut overflow = vault(overflow_scope, "Overflow");
    overflow.slug = "bounded_overflow".to_string();
    let error = repo
        .create(&overflow)
        .await
        .expect_err("the 201st vault must be rejected");
    assert!(error
        .to_string()
        .contains("vault count exceeds the supported range"));
    let listed = repo
        .list_by_storage(fixture.scope.storage_id)
        .await
        .expect("rejected write must leave a readable bounded catalog");
    assert_eq!(listed.len(), 200);
    assert!(repo
        .get_by_id(fixture.scope.storage_id, overflow_scope.vault_id)
        .await
        .expect("lookup rejected vault")
        .is_none());
}

#[tokio::test]
async fn concurrent_local_vault_creates_serialize_at_the_hard_cap() {
    let fixture = fixture_with_max_connections(2).await;
    let repo = LocalVaultRepo::new(&fixture.pool);
    for index in 0..198 {
        let scope = LocalSyncScope {
            storage_id: fixture.scope.storage_id,
            vault_id: Uuid::now_v7(),
        };
        let mut extra = vault(scope, "Capacity fill");
        extra.slug = format!("capacity_{index:03}");
        repo.create(&extra).await.expect("fill to 199 vaults");
    }

    let first_pool = fixture.pool.clone();
    let second_pool = fixture.pool.clone();
    let storage_id = fixture.scope.storage_id;
    let first = tokio::spawn(async move {
        let scope = LocalSyncScope {
            storage_id,
            vault_id: Uuid::now_v7(),
        };
        let mut candidate = vault(scope, "Concurrent first");
        candidate.slug = "concurrent_first".to_string();
        LocalVaultRepo::new(&first_pool).create(&candidate).await
    });
    let second = tokio::spawn(async move {
        let scope = LocalSyncScope {
            storage_id,
            vault_id: Uuid::now_v7(),
        };
        let mut candidate = vault(scope, "Concurrent second");
        candidate.slug = "concurrent_second".to_string();
        LocalVaultRepo::new(&second_pool).create(&candidate).await
    });
    let (first, second) = tokio::join!(first, second);
    let first = first.expect("first create task");
    let second = second.expect("second create task");
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(
        repo.list_by_storage(storage_id)
            .await
            .expect("bounded vault list")
            .len(),
        200
    );
}

#[tokio::test]
async fn concurrent_default_local_personal_ensure_returns_one_row_and_one_id() {
    let pool = empty_migrated_pool(2).await;
    let first_pool = pool.clone();
    let second_pool = pool.clone();
    let first_candidate = default_local_personal_candidate(Uuid::now_v7());
    let second_candidate = default_local_personal_candidate(Uuid::now_v7());
    assert_ne!(first_candidate.id, second_candidate.id);

    let first = tokio::spawn(async move {
        LocalVaultRepo::new(&first_pool)
            .ensure_default_local_personal(&first_candidate)
            .await
    });
    let second = tokio::spawn(async move {
        LocalVaultRepo::new(&second_pool)
            .ensure_default_local_personal(&second_candidate)
            .await
    });
    let first = first
        .await
        .expect("first ensure task")
        .expect("first ensure");
    let second = second
        .await
        .expect("second ensure task")
        .expect("second ensure");
    assert_eq!(first.id, second.id);
    let listed = LocalVaultRepo::new(&pool)
        .list_by_storage(Uuid::nil())
        .await
        .expect("list local vaults");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, first.id);
}

#[tokio::test]
async fn default_local_personal_ensure_rejects_multiple_semantic_defaults() {
    let pool = empty_migrated_pool(1).await;
    let repo = LocalVaultRepo::new(&pool);
    repo.create(&default_local_personal_candidate(Uuid::now_v7()))
        .await
        .expect("insert first default");
    let mut second = default_local_personal_candidate(Uuid::now_v7());
    second.name = "Another personal default".to_string();
    repo.create(&second)
        .await
        .expect("insert corrupt second default");

    let candidate = default_local_personal_candidate(Uuid::now_v7());
    let error = repo
        .ensure_default_local_personal(&candidate)
        .await
        .expect_err("multiple semantic defaults must fail closed");
    assert!(error
        .to_string()
        .contains("multiple default local personal vaults"));
}

#[tokio::test]
async fn cache_key_fingerprint_bind_is_exact_empty_and_idempotent() {
    let pool = empty_migrated_pool(1).await;
    let storage = remote_storage(
        Uuid::now_v7(),
        "https://bind-empty.example",
        "bind-empty-fingerprint",
    );
    LocalStorageRepo::new(&pool)
        .upsert(&storage)
        .await
        .expect("insert storage");
    let scope = LocalSyncScope {
        storage_id: storage.id,
        vault_id: Uuid::now_v7(),
    };
    let mut candidate = vault(scope, "Bind target");
    candidate.cache_key_fp = None;
    LocalVaultRepo::new(&pool)
        .create(&candidate)
        .await
        .expect("insert empty vault");
    let repo = LocalVaultRepo::new(&pool);

    assert_eq!(
        repo.bind_cache_key_fingerprint(
            scope.storage_id,
            scope.vault_id,
            &candidate.vault_key_enc,
            candidate.key_wrap_type,
            "aabbccddeeff",
        )
        .await
        .expect("bind empty vault"),
        CacheKeyFingerprintBind::Bound
    );
    assert_eq!(
        repo.bind_cache_key_fingerprint(
            scope.storage_id,
            scope.vault_id,
            &candidate.vault_key_enc,
            candidate.key_wrap_type,
            "aabbccddeeff",
        )
        .await
        .expect("repeat exact bind"),
        CacheKeyFingerprintBind::AlreadyBound
    );
    let stored = repo
        .get_by_id(scope.storage_id, scope.vault_id)
        .await
        .expect("read bound vault")
        .expect("bound vault exists");
    assert_eq!(stored.cache_key_fp.as_deref(), Some("aabbccddeeff"));

    for (envelope, wrap, fingerprint) in [
        (&[9, 9, 9][..], candidate.key_wrap_type, "aabbccddeeff"),
        (
            candidate.vault_key_enc.as_slice(),
            candidate.key_wrap_type,
            "001122aabbcc",
        ),
    ] {
        let error = repo
            .bind_cache_key_fingerprint(
                scope.storage_id,
                scope.vault_id,
                envelope,
                wrap,
                fingerprint,
            )
            .await
            .expect_err("mismatched binding proof must fail");
        assert!(matches!(error, LocalVaultKeyBindError::KeyBindingChanged));
    }
    assert!(matches!(
        repo.bind_cache_key_fingerprint(
            scope.storage_id,
            scope.vault_id,
            &candidate.vault_key_enc,
            KeyWrapType::Master,
            "aabbccddeeff",
        )
        .await,
        Err(LocalVaultKeyBindError::InvalidInput)
    ));
    let unchanged = repo
        .get_by_id(scope.storage_id, scope.vault_id)
        .await
        .expect("read unchanged vault")
        .expect("vault remains");
    assert_eq!(unchanged.vault_key_enc, candidate.vault_key_enc);
    assert_eq!(unchanged.cache_key_fp.as_deref(), Some("aabbccddeeff"));
}

#[tokio::test]
async fn cache_key_fingerprint_batch_preflights_all_rows_before_any_bind() {
    let pool = empty_migrated_pool(1).await;
    let storage = remote_storage(
        Uuid::now_v7(),
        "https://bind-batch.example",
        "bind-batch-fingerprint",
    );
    LocalStorageRepo::new(&pool)
        .upsert(&storage)
        .await
        .expect("insert storage");
    let first_scope = LocalSyncScope {
        storage_id: storage.id,
        vault_id: Uuid::now_v7(),
    };
    let second_scope = LocalSyncScope {
        storage_id: storage.id,
        vault_id: Uuid::now_v7(),
    };
    let mut first = vault(first_scope, "First batch vault");
    first.cache_key_fp = None;
    first.is_default = false;
    let mut second = vault(second_scope, "Second batch vault");
    second.cache_key_fp = None;
    second.is_default = false;
    let repository = LocalVaultRepo::new(&pool);
    repository.create(&first).await.expect("insert first vault");
    repository
        .create(&second)
        .await
        .expect("insert second vault");
    let projected = item(
        second_scope,
        Uuid::now_v7(),
        "accounts/nonempty-batch",
        "nonempty-batch",
        1,
        SyncStatus::Synced,
    );
    insert_item(&pool, &projected).await;

    let bindings = [
        cache_binding(&first, "001122aabbcc"),
        cache_binding(&second, "ffeeddccbbaa"),
    ];
    let proof = storage_proof(&storage);
    let error = repository
        .bind_cache_key_fingerprints(&proof, &bindings)
        .await
        .expect_err("one nonempty projection must reject the complete batch");
    assert!(matches!(error, LocalVaultKeyBindError::ProjectionNotEmpty));
    for scope in [first_scope, second_scope] {
        let stored = repository
            .get_by_id(scope.storage_id, scope.vault_id)
            .await
            .expect("read vault after rejected batch")
            .expect("vault remains");
        assert_eq!(stored.cache_key_fp, None);
    }
}

#[tokio::test]
async fn cache_key_fingerprint_batch_binds_multiple_rows_atomically_and_is_idempotent() {
    let pool = empty_migrated_pool(1).await;
    let storage = remote_storage(
        Uuid::now_v7(),
        "https://bind-batch-success.example",
        "bind-batch-success-fingerprint",
    );
    LocalStorageRepo::new(&pool)
        .upsert(&storage)
        .await
        .expect("insert storage");
    let scopes = [
        LocalSyncScope {
            storage_id: storage.id,
            vault_id: Uuid::now_v7(),
        },
        LocalSyncScope {
            storage_id: storage.id,
            vault_id: Uuid::now_v7(),
        },
    ];
    let mut vaults = [
        vault(scopes[0], "First batch vault"),
        vault(scopes[1], "Second batch vault"),
    ];
    for target in &mut vaults {
        target.cache_key_fp = None;
        target.is_default = false;
        LocalVaultRepo::new(&pool)
            .create(target)
            .await
            .expect("insert batch vault");
    }
    let fingerprints = ["001122aabbcc", "ffeeddccbbaa"];
    let bindings = vaults
        .iter()
        .zip(fingerprints)
        .map(|(vault, target_cache_key_fp)| cache_binding(vault, target_cache_key_fp))
        .collect::<Vec<_>>();
    let proof = storage_proof(&storage);
    let first = LocalVaultRepo::new(&pool)
        .bind_cache_key_fingerprints(&proof, &bindings)
        .await
        .expect("bind complete batch");
    assert_eq!(first.bound(), 2);
    assert_eq!(first.already_bound(), 0);
    let repeated = LocalVaultRepo::new(&pool)
        .bind_cache_key_fingerprints(&proof, &bindings)
        .await
        .expect("repeat exact batch");
    assert_eq!(repeated.bound(), 0);
    assert_eq!(repeated.already_bound(), 2);
}

#[tokio::test]
async fn cache_key_fingerprint_batch_preflights_corrupt_catalog_before_any_update() {
    let pool = empty_migrated_pool(1).await;
    let storage = remote_storage(
        Uuid::now_v7(),
        "https://bind-corrupt.example",
        "bind-corrupt-fingerprint",
    );
    LocalStorageRepo::new(&pool)
        .upsert(&storage)
        .await
        .expect("insert corrupt-batch storage");
    let scopes = [
        LocalSyncScope {
            storage_id: storage.id,
            vault_id: Uuid::now_v7(),
        },
        LocalSyncScope {
            storage_id: storage.id,
            vault_id: Uuid::now_v7(),
        },
    ];
    let mut vaults = [
        vault(scopes[0], "First corrupt batch vault"),
        vault(scopes[1], "Second corrupt batch vault"),
    ];
    for target in &mut vaults {
        target.cache_key_fp = None;
        target.is_default = false;
        LocalVaultRepo::new(&pool)
            .create(target)
            .await
            .expect("insert corrupt-batch vault");
    }
    let bindings = [
        cache_binding(&vaults[0], "001122aabbcc"),
        cache_binding(&vaults[1], "ffeeddccbbaa"),
    ];
    sqlx_core::query::query::<Sqlite>("PRAGMA ignore_check_constraints = ON")
        .execute(&pool)
        .await
        .expect("allow legacy catalog corruption fixture");
    sqlx_core::query::query::<Sqlite>("DROP TRIGGER local_vaults_v2_validate_update")
        .execute(&pool)
        .await
        .expect("disable catalog validation for legacy corruption fixture");
    sqlx_core::query::query::<Sqlite>(
        "UPDATE local_vaults SET vault_key_enc = zeroblob(65537) WHERE id = ?1",
    )
    .bind(scopes[1].vault_id)
    .execute(&pool)
    .await
    .expect("install oversized catalog envelope");

    let error = LocalVaultRepo::new(&pool)
        .bind_cache_key_fingerprints(&storage_proof(&storage), &bindings)
        .await
        .expect_err("corrupt catalog must reject complete batch");
    assert!(matches!(error, LocalVaultKeyBindError::KeyBindingChanged));
    let bound = sqlx_core::query::query::<Sqlite>(
        "SELECT COUNT(*) AS count FROM local_vaults WHERE storage_id = ?1 AND cache_key_fp IS NOT NULL",
    )
    .bind(storage.id)
    .fetch_one(&pool)
    .await
    .expect("count catalog bindings after rejection")
    .try_get::<i64, _>("count")
    .expect("decode catalog binding count");
    assert_eq!(bound, 0);
}

#[tokio::test]
async fn empty_catalog_binding_is_an_atomic_exact_catalog_proof() {
    let pool = empty_migrated_pool(1).await;
    let storage = remote_storage(
        Uuid::now_v7(),
        "https://empty-catalog.example",
        "empty-catalog-fingerprint",
    );
    LocalStorageRepo::new(&pool)
        .upsert(&storage)
        .await
        .expect("insert empty-catalog storage");
    let proof = storage_proof(&storage);
    let exact_empty = LocalVaultRepo::new(&pool)
        .bind_cache_key_fingerprints(&proof, &[])
        .await
        .expect("prove exact empty catalog");
    assert_eq!(exact_empty.bound(), 0);
    assert_eq!(exact_empty.already_bound(), 0);

    let scope = LocalSyncScope {
        storage_id: storage.id,
        vault_id: Uuid::now_v7(),
    };
    LocalVaultRepo::new(&pool)
        .create(&vault(scope, "Concurrent catalog row"))
        .await
        .expect("insert catalog row");
    let error = LocalVaultRepo::new(&pool)
        .bind_cache_key_fingerprints(&proof, &[])
        .await
        .expect_err("nonempty catalog must reject empty proof");
    assert!(matches!(error, LocalVaultKeyBindError::KeyBindingChanged));
}

#[tokio::test]
async fn cache_key_fingerprint_batch_rejects_duplicate_cross_storage_and_oversized_inputs() {
    let pool = empty_migrated_pool(1).await;
    let repository = LocalVaultRepo::new(&pool);
    let storage = remote_storage(
        Uuid::now_v7(),
        "https://invalid-batch.example",
        "invalid-batch-fingerprint",
    );
    LocalStorageRepo::new(&pool)
        .upsert(&storage)
        .await
        .expect("insert batch input storage");
    let proof = storage_proof(&storage);
    let storage_id = storage.id;
    let vault_id = Uuid::now_v7();
    let binding = CacheKeyFingerprintBinding {
        storage_id,
        vault_id,
        expected_slug: "valid-slug",
        expected_name: "Valid name",
        expected_kind: VaultKind::Personal,
        expected_is_default: false,
        expected_vault_key_enc: &[1, 2, 3],
        expected_key_wrap_type: KeyWrapType::RemoteStrict,
        target_cache_key_fp: "001122aabbcc",
    };
    assert!(matches!(
        repository
            .bind_cache_key_fingerprints(&proof, &[binding, binding])
            .await,
        Err(LocalVaultKeyBindError::InvalidInput)
    ));

    let cross_storage = CacheKeyFingerprintBinding {
        storage_id: Uuid::now_v7(),
        vault_id: Uuid::now_v7(),
        ..binding
    };
    assert!(matches!(
        repository
            .bind_cache_key_fingerprints(&proof, &[binding, cross_storage])
            .await,
        Err(LocalVaultKeyBindError::InvalidInput)
    ));

    for invalid_metadata in [
        CacheKeyFingerprintBinding {
            expected_vault_key_enc: &[],
            ..binding
        },
        CacheKeyFingerprintBinding {
            expected_key_wrap_type: KeyWrapType::Master,
            ..binding
        },
    ] {
        assert!(matches!(
            repository
                .bind_cache_key_fingerprints(&proof, &[invalid_metadata])
                .await,
            Err(LocalVaultKeyBindError::InvalidInput)
        ));
    }

    let oversized = (0..201)
        .map(|_| CacheKeyFingerprintBinding {
            storage_id,
            vault_id: Uuid::now_v7(),
            ..binding
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        repository
            .bind_cache_key_fingerprints(&proof, &oversized)
            .await,
        Err(LocalVaultKeyBindError::InvalidInput)
    ));
}

#[tokio::test]
async fn concurrent_cache_key_fingerprint_binds_allow_only_one_distinct_key() {
    let pool = empty_migrated_pool(2).await;
    let storage = remote_storage(
        Uuid::now_v7(),
        "https://bind-race.example",
        "bind-race-fingerprint",
    );
    LocalStorageRepo::new(&pool)
        .upsert(&storage)
        .await
        .expect("insert storage");
    let scope = LocalSyncScope {
        storage_id: storage.id,
        vault_id: Uuid::now_v7(),
    };
    let mut target = vault(scope, "Bind race");
    target.cache_key_fp = None;
    LocalVaultRepo::new(&pool)
        .create(&target)
        .await
        .expect("insert empty vault");

    let first_pool = pool.clone();
    let second_pool = pool.clone();
    let first_envelope = target.vault_key_enc.clone();
    let second_envelope = target.vault_key_enc.clone();
    let first = tokio::spawn(async move {
        LocalVaultRepo::new(&first_pool)
            .bind_cache_key_fingerprint(
                scope.storage_id,
                scope.vault_id,
                &first_envelope,
                target.key_wrap_type,
                "001122aabbcc",
            )
            .await
    });
    let second = tokio::spawn(async move {
        LocalVaultRepo::new(&second_pool)
            .bind_cache_key_fingerprint(
                scope.storage_id,
                scope.vault_id,
                &second_envelope,
                target.key_wrap_type,
                "ffeeddccbbaa",
            )
            .await
    });
    let first = first.await.expect("first bind task");
    let second = second.await.expect("second bind task");
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let loser = if first.is_err() { first } else { second };
    assert!(matches!(
        loser,
        Err(LocalVaultKeyBindError::KeyBindingChanged)
    ));
    let stored = LocalVaultRepo::new(&pool)
        .get_by_id(scope.storage_id, scope.vault_id)
        .await
        .expect("read race winner")
        .expect("vault remains");
    assert!(matches!(
        stored.cache_key_fp.as_deref(),
        Some("001122aabbcc" | "ffeeddccbbaa")
    ));
}

#[tokio::test]
async fn cache_key_fingerprint_bind_rejects_cross_storage_projection_references() {
    for reference in ["item", "checkpoint", "pending", "history"] {
        let pool = empty_migrated_pool(1).await;
        let target_storage = remote_storage(
            Uuid::now_v7(),
            "https://bind-target.example",
            "bind-target-fingerprint",
        );
        let foreign_storage = LocalStorage {
            id: Uuid::now_v7(),
            kind: StorageKind::LocalOnly,
            name: "Foreign local storage".to_string(),
            server_url: None,
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: true,
            auth_method: None,
        };
        let storage_repo = LocalStorageRepo::new(&pool);
        storage_repo
            .upsert(&target_storage)
            .await
            .expect("insert target storage");
        storage_repo
            .upsert(&foreign_storage)
            .await
            .expect("insert foreign storage");
        let target_scope = LocalSyncScope {
            storage_id: target_storage.id,
            vault_id: Uuid::now_v7(),
        };
        let mut target_vault = vault(target_scope, "Bind target");
        target_vault.cache_key_fp = None;
        LocalVaultRepo::new(&pool)
            .create(&target_vault)
            .await
            .expect("insert empty target vault");
        let foreign_scope = LocalSyncScope {
            storage_id: foreign_storage.id,
            vault_id: target_scope.vault_id,
        };
        let projected_item = item(
            foreign_scope,
            Uuid::now_v7(),
            "accounts/cross-storage-bind",
            "cross-storage-bind",
            1,
            SyncStatus::Synced,
        );
        match reference {
            "item" => insert_item(&pool, &projected_item).await,
            "checkpoint" => SyncCursorRepo::new(&pool)
                .upsert_checkpoint(&LocalSyncCheckpoint {
                    storage_id: foreign_scope.storage_id,
                    vault_id: foreign_scope.vault_id,
                    cursor: Some("foreign-cursor".to_string()),
                    last_seq: Some(1),
                    last_sync_at: Some(timestamp(1)),
                })
                .await
                .expect("insert foreign checkpoint"),
            "pending" => {
                insert_pending(
                    &pool,
                    &pending(foreign_scope, &projected_item, ChangeType::Create),
                )
                .await
            }
            "history" => LocalItemHistoryRepo::new(&pool)
                .create(&history(
                    foreign_scope,
                    projected_item.id,
                    1,
                    "foreign-history",
                ))
                .await
                .expect("insert foreign history"),
            _ => unreachable!("fixed reference case"),
        }

        let error = LocalVaultRepo::new(&pool)
            .bind_cache_key_fingerprint(
                target_scope.storage_id,
                target_scope.vault_id,
                &target_vault.vault_key_enc,
                target_vault.key_wrap_type,
                "aabbccddeeff",
            )
            .await
            .expect_err("any cross-storage projection reference must block binding");
        assert!(
            matches!(error, LocalVaultKeyBindError::ProjectionNotEmpty),
            "reference={reference}, error={error:?}"
        );
        let stored = LocalVaultRepo::new(&pool)
            .get_by_id(target_scope.storage_id, target_scope.vault_id)
            .await
            .expect("read unbound vault")
            .expect("target vault exists");
        assert_eq!(stored.cache_key_fp, None, "reference={reference}");
    }
}

#[tokio::test]
async fn local_vault_schema_rejects_noncanonical_or_oversized_fields() {
    let fixture = fixture().await;
    let repo = LocalVaultRepo::new(&fixture.pool);

    let mut uppercase_internal_slug = vault(
        LocalSyncScope {
            storage_id: fixture.scope.storage_id,
            vault_id: Uuid::now_v7(),
        },
        "Uppercase internal slug",
    );
    uppercase_internal_slug.slug = format!("local::{}", "A".repeat(32));
    assert!(repo.create(&uppercase_internal_slug).await.is_err());

    let mut uppercase_fingerprint = vault(
        LocalSyncScope {
            storage_id: fixture.scope.storage_id,
            vault_id: Uuid::now_v7(),
        },
        "Uppercase fingerprint",
    );
    uppercase_fingerprint.cache_key_fp = Some("001122AABBCC".to_string());
    assert!(repo.create(&uppercase_fingerprint).await.is_err());

    let mut oversized_name = vault(
        LocalSyncScope {
            storage_id: fixture.scope.storage_id,
            vault_id: Uuid::now_v7(),
        },
        "placeholder",
    );
    oversized_name.name = "é".repeat(101);
    assert!(repo.create(&oversized_name).await.is_err());

    let mut empty_name = vault(
        LocalSyncScope {
            storage_id: fixture.scope.storage_id,
            vault_id: Uuid::now_v7(),
        },
        "placeholder",
    );
    empty_name.name.clear();
    assert!(repo.create(&empty_name).await.is_err());

    let mut oversized_envelope = vault(
        LocalSyncScope {
            storage_id: fixture.scope.storage_id,
            vault_id: Uuid::now_v7(),
        },
        "Oversized envelope",
    );
    oversized_envelope.vault_key_enc = vec![0; 65_537];
    assert!(repo.create(&oversized_envelope).await.is_err());

    assert!(repo
        .update_key(
            fixture.scope.storage_id,
            fixture.scope.vault_id,
            &vec![0; 65_537],
            KeyWrapType::RemoteStrict,
        )
        .await
        .is_err());
    let unchanged = repo
        .get_by_id(fixture.scope.storage_id, fixture.scope.vault_id)
        .await
        .expect("read vault after rejected key update")
        .expect("vault remains");
    assert_eq!(unchanged.vault_key_enc, vec![7, 8, 9]);
    assert_eq!(unchanged.cache_key_fp.as_deref(), Some("001122aabbcc"));
}

#[tokio::test]
async fn pull_requires_canonical_matching_vault_cache_key_fingerprint() {
    let fixture = fixture().await;
    let matching = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(1),
        "cursor-2".to_string(),
        Some(2),
        timestamp(2),
        Vec::new(),
    )
    .expect("canonical matching fingerprint plan");
    LocalSyncRepo::new(&fixture.pool)
        .commit_pull_page(&matching)
        .await
        .expect("matching vault-key proof commits");
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-2")
    );

    let invalid = PullPage::new(
        fixture.scope,
        "001122AABBCC".to_string(),
        Some("cursor-2".to_string()),
        Some(2),
        "cursor-3".to_string(),
        Some(3),
        timestamp(3),
        Vec::new(),
    );
    assert!(matches!(invalid, Err(LocalSyncError::InvalidPlan { .. })));

    let mismatched = PullPage::new(
        fixture.scope,
        "ffeeddccbbaa".to_string(),
        Some("cursor-2".to_string()),
        Some(2),
        "cursor-3".to_string(),
        Some(3),
        timestamp(3),
        Vec::new(),
    )
    .expect("canonical mismatched fingerprint plan");
    let error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .commit_pull_page(&mismatched)
            .await,
        "mismatched vault-key proof must fail",
    );
    assert!(matches!(error, LocalSyncError::StaleVaultKey { .. }));
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-2")
    );
}

#[tokio::test]
async fn key_rotation_clears_fingerprint_and_blocks_empty_and_nonempty_pull_writes() {
    let fixture = fixture().await;
    let item_id = Uuid::now_v7();
    let original = item(
        fixture.scope,
        item_id,
        "accounts/key-rotation",
        "key-rotation-original",
        1,
        SyncStatus::Synced,
    );
    insert_item(&fixture.pool, &original).await;

    assert_eq!(
        LocalVaultRepo::new(&fixture.pool)
            .update_key(
                fixture.scope.storage_id,
                fixture.scope.vault_id,
                &[9, 8, 7],
                KeyWrapType::RemoteStrict,
            )
            .await
            .expect("rotate vault envelope"),
        1
    );
    let rotated = LocalVaultRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, fixture.scope.vault_id)
        .await
        .expect("read rotated vault")
        .expect("rotated vault exists");
    assert_eq!(rotated.vault_key_enc, vec![9, 8, 7]);
    assert_eq!(rotated.cache_key_fp, None);

    let empty = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(1),
        "cursor-empty".to_string(),
        Some(2),
        timestamp(2),
        Vec::new(),
    )
    .expect("empty post-rotation page");
    let empty_error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .commit_pull_page(&empty)
            .await,
        "empty pull must not bypass the vault-key CAS",
    );
    assert!(matches!(empty_error, LocalSyncError::StaleVaultKey { .. }));

    let mut projected = original.clone();
    projected.version = 2;
    projected.updated_at = timestamp(2);
    projected.checksum = canonical_checksum("key-rotation-projected");
    let change = PullChange::new(fixture.scope, exact(&original), projected, Vec::new())
        .expect("valid post-rotation item projection");
    let nonempty = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(1),
        "cursor-nonempty".to_string(),
        Some(2),
        timestamp(2),
        vec![change],
    )
    .expect("nonempty post-rotation page");
    let nonempty_error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .commit_pull_page(&nonempty)
            .await,
        "nonempty pull must not bypass the vault-key CAS",
    );
    assert!(matches!(
        nonempty_error,
        LocalSyncError::StaleVaultKey { .. }
    ));

    let stored = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, item_id)
        .await
        .expect("read item after rejected pulls")
        .expect("item remains");
    assert_eq!(stored.version, 1);
    assert_eq!(stored.checksum, original.checksum);
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-1")
    );
    assert_eq!(
        row_count(&fixture.pool, "item_history", fixture.scope.storage_id).await,
        0
    );
}

#[tokio::test]
async fn commit_push_updates_items_deletes_exact_pending_and_keeps_pull_cursor() {
    let fixture = fixture().await;
    let item_id = Uuid::now_v7();
    let local = item(
        fixture.scope,
        item_id,
        "accounts/main",
        "checksum-local",
        4,
        SyncStatus::Modified,
    );
    insert_item(&fixture.pool, &local).await;
    let local_pending = pending(fixture.scope, &local, ChangeType::Update);
    insert_pending(&fixture.pool, &local_pending).await;

    let mut projected = local.clone();
    projected.version = 5;
    projected.updated_at = timestamp(5);
    projected.sync_status = SyncStatus::Synced;
    let applied_outcome = PushOutcome::applied(
        fixture.scope,
        stored_proof(&fixture.pool, fixture.scope.storage_id, item_id).await,
        exact(&local),
        projected,
    )
    .expect("valid applied outcome");
    let plan = PushCommit::new(
        fixture.scope,
        Some("cursor-1".to_string()),
        Some(1),
        "server-head-9".to_string(),
        vec![applied_outcome],
    )
    .expect("valid push plan");
    let receipt = LocalSyncRepo::new(&fixture.pool)
        .commit_push(&plan)
        .await
        .expect("commit push");

    assert_eq!(receipt.applied(), 1);
    assert_eq!(receipt.pending_deleted(), 1);
    assert_eq!(receipt.server_head_hint(), "server-head-9");
    assert_eq!(receipt.last_seq(), Some(1));
    let stored = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, item_id)
        .await
        .expect("read item")
        .expect("item exists");
    assert_eq!(stored.version, 5);
    assert_eq!(stored.sync_status, SyncStatus::Synced);
    assert!(PendingChangeRepo::new(&fixture.pool)
        .list_by_storage(fixture.scope.storage_id)
        .await
        .expect("read pending")
        .is_empty());
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-1")
    );
    let checkpoint = SyncCursorRepo::new(&fixture.pool)
        .get_checkpoint(fixture.scope.storage_id, fixture.scope.vault_id)
        .await
        .expect("read push checkpoint")
        .expect("push checkpoint exists");
    assert_eq!(checkpoint.cursor.as_deref(), Some("cursor-1"));
    assert_eq!(checkpoint.last_seq, Some(1));
}

#[tokio::test]
async fn push_accepts_coalesced_create_update_restore_and_delete_above_pending_base() {
    let fixture = fixture().await;
    let created = item(
        fixture.scope,
        Uuid::now_v7(),
        "accounts/created",
        "checksum-created",
        7,
        SyncStatus::Modified,
    );
    let updated = item(
        fixture.scope,
        Uuid::now_v7(),
        "accounts/updated",
        "checksum-updated-local",
        9,
        SyncStatus::Modified,
    );
    let restored = item(
        fixture.scope,
        Uuid::now_v7(),
        "accounts/restored",
        "checksum-restored-local",
        11,
        SyncStatus::Modified,
    );
    let mut deleted = item(
        fixture.scope,
        Uuid::now_v7(),
        "accounts/deleted",
        "checksum-deleted-local",
        13,
        SyncStatus::Tombstone,
    );
    deleted.deleted_at = Some(timestamp(13));

    let create_pending = pending(fixture.scope, &created, ChangeType::Create);
    let mut update_pending = pending(fixture.scope, &updated, ChangeType::Update);
    update_pending.base_seq = Some(3);
    let mut restore_pending = pending(fixture.scope, &restored, ChangeType::Restore);
    restore_pending.base_seq = Some(5);
    let mut delete_pending = pending(fixture.scope, &deleted, ChangeType::Delete);
    delete_pending.base_seq = Some(7);
    for local in [&created, &updated, &restored, &deleted] {
        insert_item(&fixture.pool, local).await;
    }
    for pending in [
        &create_pending,
        &update_pending,
        &restore_pending,
        &delete_pending,
    ] {
        insert_pending(&fixture.pool, pending).await;
    }

    let mut created_projection = created.clone();
    created_projection.version = 1;
    created_projection.sync_status = SyncStatus::Synced;
    created_projection.updated_at = timestamp(21);
    let mut updated_projection = updated.clone();
    updated_projection.version = 4;
    updated_projection.sync_status = SyncStatus::Synced;
    updated_projection.updated_at = timestamp(22);
    let mut restored_projection = restored.clone();
    restored_projection.version = 6;
    restored_projection.sync_status = SyncStatus::Synced;
    restored_projection.updated_at = timestamp(23);
    let mut deleted_projection = deleted.clone();
    deleted_projection.version = 8;
    deleted_projection.sync_status = SyncStatus::Synced;
    deleted_projection.updated_at = timestamp(24);
    let outcomes = vec![
        PushOutcome::applied(
            fixture.scope,
            stored_proof(&fixture.pool, fixture.scope.storage_id, created.id).await,
            exact(&created),
            created_projection,
        )
        .expect("valid create relation"),
        PushOutcome::applied(
            fixture.scope,
            stored_proof(&fixture.pool, fixture.scope.storage_id, updated.id).await,
            exact(&updated),
            updated_projection,
        )
        .expect("valid coalesced update relation"),
        PushOutcome::applied(
            fixture.scope,
            stored_proof(&fixture.pool, fixture.scope.storage_id, restored.id).await,
            exact(&restored),
            restored_projection,
        )
        .expect("valid coalesced restore relation"),
        PushOutcome::applied(
            fixture.scope,
            stored_proof(&fixture.pool, fixture.scope.storage_id, deleted.id).await,
            exact(&deleted),
            deleted_projection,
        )
        .expect("valid coalesced delete relation"),
    ];
    let plan = PushCommit::new(
        fixture.scope,
        Some("cursor-1".to_string()),
        Some(1),
        "server-head-coalesced".to_string(),
        outcomes,
    )
    .expect("valid coalesced push plan");
    let receipt = LocalSyncRepo::new(&fixture.pool)
        .commit_push(&plan)
        .await
        .expect("commit coalesced push");
    assert_eq!(receipt.applied(), 4);
    assert_eq!(receipt.pending_deleted(), 4);
    assert!(PendingChangeRepo::new(&fixture.pool)
        .list_by_storage(fixture.scope.storage_id)
        .await
        .expect("read coalesced pending")
        .is_empty());
    for (item_id, expected_version, expected_deleted) in [
        (created.id, 1, false),
        (updated.id, 4, false),
        (restored.id, 6, false),
        (deleted.id, 8, true),
    ] {
        let stored = LocalItemRepo::new(&fixture.pool)
            .get_by_id(fixture.scope.storage_id, item_id)
            .await
            .expect("read relationally applied item")
            .expect("relationally applied item exists");
        assert_eq!(stored.version, expected_version);
        assert_eq!(stored.sync_status, SyncStatus::Synced);
        assert_eq!(stored.deleted_at.is_some(), expected_deleted);
    }
}

#[tokio::test]
async fn push_rejects_update_restore_and_delete_at_or_below_pending_base() {
    let fixture = fixture().await;
    for (operation, label, local_version, base_seq, applied_version) in [
        (ChangeType::Update, "update", 9, 3, 3),
        (ChangeType::Restore, "restore", 11, 5, 4),
        (ChangeType::Delete, "delete", 13, 7, 7),
    ] {
        let mut local = item(
            fixture.scope,
            Uuid::now_v7(),
            &format!("accounts/reject-{label}"),
            &format!("checksum-reject-{label}"),
            local_version,
            if operation == ChangeType::Delete {
                SyncStatus::Tombstone
            } else {
                SyncStatus::Modified
            },
        );
        if operation == ChangeType::Delete {
            local.deleted_at = Some(timestamp(local_version));
        }
        let mut pending_row = pending(fixture.scope, &local, operation);
        pending_row.base_seq = Some(base_seq);
        insert_item(&fixture.pool, &local).await;
        insert_pending(&fixture.pool, &pending_row).await;

        let mut applied = local.clone();
        applied.version = applied_version;
        applied.updated_at = timestamp(30 + applied_version);
        applied.sync_status = SyncStatus::Synced;
        let error = expect_sync_error(
            PushOutcome::applied(
                fixture.scope,
                stored_proof(&fixture.pool, fixture.scope.storage_id, local.id).await,
                exact(&local),
                applied,
            ),
            "applied sequence at or below the pending base must be rejected",
        );
        assert!(matches!(error, LocalSyncError::InvalidPlan { .. }));

        let stored = LocalItemRepo::new(&fixture.pool)
            .get_by_id(fixture.scope.storage_id, local.id)
            .await
            .expect("read rejected item")
            .expect("rejected item remains");
        assert_eq!(stored.version, local_version);
        assert_eq!(stored.payload_enc, local.payload_enc);
        assert_eq!(stored.sync_status, local.sync_status);
    }
    assert_eq!(
        row_count(&fixture.pool, "items_cache", fixture.scope.storage_id).await,
        3
    );
    assert_eq!(
        row_count(&fixture.pool, "pending_changes", fixture.scope.storage_id).await,
        3
    );
}

#[tokio::test]
async fn applied_delete_becomes_clean_tombstone_then_pull_can_restore_it() {
    let fixture = fixture().await;
    let item_id = Uuid::now_v7();
    let mut local_tombstone = item(
        fixture.scope,
        item_id,
        "accounts/delete-restore",
        "checksum-delete-restore",
        2,
        SyncStatus::Tombstone,
    );
    local_tombstone.deleted_at = Some(timestamp(2));
    insert_item(&fixture.pool, &local_tombstone).await;
    let deletion = pending(fixture.scope, &local_tombstone, ChangeType::Delete);
    insert_pending(&fixture.pool, &deletion).await;

    let mut clean_remote_tombstone = local_tombstone.clone();
    clean_remote_tombstone.version = 3;
    clean_remote_tombstone.updated_at = timestamp(3);
    clean_remote_tombstone.sync_status = SyncStatus::Synced;
    let applied = PushOutcome::applied(
        fixture.scope,
        stored_proof(&fixture.pool, fixture.scope.storage_id, item_id).await,
        exact(&local_tombstone),
        clean_remote_tombstone.clone(),
    )
    .expect("valid applied delete");
    let push = PushCommit::new(
        fixture.scope,
        Some("cursor-1".to_string()),
        Some(1),
        "server-head-delete".to_string(),
        vec![applied],
    )
    .expect("valid delete push");
    LocalSyncRepo::new(&fixture.pool)
        .commit_push(&push)
        .await
        .expect("commit applied delete");
    let stored_tombstone = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, item_id)
        .await
        .expect("read clean tombstone")
        .expect("clean tombstone exists");
    assert_eq!(stored_tombstone.sync_status, SyncStatus::Synced);
    assert!(stored_tombstone.deleted_at.is_some());

    let mut restored = clean_remote_tombstone;
    restored.version = 4;
    restored.payload_enc = vec![4, 40, 40];
    restored.checksum = canonical_checksum("checksum-restored");
    restored.deleted_at = None;
    restored.updated_at = timestamp(4);
    let change = PullChange::new(
        fixture.scope,
        exact(&stored_tombstone),
        restored,
        Vec::new(),
    )
    .expect("valid remote restore over clean tombstone");
    let page = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(1),
        "cursor-2".to_string(),
        Some(2),
        timestamp(4),
        vec![change],
    )
    .expect("valid restore pull page");
    LocalSyncRepo::new(&fixture.pool)
        .commit_pull_page(&page)
        .await
        .expect("restore clean tombstone");
    let stored = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, item_id)
        .await
        .expect("read restored item")
        .expect("restored item exists");
    assert_eq!(stored.sync_status, SyncStatus::Synced);
    assert!(stored.deleted_at.is_none());
    assert_eq!(stored.version, 4);
}

#[tokio::test]
async fn commit_pull_page_updates_and_inserts_full_item_history_then_cursor() {
    let fixture = fixture().await;
    let existing_id = Uuid::now_v7();
    let existing = item(
        fixture.scope,
        existing_id,
        "accounts/existing",
        "checksum-1",
        1,
        SyncStatus::Synced,
    );
    insert_item(&fixture.pool, &existing).await;
    LocalItemHistoryRepo::new(&fixture.pool)
        .create(&history(fixture.scope, existing_id, 1, "old-history"))
        .await
        .expect("insert old history");

    let mut updated = existing.clone();
    updated.version = 2;
    updated.checksum = canonical_checksum("checksum-2");
    updated.payload_enc = vec![2, 2, 2];
    updated.updated_at = timestamp(2);
    let updated_history = history(fixture.scope, existing_id, 1, "history-1");

    let inserted_id = Uuid::now_v7();
    let inserted = item(
        fixture.scope,
        inserted_id,
        "accounts/new",
        "checksum-new",
        1,
        SyncStatus::Synced,
    );
    let inserted_history = history(fixture.scope, inserted_id, 1, "new-history");

    let updated_change = PullChange::new(
        fixture.scope,
        exact(&existing),
        updated,
        vec![updated_history],
    )
    .expect("valid updated pull change");
    let inserted_change = PullChange::new(
        fixture.scope,
        LocalItemExpectation::Absent,
        inserted,
        vec![inserted_history],
    )
    .expect("valid inserted pull change");
    let page = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(1),
        "cursor-2".to_string(),
        Some(2),
        timestamp(20),
        vec![updated_change, inserted_change],
    )
    .expect("valid pull page");
    let receipt = LocalSyncRepo::new(&fixture.pool)
        .commit_pull_page(&page)
        .await
        .expect("commit pull");

    assert_eq!(receipt.items(), 2);
    assert_eq!(receipt.history_entries(), 2);
    assert_eq!(receipt.cursor(), "cursor-2");
    assert_eq!(receipt.last_seq(), Some(2));
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-2")
    );
    for (item_id, checksum) in [(existing_id, "checksum-2"), (inserted_id, "checksum-new")] {
        let stored = LocalItemRepo::new(&fixture.pool)
            .get_by_id(fixture.scope.storage_id, item_id)
            .await
            .expect("read projected item")
            .expect("projected item exists");
        assert_eq!(stored.checksum, canonical_checksum(checksum));
        let stored_history = LocalItemHistoryRepo::new(&fixture.pool)
            .list_by_item_limit(fixture.scope.storage_id, item_id, 10)
            .await
            .expect("read projected history");
        assert_eq!(stored_history.len(), 1);
        assert_ne!(
            stored_history[0].checksum,
            canonical_checksum("old-history")
        );
    }
}

#[tokio::test]
async fn pull_history_replaces_only_confirmed_server_rows_and_preserves_other_vault() {
    let fixture = fixture().await;
    let other_scope = LocalSyncScope {
        storage_id: fixture.scope.storage_id,
        vault_id: Uuid::now_v7(),
    };
    LocalVaultRepo::new(&fixture.pool)
        .create(&vault(other_scope, "Other Vault"))
        .await
        .expect("insert other vault");

    let item_id = Uuid::now_v7();
    let original = item(
        fixture.scope,
        item_id,
        "accounts/scoped-history",
        "checksum-scoped-2",
        2,
        SyncStatus::Synced,
    );
    insert_item(&fixture.pool, &original).await;
    LocalItemHistoryRepo::new(&fixture.pool)
        .create(&history(fixture.scope, item_id, 1, "history-primary-old"))
        .await
        .expect("insert primary history");
    let mut local_pending = history(fixture.scope, item_id, 10, "history-local-pending");
    local_pending.source = HistorySource::Local;
    local_pending.sync_status = HistorySyncStatus::Pending;
    let mut optimistic = history(fixture.scope, item_id, 11, "history-ui-optimistic");
    optimistic.source = HistorySource::UiOptimistic;
    let mut server_pending = history(fixture.scope, item_id, 12, "history-server-pending");
    server_pending.sync_status = HistorySyncStatus::Pending;
    let mut server_rejected = history(fixture.scope, item_id, 13, "history-server-rejected");
    server_rejected.sync_status = HistorySyncStatus::Rejected;
    for preserved in [local_pending, optimistic, server_pending, server_rejected] {
        LocalItemHistoryRepo::new(&fixture.pool)
            .create(&preserved)
            .await
            .expect("insert non-server-confirmed history");
    }
    LocalItemHistoryRepo::new(&fixture.pool)
        .create(&history(other_scope, item_id, 1, "history-other-keep"))
        .await
        .expect("insert other-vault history");

    let mut projected = original.clone();
    projected.version = 3;
    projected.checksum = canonical_checksum("checksum-scoped-3");
    projected.updated_at = timestamp(3);
    let change = PullChange::new(
        fixture.scope,
        exact(&original),
        projected,
        vec![history(fixture.scope, item_id, 2, "history-primary-new")],
    )
    .expect("valid scoped-history change");
    let page = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(1),
        "cursor-2".to_string(),
        Some(2),
        timestamp(3),
        vec![change],
    )
    .expect("valid scoped-history page");
    LocalSyncRepo::new(&fixture.pool)
        .commit_pull_page(&page)
        .await
        .expect("commit scoped-history page");

    assert_eq!(
        history_checksums(&fixture.pool, fixture.scope, item_id).await,
        vec![
            canonical_checksum("history-primary-new"),
            canonical_checksum("history-local-pending"),
            canonical_checksum("history-ui-optimistic"),
            canonical_checksum("history-server-pending"),
            canonical_checksum("history-server-rejected"),
        ]
    );
    assert_eq!(
        history_checksums(&fixture.pool, other_scope, item_id).await,
        vec![canonical_checksum("history-other-keep")]
    );
}

#[tokio::test]
async fn concurrent_writers_serialize_and_only_one_exact_pull_page_commits() {
    let fixture = fixture_with_max_connections(2).await;
    let item_id = Uuid::now_v7();
    let original = item(
        fixture.scope,
        item_id,
        "accounts/concurrent",
        "checksum-concurrent-1",
        1,
        SyncStatus::Synced,
    );
    insert_item(&fixture.pool, &original).await;

    let mut first_projection = original.clone();
    first_projection.version = 2;
    first_projection.checksum = canonical_checksum("checksum-concurrent-first");
    first_projection.updated_at = timestamp(2);
    let first_change = PullChange::new(
        fixture.scope,
        exact(&original),
        first_projection,
        Vec::new(),
    )
    .expect("valid first concurrent change");
    let first_page = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(1),
        "cursor-first".to_string(),
        Some(2),
        timestamp(2),
        vec![first_change],
    )
    .expect("valid first concurrent page");

    let mut second_projection = original.clone();
    second_projection.version = 2;
    second_projection.checksum = canonical_checksum("checksum-concurrent-second");
    second_projection.updated_at = timestamp(2);
    let second_change = PullChange::new(
        fixture.scope,
        exact(&original),
        second_projection,
        Vec::new(),
    )
    .expect("valid second concurrent change");
    let second_page = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(1),
        "cursor-second".to_string(),
        Some(2),
        timestamp(2),
        vec![second_change],
    )
    .expect("valid second concurrent page");

    let repo = LocalSyncRepo::new(&fixture.pool);
    let (first_result, second_result) = tokio::join!(
        repo.commit_pull_page(&first_page),
        repo.commit_pull_page(&second_page)
    );
    assert_ne!(first_result.is_ok(), second_result.is_ok());
    let rejected = if let Err(error) = first_result {
        error
    } else if let Err(error) = second_result {
        error
    } else {
        panic!("one concurrent pull page must be rejected")
    };
    assert!(matches!(
        rejected,
        LocalSyncError::StaleCursor { .. } | LocalSyncError::StaleItem { .. }
    ));

    let stored = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, item_id)
        .await
        .expect("read concurrent winner")
        .expect("concurrent winner exists");
    assert_eq!(stored.version, 2);
    let stored_cursor = cursor(&fixture.pool, fixture.scope)
        .await
        .expect("winner cursor");
    assert!(stored_cursor == "cursor-first" || stored_cursor == "cursor-second");
}

#[tokio::test]
async fn stale_cursor_rolls_back_without_changing_any_projection_row() {
    let fixture = fixture().await;
    let item_id = Uuid::now_v7();
    let original = item(
        fixture.scope,
        item_id,
        "accounts/stale-cursor",
        "checksum-1",
        1,
        SyncStatus::Synced,
    );
    insert_item(&fixture.pool, &original).await;
    let mut projected = original.clone();
    projected.version = 2;
    projected.checksum = canonical_checksum("checksum-2");

    let change = PullChange::new(fixture.scope, exact(&original), projected, Vec::new())
        .expect("valid pull change");
    let page = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("wrong-cursor".to_string()),
        Some(1),
        "cursor-2".to_string(),
        Some(2),
        timestamp(2),
        vec![change],
    )
    .expect("valid pull page");
    let error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .commit_pull_page(&page)
            .await,
        "cursor must be stale",
    );
    assert!(matches!(error, LocalSyncError::StaleCursor { .. }));
    let stored = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, item_id)
        .await
        .expect("read item")
        .expect("item exists");
    assert_eq!(stored.version, 1);
    assert_eq!(stored.checksum, canonical_checksum("checksum-1"));
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-1")
    );
}

#[tokio::test]
async fn last_seq_survives_restart_and_participates_in_checkpoint_cas() {
    let fixture = fixture().await;
    let item_id = Uuid::now_v7();
    let original = item(
        fixture.scope,
        item_id,
        "accounts/last-seq",
        "checksum-last-seq-1",
        1,
        SyncStatus::Synced,
    );
    insert_item(&fixture.pool, &original).await;

    let mut stale_projection = original.clone();
    stale_projection.version = 2;
    stale_projection.checksum = canonical_checksum("checksum-last-seq-stale");
    stale_projection.updated_at = timestamp(2);
    let stale_change = PullChange::new(
        fixture.scope,
        exact(&original),
        stale_projection,
        Vec::new(),
    )
    .expect("valid stale-sequence change");
    let stale_page = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(99),
        "cursor-stale-seq".to_string(),
        Some(100),
        timestamp(2),
        vec![stale_change],
    )
    .expect("valid stale-sequence page");
    let stale_error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .commit_pull_page(&stale_page)
            .await,
        "same cursor with stale last sequence must fail CAS",
    );
    assert!(matches!(stale_error, LocalSyncError::StaleCursor { .. }));

    // Close every connection and reopen the file to prove the sequence is
    // durable across a real SQLite restart.
    fixture.pool.close().await;
    let restarted_pool = connect_sqlite_with_max(&fixture.url, 1)
        .await
        .expect("reopen sqlite after restart");
    migrate_local(&restarted_pool)
        .await
        .expect("recheck migrations after restart");
    let restarted_checkpoint = SyncCursorRepo::new(&restarted_pool)
        .get_checkpoint(fixture.scope.storage_id, fixture.scope.vault_id)
        .await
        .expect("load restarted checkpoint")
        .expect("restarted checkpoint exists");
    assert_eq!(restarted_checkpoint.cursor.as_deref(), Some("cursor-1"));
    assert_eq!(restarted_checkpoint.last_seq, Some(1));

    let mut next_projection = original.clone();
    next_projection.version = 2;
    next_projection.checksum = canonical_checksum("checksum-last-seq-2");
    next_projection.updated_at = timestamp(2);
    let next_change = PullChange::new(fixture.scope, exact(&original), next_projection, Vec::new())
        .expect("valid successor change");
    let next_page = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        restarted_checkpoint.cursor,
        restarted_checkpoint.last_seq,
        "cursor-2".to_string(),
        Some(2),
        timestamp(2),
        vec![next_change],
    )
    .expect("valid successor page");
    let receipt = LocalSyncRepo::new(&restarted_pool)
        .commit_pull_page(&next_page)
        .await
        .expect("commit successor checkpoint");
    assert_eq!(receipt.cursor(), "cursor-2");
    assert_eq!(receipt.last_seq(), Some(2));
    let durable = SyncCursorRepo::new(&restarted_pool)
        .get_checkpoint(fixture.scope.storage_id, fixture.scope.vault_id)
        .await
        .expect("reload durable checkpoint")
        .expect("durable checkpoint exists");
    assert_eq!(durable.cursor.as_deref(), Some("cursor-2"));
    assert_eq!(durable.last_seq, Some(2));
}

#[tokio::test]
async fn stale_item_rolls_back_page_and_cursor() {
    let fixture = fixture().await;
    let item_id = Uuid::now_v7();
    let original = item(
        fixture.scope,
        item_id,
        "accounts/stale-item",
        "checksum-current",
        3,
        SyncStatus::Synced,
    );
    insert_item(&fixture.pool, &original).await;
    let mut projected = original.clone();
    projected.version = 4;
    projected.checksum = canonical_checksum("checksum-next");
    let mut stale = original.clone();
    stale.version = 2;
    stale.checksum = canonical_checksum("checksum-old");

    let change = PullChange::new(
        fixture.scope,
        exact(&stale),
        projected,
        vec![history(fixture.scope, item_id, 3, "history-next")],
    )
    .expect("valid stale pull change");
    let page = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(1),
        "cursor-2".to_string(),
        Some(2),
        timestamp(4),
        vec![change],
    )
    .expect("valid stale pull page");
    let error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .commit_pull_page(&page)
            .await,
        "item must be stale",
    );
    assert!(matches!(error, LocalSyncError::StaleItem { .. }));
    let stored = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, item_id)
        .await
        .expect("read item")
        .expect("item exists");
    assert_eq!(stored.version, 3);
    assert_eq!(stored.checksum, canonical_checksum("checksum-current"));
    assert!(LocalItemHistoryRepo::new(&fixture.pool)
        .list_by_item_limit(fixture.scope.storage_id, item_id, 10)
        .await
        .expect("read history")
        .is_empty());
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-1")
    );
}

#[tokio::test]
async fn concurrent_item_metadata_and_status_change_rolls_back_page_and_cursor() {
    let fixture = fixture().await;
    let item_id = Uuid::now_v7();
    let original = item(
        fixture.scope,
        item_id,
        "accounts/metadata-race",
        "checksum-metadata-1",
        2,
        SyncStatus::Synced,
    );
    insert_item(&fixture.pool, &original).await;

    let mut projected = original.clone();
    projected.version = 3;
    projected.checksum = canonical_checksum("checksum-metadata-3");
    projected.updated_at = timestamp(3);
    let change = PullChange::new(fixture.scope, exact(&original), projected, Vec::new())
        .expect("valid metadata-race pull change");
    let page = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(1),
        "cursor-2".to_string(),
        Some(2),
        timestamp(3),
        vec![change],
    )
    .expect("valid metadata-race pull page");

    let mut concurrent = original.clone();
    concurrent.name = "renamed-locally".to_string();
    concurrent.cache_key_fp = Some("ffeeddccbbaa".to_string());
    concurrent.sync_status = SyncStatus::Modified;
    LocalItemRepo::new(&fixture.pool)
        .update(&concurrent)
        .await
        .expect("apply concurrent metadata mutation");

    let error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .commit_pull_page(&page)
            .await,
        "full item proof must reject metadata race",
    );
    assert!(matches!(error, LocalSyncError::StaleItem { .. }));
    let stored = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, item_id)
        .await
        .expect("read concurrently changed item")
        .expect("concurrently changed item exists");
    assert_eq!(stored.name, "renamed-locally");
    assert_eq!(stored.sync_status, SyncStatus::Modified);
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-1")
    );
}

#[tokio::test]
async fn pull_plan_rejects_exact_dirty_item_before_database_mutation() {
    let fixture = fixture().await;
    let dirty = item(
        fixture.scope,
        Uuid::now_v7(),
        "accounts/dirty-pull",
        "checksum-dirty-pull",
        2,
        SyncStatus::Modified,
    );
    insert_item(&fixture.pool, &dirty).await;
    let mut projected = dirty.clone();
    projected.version = 3;
    projected.checksum = canonical_checksum("checksum-dirty-pull-server");
    projected.updated_at = timestamp(3);
    projected.sync_status = SyncStatus::Synced;
    let error = expect_sync_error(
        PullChange::new(fixture.scope, exact(&dirty), projected, Vec::new()),
        "pull must not overwrite a dirty exact item",
    );
    assert!(matches!(error, LocalSyncError::InvalidPlan { .. }));
    let stored = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, dirty.id)
        .await
        .expect("read rejected dirty pull item")
        .expect("dirty pull item exists");
    assert_eq!(stored.version, 2);
    assert_eq!(stored.sync_status, SyncStatus::Modified);
    let checkpoint = SyncCursorRepo::new(&fixture.pool)
        .get_checkpoint(fixture.scope.storage_id, fixture.scope.vault_id)
        .await
        .expect("read rejected dirty pull checkpoint")
        .expect("dirty pull checkpoint exists");
    assert_eq!(checkpoint.cursor.as_deref(), Some("cursor-1"));
    assert_eq!(checkpoint.last_seq, Some(1));
}

#[tokio::test]
async fn concurrent_pending_change_blocks_pull_page_and_cursor() {
    let fixture = fixture().await;
    let item_id = Uuid::now_v7();
    let original = item(
        fixture.scope,
        item_id,
        "accounts/pending-race",
        "checksum-pending-1",
        2,
        SyncStatus::Synced,
    );
    insert_item(&fixture.pool, &original).await;
    let original_history = history(fixture.scope, item_id, 2, "history-pending-2");
    LocalItemHistoryRepo::new(&fixture.pool)
        .create(&original_history)
        .await
        .expect("insert pending-race history");

    let mut projected = original.clone();
    projected.version = 3;
    projected.checksum = canonical_checksum("checksum-pending-3");
    projected.updated_at = timestamp(3);
    let replacement_history = history(fixture.scope, item_id, 3, "history-pending-3");
    let change = PullChange::new(
        fixture.scope,
        exact(&original),
        projected,
        vec![replacement_history],
    )
    .expect("valid pending-race pull change");
    let page = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(1),
        "cursor-2".to_string(),
        Some(2),
        timestamp(3),
        vec![change],
    )
    .expect("valid pending-race pull page");

    let concurrent_pending = pending(fixture.scope, &original, ChangeType::Update);
    insert_pending(&fixture.pool, &concurrent_pending).await;
    let error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .commit_pull_page(&page)
            .await,
        "pending row must block pull",
    );
    assert!(matches!(
        error,
        LocalSyncError::StalePending { pending_id }
            if pending_id == concurrent_pending.id
    ));
    let stored = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, item_id)
        .await
        .expect("read pending-race item")
        .expect("pending-race item exists");
    assert_eq!(stored.version, 2);
    assert_eq!(
        PendingChangeRepo::new(&fixture.pool)
            .list_by_item(fixture.scope.storage_id, item_id)
            .await
            .expect("read concurrent pending")
            .len(),
        1
    );
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-1")
    );
    assert_eq!(
        history_checksums(&fixture.pool, fixture.scope, item_id).await,
        vec![original_history.checksum]
    );
}

#[tokio::test]
async fn stored_pending_item_mismatch_is_rejected_without_changes() {
    let fixture = fixture().await;
    let item_id = Uuid::now_v7();
    let original = item(
        fixture.scope,
        item_id,
        "accounts/stale-pending",
        "checksum-local",
        5,
        SyncStatus::Modified,
    );
    insert_item(&fixture.pool, &original).await;
    let original_history = history(fixture.scope, item_id, 4, "history-stored-mismatch");
    LocalItemHistoryRepo::new(&fixture.pool)
        .create(&original_history)
        .await
        .expect("insert mismatch history");
    let mut mismatched_pending = pending(fixture.scope, &original, ChangeType::Update);
    mismatched_pending.payload_enc = Some(vec![99, 98, 97]);
    mismatched_pending.checksum = Some(canonical_checksum("different-pending-payload"));
    mismatched_pending.path = Some("accounts/stored-mismatch".to_string());
    mismatched_pending.name = Some("stored-mismatch".to_string());
    mismatched_pending.base_seq = Some(2);
    mismatched_pending.created_at = timestamp(99);
    insert_pending(&fixture.pool, &mismatched_pending).await;

    let mut projected = original.clone();
    projected.version = 6;
    projected.updated_at = timestamp(6);
    projected.sync_status = SyncStatus::Synced;
    let error = expect_sync_error(
        PushOutcome::applied(
            fixture.scope,
            stored_proof(&fixture.pool, fixture.scope.storage_id, item_id).await,
            exact(&original),
            projected,
        ),
        "stored pending and item rows must be relationally consistent",
    );
    assert!(matches!(error, LocalSyncError::InvalidPlan { .. }));
    let stored = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, item_id)
        .await
        .expect("read item")
        .expect("item exists");
    assert_eq!(stored.version, 5);
    assert_eq!(stored.sync_status, SyncStatus::Modified);
    assert_eq!(
        history_checksums(&fixture.pool, fixture.scope, item_id).await,
        vec![canonical_checksum("history-stored-mismatch")]
    );
    assert_eq!(
        PendingChangeRepo::new(&fixture.pool)
            .list_by_storage(fixture.scope.storage_id)
            .await
            .expect("read pending")
            .len(),
        1
    );
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-1")
    );
}

#[tokio::test]
async fn push_pending_delete_failpoint_rolls_back_prior_item_mutation() {
    let fixture = fixture().await;
    let item_id = Uuid::now_v7();
    let original = item(
        fixture.scope,
        item_id,
        "accounts/push-rollback",
        "checksum-push-4",
        4,
        SyncStatus::Modified,
    );
    insert_item(&fixture.pool, &original).await;
    let pending = pending(fixture.scope, &original, ChangeType::Update);
    insert_pending(&fixture.pool, &pending).await;
    sqlx_core::query::query::<Sqlite>(
        r#"
        CREATE TRIGGER fail_pending_delete
        BEFORE DELETE ON pending_changes
        BEGIN
            SELECT RAISE(ABORT, 'pending delete failpoint');
        END
        "#,
    )
    .execute(&fixture.pool)
    .await
    .expect("install pending delete failpoint");

    let mut projected = original.clone();
    projected.version = 5;
    projected.updated_at = timestamp(5);
    projected.sync_status = SyncStatus::Synced;
    let outcome = PushOutcome::applied(
        fixture.scope,
        stored_proof(&fixture.pool, fixture.scope.storage_id, item_id).await,
        exact(&original),
        projected,
    )
    .expect("valid push rollback outcome");
    let plan = PushCommit::new(
        fixture.scope,
        Some("cursor-1".to_string()),
        Some(1),
        "server-head-5".to_string(),
        vec![outcome],
    )
    .expect("valid push rollback plan");
    let error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool).commit_push(&plan).await,
        "pending delete failpoint must abort push commit",
    );
    assert!(matches!(error, LocalSyncError::Database(_)));

    let stored = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, item_id)
        .await
        .expect("read rolled-back push item")
        .expect("rolled-back push item exists");
    assert_eq!(stored.version, 4);
    assert_eq!(stored.sync_status, SyncStatus::Modified);
    assert_eq!(
        PendingChangeRepo::new(&fixture.pool)
            .list_by_item(fixture.scope.storage_id, item_id)
            .await
            .expect("read rolled-back pending")
            .len(),
        1
    );
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-1")
    );
}

#[tokio::test]
async fn any_conflict_fails_closed_with_canonical_pending_and_history_unchanged() {
    let fixture = fixture().await;
    let original = item(
        fixture.scope,
        Uuid::now_v7(),
        "accounts/conflict",
        "checksum-conflict",
        4,
        SyncStatus::Modified,
    );
    insert_item(&fixture.pool, &original).await;
    let change = pending(fixture.scope, &original, ChangeType::Update);
    insert_pending(&fixture.pool, &change).await;
    LocalItemHistoryRepo::new(&fixture.pool)
        .create(&history(fixture.scope, original.id, 3, "history-conflict"))
        .await
        .expect("insert conflict history");
    let mut projected = original.clone();
    projected.version = 5;
    projected.updated_at = timestamp(5);
    projected.sync_status = SyncStatus::Synced;
    let applied = PushOutcome::applied(
        fixture.scope,
        stored_proof(&fixture.pool, fixture.scope.storage_id, original.id).await,
        exact(&original),
        projected,
    )
    .expect("valid applied member before conflicted member");

    let error = expect_sync_error(
        PushCommit::new(
            fixture.scope,
            Some("cursor-1".to_string()),
            Some(1),
            "server-head-conflict".to_string(),
            vec![applied, PushOutcome::conflict()],
        ),
        "a conflicted batch must be rejected before persistence",
    );
    assert!(matches!(error, LocalSyncError::InvalidPlan { .. }));
    let stored = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, original.id)
        .await
        .expect("read conflict canonical")
        .expect("conflict canonical exists");
    assert_eq!(stored.version, 4);
    assert_eq!(stored.sync_status, SyncStatus::Modified);
    assert_eq!(
        PendingChangeRepo::new(&fixture.pool)
            .list_by_item(fixture.scope.storage_id, original.id)
            .await
            .expect("read conflict pending")
            .len(),
        1
    );
    assert_eq!(
        history_checksums(&fixture.pool, fixture.scope, original.id).await,
        vec![canonical_checksum("history-conflict")]
    );
    assert_eq!(
        row_count(&fixture.pool, "items_cache", fixture.scope.storage_id).await,
        1
    );
    let checkpoint = SyncCursorRepo::new(&fixture.pool)
        .get_checkpoint(fixture.scope.storage_id, fixture.scope.vault_id)
        .await
        .expect("read conflict checkpoint")
        .expect("conflict checkpoint exists");
    assert_eq!(checkpoint.cursor.as_deref(), Some("cursor-1"));
    assert_eq!(checkpoint.last_seq, Some(1));
}

#[tokio::test]
async fn pull_cursor_failpoint_rolls_back_items_and_history() {
    let fixture = fixture().await;
    let item_id = Uuid::now_v7();
    let original = item(
        fixture.scope,
        item_id,
        "accounts/cursor-failure",
        "checksum-1",
        1,
        SyncStatus::Synced,
    );
    insert_item(&fixture.pool, &original).await;
    let old_history = history(fixture.scope, item_id, 1, "old-history");
    LocalItemHistoryRepo::new(&fixture.pool)
        .create(&old_history)
        .await
        .expect("insert old history");
    sqlx_core::query::query::<Sqlite>(
        r#"
        CREATE TRIGGER fail_cursor_publish
        BEFORE UPDATE ON sync_cursors
        BEGIN
            SELECT RAISE(ABORT, 'cursor failpoint');
        END
        "#,
    )
    .execute(&fixture.pool)
    .await
    .expect("install cursor failpoint");

    let mut projected = original.clone();
    projected.version = 2;
    projected.checksum = canonical_checksum("checksum-2");
    let change = PullChange::new(
        fixture.scope,
        exact(&original),
        projected,
        vec![history(fixture.scope, item_id, 1, "new-history")],
    )
    .expect("valid failpoint pull change");
    let page = PullPage::new(
        fixture.scope,
        "001122aabbcc".to_string(),
        Some("cursor-1".to_string()),
        Some(1),
        "cursor-2".to_string(),
        Some(2),
        timestamp(2),
        vec![change],
    )
    .expect("valid failpoint pull page");
    let error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .commit_pull_page(&page)
            .await,
        "cursor trigger must abort",
    );
    assert!(matches!(error, LocalSyncError::Database(_)));

    let stored = LocalItemRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, item_id)
        .await
        .expect("read item")
        .expect("item exists");
    assert_eq!(stored.version, 1);
    assert_eq!(stored.checksum, canonical_checksum("checksum-1"));
    let stored_history = LocalItemHistoryRepo::new(&fixture.pool)
        .list_by_item_limit(fixture.scope.storage_id, item_id, 10)
        .await
        .expect("read history");
    assert_eq!(stored_history.len(), 1);
    assert_eq!(
        stored_history[0].checksum,
        canonical_checksum("old-history")
    );
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-1")
    );
    let checkpoint = SyncCursorRepo::new(&fixture.pool)
        .get_checkpoint(fixture.scope.storage_id, fixture.scope.vault_id)
        .await
        .expect("read rolled-back checkpoint")
        .expect("rolled-back checkpoint exists");
    assert_eq!(checkpoint.last_seq, Some(1));
}

#[tokio::test]
async fn reset_rejects_dirty_items_and_non_server_confirmed_history() {
    let fixture = fixture().await;
    let mut target = item(
        fixture.scope,
        Uuid::now_v7(),
        "accounts/dirty-reset",
        "checksum-dirty-reset",
        2,
        SyncStatus::Modified,
    );
    insert_item(&fixture.pool, &target).await;
    let reset = ResetProjection::new(storage_proof(&fixture.storage), None)
        .expect("valid dirty reset projection");
    let dirty_error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .reset_projection(&reset)
            .await,
        "dirty item must block reset",
    );
    assert!(matches!(
        dirty_error,
        LocalSyncError::ProjectionNotClean {
            dirty_items: 1,
            non_server_history: 0,
            ..
        }
    ));

    target.sync_status = SyncStatus::Synced;
    LocalItemRepo::new(&fixture.pool)
        .update(&target)
        .await
        .expect("mark reset item clean");
    let mut local_history = history(fixture.scope, target.id, 1, "history-dirty-reset");
    local_history.source = HistorySource::Local;
    LocalItemHistoryRepo::new(&fixture.pool)
        .create(&local_history)
        .await
        .expect("insert local reset history");
    let history_error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .reset_projection(&reset)
            .await,
        "non-server history must block reset",
    );
    assert!(matches!(
        history_error,
        LocalSyncError::ProjectionNotClean {
            dirty_items: 0,
            non_server_history: 1,
            ..
        }
    ));
    assert_eq!(
        row_count(&fixture.pool, "items_cache", fixture.scope.storage_id).await,
        1
    );
    assert_eq!(
        row_count(&fixture.pool, "item_history", fixture.scope.storage_id).await,
        1
    );
    assert_eq!(
        row_count(&fixture.pool, "sync_cursors", fixture.scope.storage_id).await,
        1
    );
}

#[tokio::test]
async fn reset_rejects_foreign_storage_item_referencing_a_target_vault_without_cascade() {
    let fixture = fixture().await;
    let foreign_storage = remote_storage(
        Uuid::now_v7(),
        "https://foreign-item.example",
        "foreign-item-fingerprint",
    );
    LocalStorageRepo::new(&fixture.pool)
        .upsert(&foreign_storage)
        .await
        .expect("insert foreign storage");
    let malformed_scope = LocalSyncScope {
        storage_id: foreign_storage.id,
        vault_id: fixture.scope.vault_id,
    };
    let malformed_item = item(
        malformed_scope,
        Uuid::now_v7(),
        "accounts/foreign-item",
        "checksum-foreign-item",
        3,
        SyncStatus::Synced,
    );
    insert_item(&fixture.pool, &malformed_item).await;

    let reset = ResetProjection::new(storage_proof(&fixture.storage), None)
        .expect("valid cross-storage item reset plan");
    let error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .reset_projection(&reset)
            .await,
        "foreign-storage item must prevent target vault deletion",
    );
    assert!(matches!(
        error,
        LocalSyncError::CrossStorageVaultReference {
            storage_id,
            foreign_items: 1,
            foreign_history: 0,
        } if storage_id == fixture.scope.storage_id
    ));

    let stored_item = LocalItemRepo::new(&fixture.pool)
        .get_by_id(foreign_storage.id, malformed_item.id)
        .await
        .expect("read malformed item after rejected reset")
        .expect("malformed item survives rejected reset");
    assert_eq!(stored_item.payload_enc, malformed_item.payload_enc);
    assert_eq!(stored_item.checksum, malformed_item.checksum);
    let stored_vault = LocalVaultRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, fixture.scope.vault_id)
        .await
        .expect("read target vault after rejected reset")
        .expect("target vault survives rejected reset");
    assert_eq!(stored_vault.vault_key_enc, vec![7, 8, 9]);
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-1")
    );
    assert!(LocalStorageRepo::new(&fixture.pool)
        .get(fixture.scope.storage_id)
        .await
        .expect("read target storage after rejected reset")
        .is_some());
}

#[tokio::test]
async fn reset_rejects_foreign_storage_history_referencing_a_target_vault_without_cascade() {
    let fixture = fixture().await;
    let foreign_storage = remote_storage(
        Uuid::now_v7(),
        "https://foreign-history.example",
        "foreign-history-fingerprint",
    );
    LocalStorageRepo::new(&fixture.pool)
        .upsert(&foreign_storage)
        .await
        .expect("insert foreign storage");
    let malformed_scope = LocalSyncScope {
        storage_id: foreign_storage.id,
        vault_id: fixture.scope.vault_id,
    };
    let malformed_history = history(
        malformed_scope,
        Uuid::now_v7(),
        4,
        "checksum-foreign-history",
    );
    LocalItemHistoryRepo::new(&fixture.pool)
        .create(&malformed_history)
        .await
        .expect("insert malformed history");

    let reset = ResetProjection::new(storage_proof(&fixture.storage), None)
        .expect("valid cross-storage history reset plan");
    let error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .reset_projection(&reset)
            .await,
        "foreign-storage history must prevent target vault deletion",
    );
    assert!(matches!(
        error,
        LocalSyncError::CrossStorageVaultReference {
            storage_id,
            foreign_items: 0,
            foreign_history: 1,
        } if storage_id == fixture.scope.storage_id
    ));

    let stored_history = LocalItemHistoryRepo::new(&fixture.pool)
        .list_by_item_limit(foreign_storage.id, malformed_history.item_id, 10)
        .await
        .expect("read malformed history after rejected reset");
    assert_eq!(stored_history.len(), 1);
    assert_eq!(stored_history[0].payload_enc, malformed_history.payload_enc);
    assert_eq!(stored_history[0].checksum, malformed_history.checksum);
    let stored_vault = LocalVaultRepo::new(&fixture.pool)
        .get_by_id(fixture.scope.storage_id, fixture.scope.vault_id)
        .await
        .expect("read target vault after rejected reset")
        .expect("target vault survives rejected reset");
    assert_eq!(stored_vault.vault_key_enc, vec![7, 8, 9]);
    assert_eq!(
        cursor(&fixture.pool, fixture.scope).await.as_deref(),
        Some("cursor-1")
    );
    assert!(LocalStorageRepo::new(&fixture.pool)
        .get(fixture.scope.storage_id)
        .await
        .expect("read target storage after rejected reset")
        .is_some());
}

#[tokio::test]
async fn reset_delete_failpoints_roll_back_every_table() {
    for table in ["sync_cursors", "item_history", "local_vaults"] {
        let fixture = fixture().await;
        let item_id = Uuid::now_v7();
        let original = item(
            fixture.scope,
            item_id,
            "accounts/reset-failpoint",
            "checksum-reset",
            1,
            SyncStatus::Synced,
        );
        insert_item(&fixture.pool, &original).await;
        LocalItemHistoryRepo::new(&fixture.pool)
            .create(&history(fixture.scope, item_id, 1, "history-reset"))
            .await
            .expect("insert history");

        let trigger_sql = format!(
            "CREATE TRIGGER fail_reset_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT, 'reset failpoint'); END"
        );
        sqlx_core::query::query::<Sqlite>(&trigger_sql)
            .execute(&fixture.pool)
            .await
            .expect("install reset failpoint");
        let reset = ResetProjection::new(storage_proof(&fixture.storage), None)
            .expect("valid reset projection");
        let error = expect_sync_error(
            LocalSyncRepo::new(&fixture.pool)
                .reset_projection(&reset)
                .await,
            "reset trigger must abort",
        );
        assert!(
            matches!(error, LocalSyncError::Database(_)),
            "table={table}"
        );

        for projected_table in [
            "sync_cursors",
            "item_history",
            "items_cache",
            "local_vaults",
        ] {
            assert_eq!(
                row_count(&fixture.pool, projected_table, fixture.scope.storage_id).await,
                1,
                "table={table}, projected_table={projected_table}"
            );
        }
        assert_eq!(
            row_count(&fixture.pool, "pending_changes", fixture.scope.storage_id).await,
            0,
            "table={table}, pending table remains clean"
        );
    }
}

#[tokio::test]
async fn reset_requires_no_pending_then_deletes_clean_tombstone_and_preserves_other_storage() {
    let fixture = fixture().await;
    let target_item = item(
        fixture.scope,
        Uuid::now_v7(),
        "accounts/target",
        "checksum-target",
        1,
        SyncStatus::Modified,
    );
    insert_item(&fixture.pool, &target_item).await;
    let target_pending = pending(fixture.scope, &target_item, ChangeType::Update);
    insert_pending(&fixture.pool, &target_pending).await;
    LocalItemHistoryRepo::new(&fixture.pool)
        .create(&history(fixture.scope, target_item.id, 1, "history-target"))
        .await
        .expect("insert target history");

    let other_storage = remote_storage(Uuid::now_v7(), "https://two.example", "fingerprint-two");
    LocalStorageRepo::new(&fixture.pool)
        .upsert(&other_storage)
        .await
        .expect("insert other storage");
    let other_scope = LocalSyncScope {
        storage_id: other_storage.id,
        vault_id: Uuid::now_v7(),
    };
    LocalVaultRepo::new(&fixture.pool)
        .create(&vault(other_scope, "Other"))
        .await
        .expect("insert other vault");
    let other_item = item(
        other_scope,
        Uuid::now_v7(),
        "accounts/other",
        "checksum-other",
        2,
        SyncStatus::Modified,
    );
    insert_item(&fixture.pool, &other_item).await;
    insert_pending(
        &fixture.pool,
        &pending(other_scope, &other_item, ChangeType::Update),
    )
    .await;
    LocalItemHistoryRepo::new(&fixture.pool)
        .create(&history(other_scope, other_item.id, 1, "history-other"))
        .await
        .expect("insert other history");
    SyncCursorRepo::new(&fixture.pool)
        .upsert(&LocalSyncCursor {
            storage_id: other_scope.storage_id,
            vault_id: other_scope.vault_id,
            cursor: Some("cursor-other".to_string()),
            last_sync_at: Some(timestamp(2)),
        })
        .await
        .expect("insert other cursor");

    let repo = LocalSyncRepo::new(&fixture.pool);
    let protected_reset =
        ResetProjection::new(storage_proof(&fixture.storage), None).expect("valid protected reset");
    let error = expect_sync_error(
        repo.reset_projection(&protected_reset).await,
        "pending changes must protect reset",
    );
    assert!(matches!(
        error,
        LocalSyncError::PendingChangesPresent { count: 1, .. }
    ));
    assert_eq!(
        row_count(&fixture.pool, "items_cache", fixture.scope.storage_id).await,
        1
    );
    assert_eq!(
        row_count(&fixture.pool, "pending_changes", fixture.scope.storage_id).await,
        1
    );

    assert_eq!(
        PendingChangeRepo::new(&fixture.pool)
            .delete_by_item(fixture.scope.storage_id, target_item.id)
            .await
            .expect("resolve target pending before reset"),
        1
    );
    let mut clean_remote_tombstone = target_item.clone();
    clean_remote_tombstone.sync_status = SyncStatus::Synced;
    clean_remote_tombstone.deleted_at = Some(timestamp(2));
    clean_remote_tombstone.updated_at = timestamp(2);
    LocalItemRepo::new(&fixture.pool)
        .update(&clean_remote_tombstone)
        .await
        .expect("mark target as a clean remote tombstone");

    let replacement = remote_storage(
        fixture.scope.storage_id,
        "https://one.example",
        "fingerprint-replacement",
    );
    let reset = ResetProjection::new(storage_proof(&fixture.storage), Some(replacement))
        .expect("valid replacement reset");
    let receipt = repo
        .reset_projection(&reset)
        .await
        .expect("reset target projection");
    assert_eq!(receipt.pending_deleted, 0);
    assert_eq!(receipt.cursors_deleted, 1);
    assert_eq!(receipt.history_deleted, 1);
    assert_eq!(receipt.items_deleted, 1);
    assert_eq!(receipt.vaults_deleted, 1);
    assert!(receipt.storage_metadata_updated);

    for table in [
        "pending_changes",
        "sync_cursors",
        "item_history",
        "items_cache",
        "local_vaults",
    ] {
        assert_eq!(
            row_count(&fixture.pool, table, fixture.scope.storage_id).await,
            0,
            "target table={table}"
        );
        assert_eq!(
            row_count(&fixture.pool, table, other_scope.storage_id).await,
            1,
            "other table={table}"
        );
    }
    let stored_target = LocalStorageRepo::new(&fixture.pool)
        .get(fixture.scope.storage_id)
        .await
        .expect("read target storage")
        .expect("target storage exists");
    assert_eq!(
        stored_target.server_fingerprint.as_deref(),
        Some("fingerprint-replacement")
    );
    let stored_other = LocalStorageRepo::new(&fixture.pool)
        .get(other_scope.storage_id)
        .await
        .expect("read other storage")
        .expect("other storage exists");
    assert_eq!(
        stored_other.server_fingerprint,
        other_storage.server_fingerprint
    );
}

#[tokio::test]
async fn reset_rejects_same_fingerprint_with_changed_storage_metadata() {
    let fixture = fixture().await;
    let target = item(
        fixture.scope,
        Uuid::now_v7(),
        "accounts/binding",
        "checksum-binding",
        1,
        SyncStatus::Synced,
    );
    insert_item(&fixture.pool, &target).await;

    let expected_storage = storage_proof(&fixture.storage);
    sqlx_core::query::query::<Sqlite>(
        r#"
        UPDATE storages
        SET server_url = ?2, account_subject = ?3, auth_method = ?4
        WHERE id = ?1
        "#,
    )
    .bind(fixture.scope.storage_id)
    .bind("https://changed.example")
    .bind("changed-account-subject")
    .bind(AuthMethod::Oidc.as_i32())
    .execute(&fixture.pool)
    .await
    .expect("change storage metadata without changing fingerprint");

    let reset = ResetProjection::new(expected_storage, None).expect("valid stale reset proof");
    let error = expect_sync_error(
        LocalSyncRepo::new(&fixture.pool)
            .reset_projection(&reset)
            .await,
        "storage binding must be stale",
    );
    assert!(matches!(
        error,
        LocalSyncError::StorageBindingChanged { .. }
    ));
    assert_eq!(
        row_count(&fixture.pool, "items_cache", fixture.scope.storage_id).await,
        1
    );
    assert_eq!(
        row_count(&fixture.pool, "local_vaults", fixture.scope.storage_id).await,
        1
    );
    assert_eq!(
        row_count(&fixture.pool, "sync_cursors", fixture.scope.storage_id).await,
        1
    );
}
