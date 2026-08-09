//! What `apply_shared_pull_change` must do, written from the desktop implementation.
//!
//! The companion of `sync_pull.rs`, for shared vaults. Same arbiter rule: every
//! test encodes the behaviour of `apps/desktop/src-tauri/src/services/sync_helpers.rs`,
//! which is the side that has been in front of users, and where the client
//! disagrees the client is wrong.
//!
//! Shared vaults differ from personal ones in one way that matters here: the
//! server holds the vault key and hands the payload over as plaintext JSON, so
//! there is no ciphertext to check a checksum against and nothing to decrypt.
//! The client encrypts what arrives under the master key for its local cache,
//! and the `checksum` field on the wire describes the server's copy, not that
//! cache. So the two tests `sync_pull.rs` has for checksum and decryption have
//! no equivalent here — every other divergence does.
//!
//! See docs/adr/0003-shared-core-layering.md.

use chrono::{TimeZone, Utc};
use serde_json::json;
use uuid::Uuid;
use zann_client::sync_helpers::apply_shared_pull_change;
use zann_client::types::{SyncSharedHistoryEntry, SyncSharedPullChange};
use zann_core::crypto::SecretKey;
use zann_core::vault_crypto::payload_checksum;
use zann_core::{ChangeType, StorageKind, SyncStatus, VaultKind};
use zann_db::local::{
    HistorySource, HistorySyncStatus, KeyWrapType, LocalItem, LocalItemHistory,
    LocalItemHistoryRepo, LocalItemRepo, LocalStorage, LocalStorageRepo, LocalVault,
    LocalVaultRepo,
};
use zann_db::SqlitePool;

const STORAGE_ID: Uuid = Uuid::nil();

struct Fixture {
    pool: SqlitePool,
    vault_id: Uuid,
    master_key: SecretKey,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite://{}", dir.path().join("local.sqlite").display());
    let pool = zann_db::connect_sqlite_with_max(&url, 2)
        .await
        .expect("connect");
    zann_db::migrate_local(&pool).await.expect("migrate");

    LocalStorageRepo::new(&pool)
        .upsert(&LocalStorage {
            id: STORAGE_ID,
            kind: StorageKind::Remote,
            name: "remote".to_string(),
            server_url: Some("https://example.invalid".to_string()),
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: true,
            auth_method: None,
        })
        .await
        .expect("create storage");

    let vault_id = Uuid::now_v7();
    LocalVaultRepo::new(&pool)
        .create(&LocalVault {
            id: vault_id,
            storage_id: STORAGE_ID,
            name: "shared".to_string(),
            kind: VaultKind::Shared,
            is_default: false,
            // Server-side encryption: the client never unwraps this.
            vault_key_enc: Vec::new(),
            key_wrap_type: KeyWrapType::RemoteServer,
            last_synced_at: None,
        })
        .await
        .expect("create vault");

    Fixture {
        pool,
        vault_id,
        master_key: SecretKey::generate(),
        _dir: dir,
    }
}

fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000 + seconds, 0)
        .single()
        .expect("timestamp")
}

/// A local row as it would exist after an earlier sync.
async fn seed_item(f: &Fixture, item_id: Uuid, version: i64, payload: &[u8]) {
    LocalItemRepo::new(&f.pool)
        .create(&LocalItem {
            id: item_id,
            storage_id: STORAGE_ID,
            vault_id: f.vault_id,
            path: "secrets/one".to_string(),
            name: "one".to_string(),
            type_id: "kv".to_string(),
            payload_enc: payload.to_vec(),
            checksum: payload_checksum(payload),
            cache_key_fp: Some("fp-local".to_string()),
            version,
            deleted_at: None,
            updated_at: at(0),
            sync_status: SyncStatus::Synced,
        })
        .await
        .expect("seed item");
}

/// A change exactly as the server sends it. Note what is absent: the server's
/// `SyncSharedPullChange` has no `deleted_at` — deletion is carried by
/// `operation` alone, and the payload is dropped for a delete
/// (crates/zann-server/src/domains/sync/service.rs).
fn change(
    item_id: Uuid,
    operation: ChangeType,
    seq: i64,
    payload: Option<serde_json::Value>,
) -> SyncSharedPullChange {
    SyncSharedPullChange {
        item_id: item_id.to_string(),
        operation: operation.as_i32(),
        seq,
        updated_at: at(seq).to_rfc3339(),
        // The server's checksum covers *its* ciphertext, which the client never
        // sees. It is carried along and deliberately not compared to anything.
        checksum: "server-side-checksum".to_string(),
        payload,
        path: "secrets/one".to_string(),
        name: "one".to_string(),
        type_id: "kv".to_string(),
        history: Vec::new(),
    }
}

fn history_entry(version: i64, value: &str) -> SyncSharedHistoryEntry {
    SyncSharedHistoryEntry {
        version,
        checksum: format!("server-checksum-{version}"),
        change_type: ChangeType::Update.as_i32(),
        changed_by_name: Some("Ada".to_string()),
        changed_by_email: "ada@example.com".to_string(),
        created_at: at(version).to_rfc3339(),
        payload: json!({ "v": 1, "typeId": "kv", "fields": { "value": value } }),
    }
}

async fn apply(f: &Fixture, change: &SyncSharedPullChange) -> Result<bool, String> {
    let item_repo = LocalItemRepo::new(&f.pool);
    let history_repo = LocalItemHistoryRepo::new(&f.pool);
    apply_shared_pull_change(
        &item_repo,
        &history_repo,
        &f.master_key,
        STORAGE_ID,
        f.vault_id,
        change,
    )
    .await
}

async fn fetch(f: &Fixture, item_id: Uuid) -> LocalItem {
    LocalItemRepo::new(&f.pool)
        .get_by_id(STORAGE_ID, item_id)
        .await
        .expect("get item")
        .expect("item should exist")
}

async fn history(f: &Fixture, item_id: Uuid) -> Vec<LocalItemHistory> {
    LocalItemHistoryRepo::new(&f.pool)
        .list_by_item_limit(STORAGE_ID, item_id, 50)
        .await
        .expect("list history")
}

/// The same bug `sync_pull.rs` pins down for personal vaults. The server signals
/// a deletion with `operation`, the client reads `deleted_at`, which is not a
/// field the shared pull response has at all — so an item someone else deleted
/// stays in the list forever.
#[tokio::test]
async fn a_delete_operation_creates_a_tombstone() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();
    seed_item(&f, item_id, 1, b"payload").await;

    let applied = apply(&f, &change(item_id, ChangeType::Delete, 2, None))
        .await
        .expect("apply");

    assert!(applied, "a delete must be applied");
    let item = fetch(&f, item_id).await;
    assert!(
        item.deleted_at.is_some(),
        "the item was not tombstoned: a deletion in a shared vault is lost"
    );
    assert_eq!(item.sync_status, SyncStatus::Tombstone);
    assert_eq!(item.version, 2);
}

/// A delete for something never synced here is not an error, and must not
/// resurrect the item as an empty row.
#[tokio::test]
async fn a_delete_for_an_unknown_item_creates_nothing() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();

    let applied = apply(&f, &change(item_id, ChangeType::Delete, 3, None))
        .await
        .expect("apply");

    assert!(applied, "a delete is still a change that was handled");
    assert!(
        LocalItemRepo::new(&f.pool)
            .get_by_id(STORAGE_ID, item_id)
            .await
            .expect("get item")
            .is_none(),
        "a delete conjured a row for an item that was never here"
    );
}

/// The desktop skips only a *strictly* newer local version. `>=` matters more
/// for shared vaults than personal ones: the server's bootstrap path stamps
/// every item with the vault's current seq, so a second bootstrap would compare
/// equal and drop the lot.
#[tokio::test]
async fn a_change_at_the_same_seq_is_reapplied() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();
    seed_item(&f, item_id, 5, b"old").await;

    let applied = apply(
        &f,
        &change(
            item_id,
            ChangeType::Update,
            5,
            Some(json!({ "value": "new" })),
        ),
    )
    .await
    .expect("apply");

    assert!(applied, "a change at the same seq must be re-applied");
    assert_ne!(
        fetch(&f, item_id).await.payload_enc,
        b"old".to_vec(),
        "the local cache still holds the stale payload"
    );
}

/// A strictly newer local row still wins.
#[tokio::test]
async fn a_newer_local_version_still_wins() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();
    seed_item(&f, item_id, 9, b"local").await;

    let applied = apply(
        &f,
        &change(
            item_id,
            ChangeType::Update,
            4,
            Some(json!({ "value": "stale" })),
        ),
    )
    .await
    .expect("apply");

    assert!(!applied, "a stale change must not be applied");
    assert_eq!(fetch(&f, item_id).await.payload_enc, b"local".to_vec());
}

/// The cache is written under the master key, and the row records which key
/// that was so a rotation can invalidate it. The client left it empty.
#[tokio::test]
async fn the_cache_key_fingerprint_is_recorded() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();

    apply(
        &f,
        &change(
            item_id,
            ChangeType::Create,
            1,
            Some(json!({ "value": "payload" })),
        ),
    )
    .await
    .expect("apply");

    assert!(
        fetch(&f, item_id).await.cache_key_fp.is_some(),
        "cache_key_fp was left empty, so a rotated key cannot invalidate the cache"
    );
}

/// An update with no payload is a malformed change, not an instruction to blank
/// the item. The client encrypted the absence into an empty cache entry and
/// stored it over a perfectly good one.
#[tokio::test]
async fn an_update_without_a_payload_is_rejected() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();
    seed_item(&f, item_id, 1, b"good").await;

    let applied = apply(&f, &change(item_id, ChangeType::Update, 2, None))
        .await
        .expect("apply");

    assert!(!applied, "an update with no payload must be rejected");
    assert_eq!(
        fetch(&f, item_id).await.payload_enc,
        b"good".to_vec(),
        "a payload-less update wiped the cached payload"
    );
}

/// The item's own checksum has to describe the bytes actually cached, because
/// that is what `verify` recomputes. Carrying the server's checksum across
/// would make every shared item look corrupt.
#[tokio::test]
async fn the_stored_checksum_covers_the_local_cache() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();

    apply(
        &f,
        &change(
            item_id,
            ChangeType::Create,
            1,
            Some(json!({ "value": "payload" })),
        ),
    )
    .await
    .expect("apply");

    let item = fetch(&f, item_id).await;
    assert_eq!(
        item.checksum,
        payload_checksum(&item.payload_enc),
        "the stored checksum does not describe the stored bytes"
    );
}

/// History arrives as the server's tail. It has to land locally, re-encrypted
/// under the master key like the payload.
#[tokio::test]
async fn history_from_the_server_is_stored() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();

    let mut incoming = change(
        item_id,
        ChangeType::Update,
        2,
        Some(json!({ "value": "current" })),
    );
    incoming.history = vec![history_entry(1, "first"), history_entry(2, "second")];

    apply(&f, &incoming).await.expect("apply");

    let stored = history(&f, item_id).await;
    assert_eq!(stored.len(), 2, "the server history tail was not stored");
    assert!(
        stored.iter().all(|entry| !entry.payload_enc.is_empty()),
        "a history row was stored with no payload"
    );
    assert!(
        stored
            .iter()
            .all(|entry| entry.checksum == payload_checksum(&entry.payload_enc)),
        "a history checksum does not describe the bytes stored beside it"
    );
}

/// The reason this is `merge_by_item` and not `replace_by_item`: a local edit
/// that has not been pushed yet is a *pending* history row, and it is the only
/// copy of that version anywhere. Wiping the item's history to write the
/// server's tail over it destroys the user's own unsynced change.
#[tokio::test]
async fn a_pending_local_history_row_survives_a_pull() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();
    seed_item(&f, item_id, 1, b"payload").await;

    let pending = LocalItemHistory {
        id: Uuid::now_v7(),
        storage_id: STORAGE_ID,
        vault_id: f.vault_id,
        item_id,
        payload_enc: b"not pushed yet".to_vec(),
        checksum: payload_checksum(b"not pushed yet"),
        version: 7,
        change_type: ChangeType::Update,
        changed_by_email: "me@example.com".to_string(),
        changed_by_name: None,
        changed_by_device_id: None,
        changed_by_device_name: None,
        source: HistorySource::Local,
        sync_status: HistorySyncStatus::Pending,
        created_at: at(0),
    };
    LocalItemHistoryRepo::new(&f.pool)
        .create(&pending)
        .await
        .expect("seed pending history");

    let mut incoming = change(
        item_id,
        ChangeType::Update,
        2,
        Some(json!({ "value": "from the server" })),
    );
    incoming.history = vec![history_entry(1, "first")];

    apply(&f, &incoming).await.expect("apply");

    let stored = history(&f, item_id).await;
    assert!(
        stored
            .iter()
            .any(|entry| entry.version == 7 && entry.sync_status == HistorySyncStatus::Pending),
        "the unpushed local history row was destroyed by a pull"
    );
    assert!(
        stored.iter().any(|entry| entry.version == 1),
        "the server history tail was not stored"
    );
}

/// Once the server confirms that version, the pending row becomes the confirmed
/// one rather than a duplicate sitting next to it.
#[tokio::test]
async fn a_confirmed_version_replaces_its_pending_row() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();
    seed_item(&f, item_id, 1, b"payload").await;

    LocalItemHistoryRepo::new(&f.pool)
        .create(&LocalItemHistory {
            id: Uuid::now_v7(),
            storage_id: STORAGE_ID,
            vault_id: f.vault_id,
            item_id,
            payload_enc: b"local guess".to_vec(),
            checksum: payload_checksum(b"local guess"),
            version: 2,
            change_type: ChangeType::Update,
            changed_by_email: "me@example.com".to_string(),
            changed_by_name: None,
            changed_by_device_id: None,
            changed_by_device_name: None,
            source: HistorySource::Local,
            sync_status: HistorySyncStatus::Pending,
            created_at: at(0),
        })
        .await
        .expect("seed pending history");

    let mut incoming = change(
        item_id,
        ChangeType::Update,
        2,
        Some(json!({ "value": "confirmed" })),
    );
    incoming.history = vec![history_entry(2, "confirmed")];

    apply(&f, &incoming).await.expect("apply");

    let stored = history(&f, item_id).await;
    let at_version_2 = stored
        .iter()
        .filter(|entry| entry.version == 2)
        .collect::<Vec<_>>();
    assert_eq!(
        at_version_2.len(),
        1,
        "the confirmed row was added beside the pending one instead of replacing it"
    );
    assert_eq!(at_version_2[0].sync_status, HistorySyncStatus::Confirmed);
}

/// A delete still carries the history tail, so the versions before it stay
/// readable for a restore.
#[tokio::test]
async fn a_delete_still_applies_its_history() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();
    seed_item(&f, item_id, 1, b"payload").await;

    let mut incoming = change(item_id, ChangeType::Delete, 2, None);
    incoming.history = vec![history_entry(1, "before the delete")];

    apply(&f, &incoming).await.expect("apply");

    assert!(
        history(&f, item_id)
            .await
            .iter()
            .any(|entry| entry.version == 1),
        "the history tail was dropped along with the item"
    );
}

/// An unreadable timestamp must not be stamped `now`: that would make the change
/// look newer than everything local and win every later comparison.
#[tokio::test]
async fn an_unparseable_timestamp_is_rejected() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();
    seed_item(&f, item_id, 1, b"good").await;

    let mut incoming = change(
        item_id,
        ChangeType::Update,
        2,
        Some(json!({ "value": "new" })),
    );
    incoming.updated_at = "not a timestamp".to_string();

    let applied = apply(&f, &incoming).await.expect("apply");

    assert!(
        !applied,
        "a change with no readable timestamp must be rejected"
    );
    assert_eq!(fetch(&f, item_id).await.payload_enc, b"good".to_vec());
}
