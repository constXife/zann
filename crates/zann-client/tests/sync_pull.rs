//! What `apply_pull_change` must do, written from the desktop implementation.
//!
//! `zann-client` was extracted from the desktop backend and the two have since
//! drifted. This file is the arbiter: every test here encodes the behaviour of
//! `apps/desktop/src-tauri/src/services/sync_helpers.rs`, which is the side
//! that has been in front of users. Where the client disagrees, the client is
//! wrong.
//!
//! These are written before the reconciliation and are expected to fail, so
//! that fixing the client is a red-to-green transition rather than an
//! assertion that nothing changed. See docs/adr/0003-shared-core-layering.md.
//!
//! `apply_pull_change` takes repositories and one change — no HTTP, no server —
//! so all of this runs against a temporary SQLite file.

use chrono::{TimeZone, Utc};
use uuid::Uuid;
use zann_client::crypto::payload_aad;
use zann_client::sync_helpers::apply_pull_change;
use zann_client::types::SyncPullChange;
use zann_core::crypto::{encrypt_blob, SecretKey};
use zann_core::vault_crypto::payload_checksum;
use zann_core::{
    ChangeType, EncryptedPayload, FieldKind, FieldValue, StorageKind, SyncStatus, VaultKind,
};
use zann_db::local::{
    KeyWrapType, LocalItem, LocalItemHistoryRepo, LocalItemRepo, LocalStorage, LocalStorageRepo,
    LocalVault, LocalVaultRepo,
};
use zann_db::SqlitePool;

const STORAGE_ID: Uuid = Uuid::nil();

struct Fixture {
    pool: SqlitePool,
    vault_id: Uuid,
    vault_key: SecretKey,
    _dir: tempfile::TempDir,
}

/// A payload the way the server would have stored it: a real encrypted blob, so
/// that the decryption check has something to succeed at.
fn encrypted(f: &Fixture, item_id: Uuid, value: &str) -> Vec<u8> {
    let mut payload = EncryptedPayload::new("kv");
    payload.fields.insert(
        "value".to_string(),
        FieldValue {
            kind: FieldKind::Text,
            value: value.to_string(),
            meta: None,
        },
    );
    let bytes = payload.to_bytes().expect("serialize payload");
    encrypt_blob(&f.vault_key, &bytes, &payload_aad(f.vault_id, item_id))
        .expect("encrypt payload")
        .to_bytes()
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
            kind: StorageKind::LocalOnly,
            name: "local".to_string(),
            server_url: None,
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
            name: "personal".to_string(),
            kind: VaultKind::Personal,
            is_default: true,
            vault_key_enc: vec![0u8; 60],
            key_wrap_type: KeyWrapType::Master,
            last_synced_at: None,
        })
        .await
        .expect("create vault");

    Fixture {
        pool,
        vault_id,
        vault_key: SecretKey::generate(),
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
/// `SyncPullChange` has no `deleted_at` — deletion is carried by `operation`
/// alone (crates/zann-server/src/domains/sync/http/v1/types.rs).
fn change(
    item_id: Uuid,
    operation: ChangeType,
    seq: i64,
    payload: Option<Vec<u8>>,
) -> SyncPullChange {
    let checksum = payload
        .as_ref()
        .map(|bytes| payload_checksum(bytes))
        .unwrap_or_default();
    SyncPullChange {
        item_id: item_id.to_string(),
        operation: operation.as_i32(),
        seq,
        updated_at: at(seq).to_rfc3339(),
        checksum,
        payload_enc: payload,
        path: "secrets/one".to_string(),
        name: "one".to_string(),
        type_id: "kv".to_string(),
        history: Vec::new(),
    }
}

async fn apply(f: &Fixture, change: &SyncPullChange) -> Result<bool, String> {
    let item_repo = LocalItemRepo::new(&f.pool);
    let history_repo = LocalItemHistoryRepo::new(&f.pool);
    apply_pull_change(
        &item_repo,
        &history_repo,
        &f.vault_key,
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

/// The bug this whole exercise is about. The server signals a deletion with
/// `operation`, and the client reads `deleted_at`, which never arrives — so a
/// deletion made on another device never lands. COSMIC runs on this code.
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
        "the item was not tombstoned: a deletion on another device is lost"
    );
    assert_eq!(item.sync_status, SyncStatus::Tombstone);
    assert_eq!(item.version, 2);
}

/// The desktop skips only a *strictly* newer local version, so a change at the
/// same seq is re-applied. The client uses `>=` and drops it, which silently
/// loses a same-sequence correction.
#[tokio::test]
async fn a_change_at_the_same_seq_is_reapplied() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();
    seed_item(&f, item_id, 5, b"old").await;

    let fresh = encrypted(&f, item_id, "new");
    let applied = apply(
        &f,
        &change(item_id, ChangeType::Update, 5, Some(fresh.clone())),
    )
    .await
    .expect("apply");

    assert!(applied, "a change at the same seq must be re-applied");
    assert_eq!(fetch(&f, item_id).await.payload_enc, fresh);
}

/// A strictly newer local row still wins.
#[tokio::test]
async fn a_newer_local_version_still_wins() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();
    seed_item(&f, item_id, 9, b"local").await;

    let stale = encrypted(&f, item_id, "stale");
    let applied = apply(&f, &change(item_id, ChangeType::Update, 4, Some(stale)))
        .await
        .expect("apply");

    assert!(!applied, "a stale change must not be applied");
    assert_eq!(fetch(&f, item_id).await.payload_enc, b"local".to_vec());
}

/// The desktop records which key the cached payload was encrypted under. The
/// client writes `None`, so nothing can later tell a stale cache from a current
/// one after a key rotation.
#[tokio::test]
async fn the_cache_key_fingerprint_is_recorded() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();

    let payload = encrypted(&f, item_id, "payload");
    apply(&f, &change(item_id, ChangeType::Create, 1, Some(payload)))
        .await
        .expect("apply");

    assert!(
        fetch(&f, item_id).await.cache_key_fp.is_some(),
        "cache_key_fp was left empty, so a rotated key cannot invalidate the cache"
    );
}

/// A payload whose bytes do not match the checksum the server sent has been
/// damaged in transit. The desktop rejects it; the client recomputes the
/// checksum from the bytes it received, which makes any corruption
/// self-consistent and therefore invisible.
#[tokio::test]
async fn a_payload_that_fails_its_checksum_is_rejected() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();
    seed_item(&f, item_id, 1, b"good").await;

    let mut damaged = change(
        item_id,
        ChangeType::Update,
        2,
        Some(encrypted(&f, item_id, "tampered")),
    );
    damaged.checksum = payload_checksum(b"what the server actually sent");

    let applied = apply(&f, &damaged).await.expect("apply");

    assert!(!applied, "a payload failing its checksum must be rejected");
    assert_eq!(
        fetch(&f, item_id).await.payload_enc,
        b"good".to_vec(),
        "the damaged payload overwrote a good local one"
    );
}

/// Bytes that are internally consistent — the checksum matches — but were not
/// written under this vault's key. Only the AEAD catches this, which is why the
/// checksum test above is not enough on its own.
#[tokio::test]
async fn a_payload_encrypted_under_another_key_is_rejected() {
    let f = fixture().await;
    let item_id = Uuid::now_v7();
    seed_item(&f, item_id, 1, b"good").await;

    let stranger = SecretKey::generate();
    let mut payload = EncryptedPayload::new("kv");
    payload.fields.insert(
        "value".to_string(),
        FieldValue {
            kind: FieldKind::Text,
            value: "not ours".to_string(),
            meta: None,
        },
    );
    let foreign = encrypt_blob(
        &stranger,
        &payload.to_bytes().expect("serialize"),
        &payload_aad(f.vault_id, item_id),
    )
    .expect("encrypt")
    .to_bytes();

    let applied = apply(&f, &change(item_id, ChangeType::Update, 2, Some(foreign)))
        .await
        .expect("apply");

    assert!(!applied, "an undecryptable payload must be rejected");
    assert_eq!(
        fetch(&f, item_id).await.payload_enc,
        b"good".to_vec(),
        "the foreign payload overwrote a good local one"
    );
}
