use super::*;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zann_core::{EncryptedPayload, ItemsService, VaultsService};

fn temp_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!("zann-verify-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root).expect("create temp root");
    root
}

async fn seeded(root: &Path) -> (SqlitePool, Arc<SecretKey>) {
    let url = format!("sqlite://{}", root.join("local.sqlite").display());
    let pool = zann_db::connect_sqlite_with_max(&url, 2)
        .await
        .expect("connect");
    zann_db::migrate_local(&pool).await.expect("migrate");
    let master_key = Arc::new(SecretKey::generate());
    (pool, master_key)
}

/// Create a local vault with one item, the same way the app would.
async fn seed_item(pool: &SqlitePool, master_key: &SecretKey, value: &str) -> (Uuid, Uuid) {
    let services = LocalServices::new(pool, master_key);
    let vault = services
        .ensure_default_local_personal()
        .await
        .expect("default vault");
    let mut payload = EncryptedPayload::new("kv");
    payload.fields.insert(
        "value".to_string(),
        zann_core::FieldValue {
            kind: zann_core::FieldKind::Text,
            value: value.to_string(),
            meta: None,
        },
    );
    let item_id = services
        .put_item(
            Uuid::nil(),
            vault.id,
            "secrets/one".to_string(),
            "kv".to_string(),
            payload,
        )
        .await
        .expect("create item");
    (vault.id, item_id)
}

#[tokio::test]
async fn a_healthy_vault_verifies_clean() {
    let root = temp_root();
    let (pool, master_key) = seeded(&root).await;
    seed_item(&pool, master_key.as_ref(), "hello").await;

    let report = run(&pool, master_key).await.expect("verify");

    assert!(report.database_ok, "integrity_check reported a fault");
    assert_eq!(report.items_checked, 1);
    assert_eq!(report.items_ok, 1);
    assert!(
        report.is_clean(),
        "unexpected problems: {:?}",
        report.problems
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn an_empty_vault_verifies_clean() {
    let root = temp_root();
    let (pool, master_key) = seeded(&root).await;

    let report = run(&pool, master_key).await.expect("verify");

    assert!(report.is_clean());
    assert_eq!(report.items_checked, 0);

    let _ = std::fs::remove_dir_all(&root);
}

/// The case the whole module exists for: bytes changed underneath, and the
/// stored checksum no longer describes them.
#[tokio::test]
async fn a_corrupted_payload_is_caught_as_a_checksum_mismatch() {
    let root = temp_root();
    let (pool, master_key) = seeded(&root).await;
    let (_, item_id) = seed_item(&pool, master_key.as_ref(), "hello").await;

    // `id` is a 16-byte BLOB, so bind the raw bytes — a string here would
    // silently match nothing and the test would pass without testing.
    let repo = LocalItemRepo::new(&pool);
    let mut item = repo
        .get_by_id(Uuid::nil(), item_id)
        .await
        .expect("read item")
        .expect("item");
    item.payload_enc = vec![0u8; 64];
    let affected = repo.update(&item).await.expect("corrupt the payload");
    assert_eq!(affected, 1, "the test did not actually corrupt anything");

    let report = run(&pool, master_key).await.expect("verify");

    assert!(!report.is_clean(), "corruption went unnoticed");
    assert_eq!(report.items_ok, 0);
    assert_eq!(report.problems.len(), 1);
    assert_eq!(report.problems[0].kind, "checksum_mismatch");
    assert_eq!(
        report.problems[0].item_id.as_deref(),
        Some(item_id.to_string().as_str())
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Bytes that are self-consistent but no longer decryptable: the checksum
/// agrees, so only the AEAD catches it. This is what tells a rewritten
/// record apart from a damaged one.
#[tokio::test]
async fn undecryptable_bytes_with_a_matching_checksum_are_caught_too() {
    let root = temp_root();
    let (pool, master_key) = seeded(&root).await;
    let (_, item_id) = seed_item(&pool, master_key.as_ref(), "hello").await;

    let bogus = vec![7u8; 96];
    let checksum = core_crypto::payload_checksum(&bogus);
    let repo = LocalItemRepo::new(&pool);
    let mut item = repo
        .get_by_id(Uuid::nil(), item_id)
        .await
        .expect("read item")
        .expect("item");
    item.payload_enc = bogus;
    item.checksum = checksum;
    let affected = repo.update(&item).await.expect("replace the payload");
    assert_eq!(affected, 1, "the test did not actually replace anything");

    let report = run(&pool, master_key).await.expect("verify");

    assert!(!report.is_clean());
    assert_eq!(report.problems.len(), 1);
    assert_eq!(report.problems[0].kind, "decrypt_failed");

    let _ = std::fs::remove_dir_all(&root);
}

/// A vault this key cannot open is skipped, not reported as damage.
#[tokio::test]
async fn a_vault_belonging_to_another_key_is_skipped_not_failed() {
    let root = temp_root();
    let (pool, master_key) = seeded(&root).await;
    seed_item(&pool, master_key.as_ref(), "hello").await;

    let stranger = Arc::new(SecretKey::generate());
    let report = run(&pool, stranger).await.expect("verify");

    assert_eq!(report.vaults_checked, 0);
    assert_eq!(report.vaults_skipped, 1);
    assert_eq!(report.items_checked, 0);
    assert_eq!(report.problems.len(), 1);
    assert_eq!(report.problems[0].kind, "vault_key_unusable");

    let _ = std::fs::remove_dir_all(&root);
}
