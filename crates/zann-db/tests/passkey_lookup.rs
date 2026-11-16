#![cfg(feature = "sqlite")]
use uuid::Uuid;
use zann_core::{EncryptedPayload, FieldKind, FieldValue, StorageKind, VaultKind};
use zann_crypto::SecretKey;
use zann_db::{local::*, services::LocalServices};
#[tokio::test]
async fn a_cold_index_repairs_in_bounded_pages_without_limiting_the_number_of_other_rps() {
    let dir = tempfile::tempdir().unwrap();
    let pool = zann_db::connect_sqlite_with_max(
        &format!("sqlite://{}", dir.path().join("local.sqlite").display()),
        1,
    )
    .await
    .unwrap();
    zann_db::migrate_local(&pool).await.unwrap();
    let storage = Uuid::now_v7();
    let vault = Uuid::now_v7();
    let key = SecretKey::generate();
    let vault_key = SecretKey::generate();
    LocalStorageRepo::new(&pool)
        .upsert(&LocalStorage {
            id: storage,
            kind: StorageKind::Remote,
            name: "Synthetic".into(),
            server_url: Some("https://example.test".into()),
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: true,
            auth_method: None,
        })
        .await
        .unwrap();
    LocalVaultRepo::new(&pool)
        .create(&LocalVault {
            id: vault,
            storage_id: storage,
            slug: "personal".into(),
            name: "Personal".into(),
            kind: VaultKind::Personal,
            is_default: true,
            vault_key_enc: zann_crypto::encrypt_vault_key(&key, vault, &vault_key).unwrap(),
            key_wrap_type: KeyWrapType::Master,
            cache_key_fp: None,
            last_synced_at: None,
        })
        .await
        .unwrap();
    let services = LocalServices::new(&pool, &key);
    for n in 0..40 {
        let mut payload = EncryptedPayload::new("passkey");
        payload.fields.insert(
            "rp_id".into(),
            FieldValue {
                kind: FieldKind::Text,
                value: format!("site{n}.example.com"),
                meta: None,
            },
        );
        services
            .put_item_with_metadata(
                storage,
                vault,
                format!("Passkeys/{n}"),
                "passkey".into(),
                payload,
                zann_core::ItemMetadata::default(),
            )
            .await
            .unwrap();
    }
    // Simulate existing encrypted rows whose derived index has not been built.
    sqlx_core::query::query("UPDATE passkey_rp_index SET rp_id=NULL")
        .execute(&pool)
        .await
        .unwrap();
    let mut batch = services.begin_item_batch(storage, vault).await.unwrap();
    let rows = batch
        .read_passkeys("site39.example.com", 4096)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    batch.commit().await.unwrap();
    let (remaining,): (i64,) =
        sqlx_core::query_as::query_as("SELECT count(*) FROM passkey_rp_index WHERE rp_id IS NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    let (items,history,pending):(i64,i64,i64)=sqlx_core::query_as::query_as("SELECT (SELECT count(*) FROM items_cache),(SELECT count(*) FROM item_history),(SELECT count(*) FROM pending_changes)").fetch_one(&pool).await.unwrap();
    assert_eq!((items, history, pending), (40, 40, 40));
}
