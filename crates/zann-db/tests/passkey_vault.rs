#![cfg(feature = "sqlite")]
use uuid::Uuid;
use zann_core::{EncryptedPayload, ItemsService, StorageKind, VaultKind};
use zann_crypto::SecretKey;
use zann_db::{
    local::{
        KeyWrapType, LocalItemRepo, LocalStorage, LocalStorageRepo, LocalVault, LocalVaultRepo,
        PendingChangeRepo,
    },
    services::LocalServices,
};

#[tokio::test]
async fn shared_passkey_creation_and_updates_leave_no_item_history_or_pending_changes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .canonicalize()
        .unwrap()
        .join("local.sqlite");
    let pool = zann_db::connect_sqlite_with_max(&format!("sqlite://{}", path.display()), 1)
        .await
        .unwrap();
    zann_db::migrate_local(&pool).await.unwrap();
    let storage = Uuid::now_v7();
    let vault = Uuid::now_v7();
    let key = SecretKey::generate();
    LocalStorageRepo::new(&pool)
        .upsert(&LocalStorage {
            id: storage,
            kind: StorageKind::Remote,
            name: "Fixture".into(),
            server_url: Some("https://fixture.test".into()),
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
            slug: "shared".into(),
            name: "Shared".into(),
            kind: VaultKind::Shared,
            is_default: false,
            vault_key_enc: vec![],
            key_wrap_type: KeyWrapType::RemoteServer,
            cache_key_fp: None,
            last_synced_at: None,
        })
        .await
        .unwrap();
    let bounded = LocalVaultRepo::new(&pool)
        .get_by_id_bounded(storage, vault)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bounded.key_wrap_type, KeyWrapType::RemoteServer);
    assert!(bounded.vault_key_enc.is_empty());
    assert_eq!(
        LocalVaultRepo::new(&pool)
            .list_by_storage_bounded(storage)
            .await
            .unwrap()
            .len(),
        1
    );
    let services = LocalServices::new(&pool, &key);
    let error = services
        .put_item(
            storage,
            vault,
            "passkey".into(),
            "passkey".into(),
            EncryptedPayload::new("passkey"),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, "passkey_personal_only");
    let login = services
        .put_item(
            storage,
            vault,
            "login".into(),
            "login".into(),
            EncryptedPayload::new("login"),
        )
        .await
        .unwrap();
    let before = LocalItemRepo::new(&pool)
        .get_by_id(storage, login)
        .await
        .unwrap()
        .unwrap();
    let pending = PendingChangeRepo::new(&pool)
        .list_by_item(storage, login)
        .await
        .unwrap()
        .len();
    for (type_id, payload_type, expected) in [
        ("passkey", "passkey", "passkey_personal_only"),
        ("passkey", "login", "item_type_mismatch"),
        ("login", "passkey", "item_type_mismatch"),
    ] {
        assert_eq!(
            services
                .update_item_by_id(
                    storage,
                    login,
                    "renamed".into(),
                    type_id.into(),
                    EncryptedPayload::new(payload_type)
                )
                .await
                .unwrap_err()
                .kind,
            expected
        );
    }
    let after = LocalItemRepo::new(&pool)
        .get_by_id(storage, login)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.version, before.version);
    assert_eq!(after.payload_enc, before.payload_enc);
    assert_eq!(after.path, before.path);
    assert_eq!(
        PendingChangeRepo::new(&pool)
            .list_by_item(storage, login)
            .await
            .unwrap()
            .len(),
        pending
    );
    use sqlx_core::row::Row;
    let row = sqlx_core::query::query("SELECT (SELECT COUNT(*) FROM items_cache) AS items, (SELECT COUNT(*) FROM item_history) AS history, (SELECT COUNT(*) FROM pending_changes) AS pending").fetch_one(&pool).await.unwrap();
    assert_eq!(row.get::<i64, _>("items"), 1);
    assert_eq!(row.get::<i64, _>("history"), 1);
    assert_eq!(row.get::<i64, _>("pending"), 1);
}
