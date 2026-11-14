#![cfg(feature = "sqlite")]

use uuid::Uuid;
use zann_core::{EncryptedPayload, ItemsService, StorageKind, VaultKind};
use zann_crypto::{encrypt_payload_bytes, payload_checksum, SecretKey};
use zann_db::local::{
    KeyWrapType, LocalItemHistoryRepo, LocalItemRepo, LocalStorage, LocalStorageRepo, LocalVault,
    LocalVaultRepo, PendingChangeRepo,
};
use zann_db::services::LocalServices;

#[tokio::test]
async fn future_payloads_are_read_only_and_refused_before_any_history_or_pending_write() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory
        .path()
        .canonicalize()
        .expect("canonical root")
        .join("local.sqlite");
    let pool = zann_db::connect_sqlite_with_max(&format!("sqlite://{}", path.display()), 1)
        .await
        .expect("SQLite");
    zann_db::migrate_local(&pool).await.expect("migrate");
    let storage = Uuid::now_v7();
    let vault = Uuid::now_v7();
    let key = SecretKey::generate();
    LocalStorageRepo::new(&pool)
        .upsert(&LocalStorage {
            id: storage,
            kind: StorageKind::Remote,
            name: "Fixture".into(),
            server_url: Some("https://fixture.example.test".into()),
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: true,
            auth_method: None,
        })
        .await
        .expect("storage");
    LocalVaultRepo::new(&pool)
        .create(&LocalVault {
            id: vault,
            storage_id: storage,
            slug: "shared".into(),
            name: "Shared".into(),
            kind: VaultKind::Shared,
            is_default: false,
            vault_key_enc: Vec::new(),
            key_wrap_type: KeyWrapType::RemoteServer,
            cache_key_fp: None,
            last_synced_at: None,
        })
        .await
        .expect("vault");
    let services = LocalServices::new(&pool, &key);
    let id = services
        .put_item(
            storage,
            vault,
            "login".into(),
            "login".into(),
            EncryptedPayload::new("login"),
        )
        .await
        .expect("item");
    let future = encrypt_payload_bytes(
        &key,
        vault,
        id,
        br#"{"fields":{"x":{"kind":"future-secret-kind"}},"v":2}"#,
    )
    .expect("future ciphertext");
    let history_repo = LocalItemHistoryRepo::new(&pool);
    let mut future_history = history_repo
        .list_by_item_limit(storage, id, 10)
        .await
        .expect("history")
        .pop()
        .expect("initial history");
    future_history.id = Uuid::now_v7();
    future_history.version = 2;
    future_history.payload_enc = future.clone();
    future_history.checksum = payload_checksum(&future);
    history_repo
        .create(&future_history)
        .await
        .expect("future history");
    let before_history = history_repo
        .list_by_item_limit(storage, id, 10)
        .await
        .expect("history")
        .len();
    let before_pending = PendingChangeRepo::new(&pool)
        .list_by_item(storage, id)
        .await
        .expect("pending")
        .len();
    assert_eq!(
        services
            .restore_item_version(storage, id, 2)
            .await
            .expect_err("future history is read-only")
            .kind,
        "unsupported_payload_version"
    );

    let repo = LocalItemRepo::new(&pool);
    let mut item = repo
        .get_by_id(storage, id)
        .await
        .expect("read")
        .expect("item");
    let admitted = item.clone();
    // A failed history insertion must roll back the item and preserve pending
    // intent. Reusing the existing history primary key forces that failure.
    let mut candidate = admitted.clone();
    candidate.path = "must-roll-back".into();
    candidate.version += 1;
    assert!(repo
        .commit_edit(&admitted, &candidate, Some(&future_history), None)
        .await
        .is_err());
    let rolled_back = repo
        .get_by_id(storage, id)
        .await
        .expect("read after rollback")
        .expect("item after rollback");
    assert_eq!(rolled_back.path, admitted.path);
    assert_eq!(rolled_back.version, admitted.version);
    assert_eq!(rolled_back.payload_enc, admitted.payload_enc);
    assert_eq!(
        PendingChangeRepo::new(&pool)
            .list_by_item(storage, id)
            .await
            .expect("pending after rollback")
            .len(),
        before_pending
    );
    item.payload_enc = future;
    item.checksum = payload_checksum(&item.payload_enc);
    repo.update(&item).await.expect("opaque future item");
    // Deterministic race: v1 was admitted, then sync installed v2 before the
    // local mutation reached its commit. The exact-source CAS must reject it.
    let mut stale = admitted.clone();
    stale.path = "stale-edit".into();
    stale.version += 1;
    assert!(!repo
        .commit_edit(&admitted, &stale, None, None)
        .await
        .expect("stale CAS"));
    let page = services
        .list_items(storage, vault, Default::default())
        .await
        .expect("future item must not hide the vault list");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, id);
    assert!(page.items[0].subtitle.is_none());
    assert_eq!(
        services
            .get_item(storage, id)
            .await
            .expect_err("future read")
            .kind,
        "unsupported_payload_version"
    );
    assert_eq!(
        services
            .update_item_by_id(
                storage,
                id,
                "renamed".into(),
                "login".into(),
                EncryptedPayload::new("login")
            )
            .await
            .expect_err("future edit")
            .kind,
        "unsupported_payload_version"
    );
    assert_eq!(
        services
            .delete_item(storage, id)
            .await
            .expect_err("future delete")
            .kind,
        "unsupported_payload_version"
    );
    // Requesting older history must not overwrite a future current payload.
    assert_eq!(
        services
            .restore_item_version(storage, id, 1)
            .await
            .expect_err("future current item")
            .kind,
        "unsupported_payload_version"
    );
    let after = repo
        .get_by_id(storage, id)
        .await
        .expect("read")
        .expect("item");
    assert_eq!(after.payload_enc, item.payload_enc);
    assert_eq!(after.checksum, item.checksum);
    assert_eq!(after.version, item.version);
    assert_eq!(after.path, item.path);
    assert!(after.deleted_at.is_none());
    assert_eq!(
        history_repo
            .list_by_item_limit(storage, id, 10)
            .await
            .expect("history")
            .len(),
        before_history
    );
    assert_eq!(
        PendingChangeRepo::new(&pool)
            .list_by_item(storage, id)
            .await
            .expect("pending")
            .len(),
        before_pending
    );
    pool.close().await;
}
