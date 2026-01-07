#![cfg(feature = "sqlite")]

use std::collections::HashMap;

use uuid::Uuid;
use zann_core::crypto::SecretKey;
use zann_core::{EncryptedPayload, FieldKind, FieldValue, ItemsService};
use zann_db::local::{LocalItemHistoryRepo, LocalStorage, LocalStorageRepo, LocalVault, LocalVaultRepo};
use zann_db::services::LocalServices;
use zann_db::{connect_sqlite_with_max, migrate_local, SqlitePool};

async fn setup_local() -> (SqlitePool, Uuid, Uuid, SecretKey) {
    let db_path = std::env::temp_dir().join(format!(
        "zann-local-history-{}.sqlite",
        Uuid::now_v7().simple()
    ));
    let db_url = format!("sqlite://{}", db_path.display());
    let pool = connect_sqlite_with_max(&db_url, 1).await.expect("sqlite");
    migrate_local(&pool).await.expect("migrate");

    let storage_id = Uuid::now_v7();
    let storage = LocalStorage {
        id: storage_id,
        kind: "remote".to_string(),
        name: "Remote Test".to_string(),
        server_url: None,
        server_name: None,
        server_fingerprint: None,
        account_subject: None,
        personal_vaults_enabled: true,
        auth_method: None,
    };
    let storage_repo = LocalStorageRepo::new(&pool);
    storage_repo.upsert(&storage).await.expect("storage upsert");

    let vault_id = Uuid::now_v7();
    let vault = LocalVault {
        id: vault_id,
        storage_id,
        name: "Shared Vault".to_string(),
        kind: "shared".to_string(),
        is_default: false,
        vault_key_enc: Vec::new(),
        key_wrap_type: "remote_server".to_string(),
        last_synced_at: None,
        server_seq: 0,
    };
    let vault_repo = LocalVaultRepo::new(&pool);
    vault_repo.create(&vault).await.expect("vault create");

    let master_key = SecretKey::generate();
    (pool, storage_id, vault_id, master_key)
}

fn login_payload(password: &str) -> EncryptedPayload {
    let mut payload = EncryptedPayload::new("login");
    let mut fields = HashMap::new();
    fields.insert(
        "password".to_string(),
        FieldValue {
            kind: FieldKind::Password,
            value: password.to_string(),
            meta: None,
        },
    );
    payload.fields = fields;
    payload
}

#[tokio::test]
async fn local_history_records_payload_updates() {
    let (pool, storage_id, vault_id, master_key) = setup_local().await;
    let services = LocalServices::new(&pool, &master_key);
    let item_id = services
        .put_item(
            storage_id,
            vault_id,
            "login".to_string(),
            "login".to_string(),
            login_payload("pw-1"),
        )
        .await
        .expect("put item");

    services
        .update_item_by_id(
            storage_id,
            item_id,
            "login".to_string(),
            "login".to_string(),
            login_payload("pw-2"),
        )
        .await
        .expect("update item");

    let history_repo = LocalItemHistoryRepo::new(&pool);
    let history = history_repo
        .list_by_item_limit(storage_id, item_id, 5)
        .await
        .expect("history list");
    assert_eq!(history.len(), 1, "expected one history entry");
    assert_eq!(history[0].version, 1, "history stores previous version");

    let payload = services
        .decrypt_payload_for_item(storage_id, vault_id, item_id, &history[0].payload_enc)
        .await
        .expect("decrypt history");
    assert_eq!(
        payload.fields["password"].value, "pw-1",
        "history payload should match previous value"
    );
}

#[tokio::test]
async fn local_history_skips_metadata_only_updates() {
    let (pool, storage_id, vault_id, master_key) = setup_local().await;
    let services = LocalServices::new(&pool, &master_key);
    let item_id = services
        .put_item(
            storage_id,
            vault_id,
            "login".to_string(),
            "login".to_string(),
            login_payload("pw-1"),
        )
        .await
        .expect("put item");

    services
        .update_item_by_id(
            storage_id,
            item_id,
            "login-renamed".to_string(),
            "login".to_string(),
            login_payload("pw-1"),
        )
        .await
        .expect("rename item");

    let history_repo = LocalItemHistoryRepo::new(&pool);
    let history = history_repo
        .list_by_item_limit(storage_id, item_id, 5)
        .await
        .expect("history list");
    assert!(
        history.is_empty(),
        "metadata-only update should not create history"
    );
}

#[tokio::test]
async fn local_history_restore_replaces_payload() {
    let (pool, storage_id, vault_id, master_key) = setup_local().await;
    let services = LocalServices::new(&pool, &master_key);
    let item_id = services
        .put_item(
            storage_id,
            vault_id,
            "login".to_string(),
            "login".to_string(),
            login_payload("pw-1"),
        )
        .await
        .expect("put item");

    services
        .update_item_by_id(
            storage_id,
            item_id,
            "login".to_string(),
            "login".to_string(),
            login_payload("pw-2"),
        )
        .await
        .expect("update item");

    services
        .restore_item_version(storage_id, item_id, 1)
        .await
        .expect("restore history");

    let restored = services
        .get_item(storage_id, item_id)
        .await
        .expect("get item");
    assert_eq!(
        restored.payload.fields["password"].value, "pw-1",
        "restore should return previous payload"
    );

    let history_repo = LocalItemHistoryRepo::new(&pool);
    let history = history_repo
        .list_by_item_limit(storage_id, item_id, 5)
        .await
        .expect("history list");
    assert_eq!(history.len(), 2, "restore should add history snapshot");
    assert_eq!(history[0].version, 2, "restore snapshot records prior version");
    assert_eq!(history[0].change_type, "restore");
    assert_eq!(history[1].version, 1, "original update still present");
}
