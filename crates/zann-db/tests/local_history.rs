#![cfg(feature = "sqlite")]

use std::collections::HashMap;

use uuid::Uuid;
use zann_crypto::crypto::SecretKey;
use zann_core::{
    ChangeType, EncryptedPayload, FieldKind, FieldValue, ItemsService, StorageKind, VaultKind,
};
use zann_db::local::{
    LocalItemHistoryRepo, LocalItemRepo, LocalStorage, LocalStorageRepo, LocalVault,
    LocalVaultRepo, PendingChangeRepo,
};
use zann_db::services::{
    LocalServices, MAX_ITEM_NAME_LEN, MAX_ITEM_PATH_SEGMENTS, MAX_ITEM_PAYLOAD_BYTES,
};
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
        kind: StorageKind::LocalOnly,
        name: "Local Test".to_string(),
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
        kind: VaultKind::Shared,
        is_default: false,
        vault_key_enc: Vec::new(),
        key_wrap_type: zann_db::local::KeyWrapType::RemoteServer,
        last_synced_at: None,
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
    assert_eq!(history.len(), 2, "expected create + update history entries");
    assert!(
        history
            .iter()
            .any(|entry| entry.change_type == ChangeType::Create),
        "missing create history entry"
    );
    let update_entry = history
        .iter()
        .find(|entry| entry.change_type == ChangeType::Update)
        .expect("missing update history entry");
    assert_eq!(
        update_entry.version, 1,
        "update history stores previous version"
    );

    let payload = services
        .decrypt_payload_for_item(storage_id, vault_id, item_id, &update_entry.payload_enc)
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
    assert_eq!(
        history.len(),
        1,
        "metadata-only update should not create additional history"
    );
    assert_eq!(
        history[0].change_type,
        ChangeType::Create,
        "metadata-only update should not add update history"
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
    assert_eq!(history.len(), 3, "restore should add history snapshot");
    let restore_entry = history
        .iter()
        .find(|entry| entry.change_type == ChangeType::Restore)
        .expect("missing restore history entry");
    assert_eq!(
        restore_entry.version, 2,
        "restore snapshot records prior version"
    );
    assert!(
        history
            .iter()
            .any(|entry| entry.change_type == ChangeType::Update),
        "original update still present"
    );
    assert!(
        history
            .iter()
            .any(|entry| entry.change_type == ChangeType::Create),
        "original create still present"
    );
}

#[tokio::test]
async fn local_items_reject_duplicate_paths() {
    let (pool, storage_id, vault_id, master_key) = setup_local().await;
    let services = LocalServices::new(&pool, &master_key);
    services
        .put_item(
            storage_id,
            vault_id,
            "folder/dup".to_string(),
            "login".to_string(),
            login_payload("pw-1"),
        )
        .await
        .expect("put item");

    let err = services
        .put_item(
            storage_id,
            vault_id,
            "folder/dup".to_string(),
            "login".to_string(),
            login_payload("pw-2"),
        )
        .await
        .expect_err("duplicate put");

    assert_eq!(err.kind, "item_exists");
}

#[tokio::test]
async fn local_restore_renames_on_path_conflict() {
    let (pool, storage_id, vault_id, master_key) = setup_local().await;
    let services = LocalServices::new(&pool, &master_key);
    let repo = LocalItemRepo::new(&pool);

    let item_id = services
        .put_item(
            storage_id,
            vault_id,
            "folder/entry".to_string(),
            "login".to_string(),
            login_payload("pw-1"),
        )
        .await
        .expect("put item");

    services
        .delete_item(storage_id, item_id)
        .await
        .expect("delete item");

    services
        .put_item(
            storage_id,
            vault_id,
            "folder/entry".to_string(),
            "login".to_string(),
            login_payload("pw-2"),
        )
        .await
        .expect("put replacement");

    services
        .restore_item(storage_id, item_id)
        .await
        .expect("restore item");

    let restored = repo
        .get_by_id(storage_id, item_id)
        .await
        .expect("get restored")
        .expect("restored exists");

    assert_eq!(restored.path, "folder/entry (restored)");
    assert_eq!(restored.name, "entry (restored)");
}

#[tokio::test]
async fn local_items_reject_invalid_paths() {
    let (pool, storage_id, vault_id, master_key) = setup_local().await;
    let services = LocalServices::new(&pool, &master_key);
    let err = services
        .put_item(
            storage_id,
            vault_id,
            "folder/../bad".to_string(),
            "login".to_string(),
            login_payload("pw-1"),
        )
        .await
        .expect_err("invalid path");

    assert_eq!(err.kind, "path_invalid");
}

#[tokio::test]
async fn local_items_reject_too_long_names() {
    let (pool, storage_id, vault_id, master_key) = setup_local().await;
    let services = LocalServices::new(&pool, &master_key);
    let long_name = "a".repeat(MAX_ITEM_NAME_LEN + 1);
    let path = format!("folder/{}", long_name);
    let err = services
        .put_item(
            storage_id,
            vault_id,
            path,
            "login".to_string(),
            login_payload("pw-1"),
        )
        .await
        .expect_err("name too long");

    assert_eq!(err.kind, "name_too_long");
}

#[tokio::test]
async fn local_items_reject_deep_paths() {
    let (pool, storage_id, vault_id, master_key) = setup_local().await;
    let services = LocalServices::new(&pool, &master_key);
    let segments = vec!["a"; MAX_ITEM_PATH_SEGMENTS + 1];
    let path = segments.join("/");
    let err = services
        .put_item(
            storage_id,
            vault_id,
            path,
            "login".to_string(),
            login_payload("pw-1"),
        )
        .await
        .expect_err("path too deep");

    assert_eq!(err.kind, "path_segments_limit");
}

#[tokio::test]
async fn local_items_reject_large_payloads() {
    let (pool, storage_id, vault_id, master_key) = setup_local().await;
    let services = LocalServices::new(&pool, &master_key);
    let mut payload = EncryptedPayload::new("note");
    let mut fields = HashMap::new();
    fields.insert(
        "text".to_string(),
        FieldValue {
            kind: FieldKind::Note,
            value: "x".repeat(MAX_ITEM_PAYLOAD_BYTES + 1024),
            meta: None,
        },
    );
    payload.fields = fields;

    let err = services
        .put_item(
            storage_id,
            vault_id,
            "big-note".to_string(),
            "note".to_string(),
            payload,
        )
        .await
        .expect_err("payload too large");

    assert_eq!(err.kind, "payload_too_large");
}

#[tokio::test]
async fn local_pending_changes_coalesce_create_and_update() {
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

    let pending_repo = PendingChangeRepo::new(&pool);
    let pending = pending_repo
        .list_by_item(storage_id, item_id)
        .await
        .expect("pending list");

    assert_eq!(pending.len(), 1, "expected single pending change");
    assert_eq!(
        pending[0].operation,
        ChangeType::Create,
        "create should stay create"
    );
    assert!(
        pending[0].base_seq.is_none(),
        "create should keep base_seq empty"
    );
}

#[tokio::test]
async fn local_pending_changes_keep_first_base_seq_on_updates() {
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

    let pending_repo = PendingChangeRepo::new(&pool);
    let _ = pending_repo
        .delete_by_item(storage_id, item_id)
        .await
        .expect("clear pending create");

    services
        .update_item_by_id(
            storage_id,
            item_id,
            "login".to_string(),
            "login".to_string(),
            login_payload("pw-2"),
        )
        .await
        .expect("update item 1");

    services
        .update_item_by_id(
            storage_id,
            item_id,
            "login".to_string(),
            "login".to_string(),
            login_payload("pw-3"),
        )
        .await
        .expect("update item 2");

    let pending = pending_repo
        .list_by_item(storage_id, item_id)
        .await
        .expect("pending list");

    assert_eq!(pending.len(), 1, "expected single pending change");
    assert_eq!(
        pending[0].operation,
        ChangeType::Update,
        "operation stays update"
    );
    assert_eq!(
        pending[0].base_seq,
        Some(1),
        "base_seq should remain from first update"
    );
}
