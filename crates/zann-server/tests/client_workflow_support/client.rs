#![allow(dead_code)]

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use zann_core::crypto::SecretKey;
use zann_core::{EncryptedPayload, ItemsService};
use zann_db::local::{
    LocalStorage, LocalStorageRepo, LocalSyncCursor, LocalVault, LocalVaultRepo, PendingChangeRepo,
    SyncCursorRepo,
};
use zann_db::{connect_sqlite_with_max, migrate_local, SqlitePool};

use super::sync_helpers::{
    apply_personal_pull_change, apply_shared_pull_change, build_shared_push_changes,
};
use super::TestApp;

pub struct LocalClient {
    pub pool: SqlitePool,
    pub storage_id: Uuid,
    pub master_key: SecretKey,
}

pub struct SyncOutcome {
    pub applied: usize,
    pub conflicts: usize,
    pub cursor: Option<String>,
    pub pull_changes: usize,
}

pub struct PullOutcome {
    pub changes: usize,
    pub cursor: Option<String>,
}

impl LocalClient {
    pub async fn new(server_url: &str) -> Self {
        Self::new_with_master(server_url, SecretKey::generate()).await
    }

    pub async fn new_with_master(server_url: &str, master_key: SecretKey) -> Self {
        let db_path =
            std::env::temp_dir().join(format!("zann-client-{}.sqlite", Uuid::now_v7().simple()));
        let db_url = format!("sqlite://{}", db_path.display());
        let pool = connect_sqlite_with_max(&db_url, 5).await.expect("sqlite");
        migrate_local(&pool).await.expect("migrate sqlite");

        let storage_id = Uuid::now_v7();
        let storage = LocalStorage {
            id: storage_id,
            kind: "remote".to_string(),
            name: "Remote Test".to_string(),
            server_url: Some(server_url.to_string()),
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: true,
            auth_method: None,
        };
        let storage_repo = LocalStorageRepo::new(&pool);
        storage_repo.upsert(&storage).await.expect("storage upsert");

        Self {
            pool,
            storage_id,
            master_key,
        }
    }

    pub async fn add_personal_vault(&self, vault_id: Uuid, vault_key_enc: Vec<u8>) {
        let vault = LocalVault {
            id: vault_id,
            storage_id: self.storage_id,
            name: "Personal Vault".to_string(),
            kind: "personal".to_string(),
            is_default: false,
            vault_key_enc,
            key_wrap_type: "remote_strict".to_string(),
            last_synced_at: None,
            server_seq: 0,
        };
        let repo = LocalVaultRepo::new(&self.pool);
        let _ = repo.create(&vault).await;
    }

    pub async fn add_shared_vault(&self, vault_id: Uuid, vault_key_enc: Vec<u8>) {
        let vault = LocalVault {
            id: vault_id,
            storage_id: self.storage_id,
            name: "Shared Vault".to_string(),
            kind: "shared".to_string(),
            is_default: false,
            vault_key_enc,
            key_wrap_type: "remote_server".to_string(),
            last_synced_at: None,
            server_seq: 0,
        };
        let repo = LocalVaultRepo::new(&self.pool);
        let _ = repo.create(&vault).await;
    }

    pub async fn put_item(&self, vault_id: Uuid, path: &str, payload: EncryptedPayload) -> Uuid {
        let services = zann_db::services::LocalServices::new(&self.pool, &self.master_key);
        services
            .put_item(
                self.storage_id,
                vault_id,
                path.to_string(),
                payload.type_id.clone(),
                payload,
            )
            .await
            .expect("put item")
    }

    pub async fn update_item(&self, item_id: Uuid, path: &str, payload: EncryptedPayload) -> Uuid {
        let services = zann_db::services::LocalServices::new(&self.pool, &self.master_key);
        services
            .update_item_by_id(
                self.storage_id,
                item_id,
                path.to_string(),
                payload.type_id.clone(),
                payload,
            )
            .await
            .expect("update item")
    }

    pub async fn get_item_payload(&self, item_id: Uuid) -> EncryptedPayload {
        let services = zann_db::services::LocalServices::new(&self.pool, &self.master_key);
        let item = services
            .get_item(self.storage_id, item_id)
            .await
            .expect("get item");
        item.payload
    }

    pub async fn pending_count(&self, vault_id: Uuid) -> usize {
        let repo = PendingChangeRepo::new(&self.pool);
        repo.list_by_storage_vault(self.storage_id, vault_id)
            .await
            .expect("pending")
            .len()
    }

    pub async fn push_personal(&self, app: &TestApp, token: &str, vault_id: Uuid) {
        let pending_repo = PendingChangeRepo::new(&self.pool);
        let pending = pending_repo
            .list_by_storage_vault(self.storage_id, vault_id)
            .await
            .expect("pending");

        if !pending.is_empty() {
            let changes: Vec<serde_json::Value> = pending
                .iter()
                .map(|change| {
                    json!({
                        "item_id": change.item_id.to_string(),
                        "operation": change.operation,
                        "payload_enc": change.payload_enc,
                        "checksum": change.checksum,
                        "path": change.path,
                        "name": change.name,
                        "type_id": change.type_id,
                        "base_seq": change.base_seq,
                    })
                })
                .collect();
            let (status, json) = app
                .send_json(
                    axum::http::Method::POST,
                    "/v1/sync/push",
                    Some(token),
                    json!({ "vault_id": vault_id, "changes": changes }),
                )
                .await;
            assert_eq!(
                status,
                axum::http::StatusCode::OK,
                "push failed: {:?}",
                json
            );
            let applied = json["applied"].as_array().cloned().unwrap_or_default();
            if !applied.is_empty() {
                let ids: Vec<Uuid> = applied
                    .iter()
                    .filter_map(|id| id.as_str())
                    .filter_map(|value| pending.iter().find(|c| c.item_id.to_string() == value))
                    .map(|change| change.id)
                    .collect();
                let _ = pending_repo.delete_by_ids(&ids).await;
            }
        }
    }

    pub async fn pull_personal(&self, app: &TestApp, token: &str, vault_id: Uuid) -> PullOutcome {
        let cursor_repo = SyncCursorRepo::new(&self.pool);
        let cursor_row = cursor_repo
            .get(&self.storage_id.to_string(), &vault_id.to_string())
            .await
            .expect("cursor")
            .unwrap_or(LocalSyncCursor {
                storage_id: self.storage_id.to_string(),
                vault_id: vault_id.to_string(),
                cursor: None,
                last_sync_at: None,
            });

        let (status, json) = app
            .send_json(
                axum::http::Method::POST,
                "/v1/sync/pull",
                Some(token),
                json!({ "vault_id": vault_id, "cursor": cursor_row.cursor, "limit": 100 }),
            )
            .await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "pull failed: {:?}",
            json
        );
        let changes = json["changes"].as_array().cloned().unwrap_or_default();
        let change_count = changes.len();
        for change in changes {
            apply_personal_pull_change(
                &self.pool,
                self.storage_id,
                vault_id,
                &self.master_key,
                change,
            )
            .await;
        }

        let cursor = LocalSyncCursor {
            storage_id: self.storage_id.to_string(),
            vault_id: vault_id.to_string(),
            cursor: json["next_cursor"].as_str().map(|value| value.to_string()),
            last_sync_at: Some(Utc::now()),
        };
        let _ = cursor_repo.upsert(&cursor).await;
        PullOutcome {
            changes: change_count,
            cursor: cursor.cursor,
        }
    }

    pub async fn sync_shared(&self, app: &TestApp, token: &str, vault_id: Uuid) -> SyncOutcome {
        let pending_repo = PendingChangeRepo::new(&self.pool);
        let pending = pending_repo
            .list_by_storage_vault(self.storage_id, vault_id)
            .await
            .expect("pending");
        let mut applied_count = 0;
        let mut conflict_count = 0;

        if !pending.is_empty() {
            let changes = build_shared_push_changes(&self.master_key, vault_id, &pending).await;
            let (status, json) = app
                .send_json(
                    axum::http::Method::POST,
                    "/v1/sync/shared/push",
                    Some(token),
                    json!({ "vault_id": vault_id, "changes": changes }),
                )
                .await;
            assert_eq!(
                status,
                axum::http::StatusCode::OK,
                "shared push failed: {:?}",
                json
            );
            let applied = json["applied"].as_array().cloned().unwrap_or_default();
            let conflicts = json["conflicts"].as_array().cloned().unwrap_or_default();
            applied_count = applied.len();
            conflict_count = conflicts.len();
            if !applied.is_empty() {
                let ids: Vec<Uuid> = applied
                    .iter()
                    .filter_map(|id| id.as_str())
                    .filter_map(|value| pending.iter().find(|c| c.item_id.to_string() == value))
                    .map(|change| change.id)
                    .collect();
                let _ = pending_repo.delete_by_ids(&ids).await;
            }
        }

        let cursor_repo = SyncCursorRepo::new(&self.pool);
        let cursor_row = cursor_repo
            .get(&self.storage_id.to_string(), &vault_id.to_string())
            .await
            .expect("cursor")
            .unwrap_or(LocalSyncCursor {
                storage_id: self.storage_id.to_string(),
                vault_id: vault_id.to_string(),
                cursor: None,
                last_sync_at: None,
            });

        let (status, json) = app
            .send_json(
                axum::http::Method::POST,
                "/v1/sync/shared/pull",
                Some(token),
                json!({ "vault_id": vault_id, "cursor": cursor_row.cursor, "limit": 100 }),
            )
            .await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "shared pull failed: {:?}",
            json
        );
        let changes = json["changes"].as_array().cloned().unwrap_or_default();
        let change_count = changes.len();
        for change in changes {
            apply_shared_pull_change(
                &self.pool,
                self.storage_id,
                vault_id,
                &self.master_key,
                change,
            )
            .await;
        }
        let cursor = LocalSyncCursor {
            storage_id: self.storage_id.to_string(),
            vault_id: vault_id.to_string(),
            cursor: json["next_cursor"].as_str().map(|value| value.to_string()),
            last_sync_at: Some(Utc::now()),
        };
        let _ = cursor_repo.upsert(&cursor).await;
        SyncOutcome {
            applied: applied_count,
            conflicts: conflict_count,
            cursor: cursor.cursor,
            pull_changes: change_count,
        }
    }
}
