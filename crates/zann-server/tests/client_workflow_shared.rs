mod client_workflow_support;
mod support;

use serde_json::json;
use uuid::Uuid;

use client_workflow_support::{key_fingerprint, login_payload, LocalClient, TestApp};
use zann_core::{ChangeType, ItemsService, SyncStatus};

async fn create_item(
    app: &TestApp,
    token: &str,
    vault_id: &str,
    password: &str,
) -> serde_json::Value {
    let payload = json!({
        "path": "login",
        "name": "login",
        "type_id": "login",
        "payload": {
            "v": 1,
            "typeId": "login",
            "fields": {
                "password": { "kind": "password", "value": password }
            }
        }
    });
    let (status, json) = app
        .send_json(
            axum::http::Method::POST,
            &format!("/v1/vaults/{}/items", vault_id),
            Some(token),
            payload,
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::CREATED,
        "create item failed: {:?}",
        json
    );
    json
}

async fn update_item(app: &TestApp, token: &str, vault_id: &str, item_id: &str, password: &str) {
    let payload = json!({
        "path": "login",
        "name": "login",
        "type_id": "login",
        "payload": {
            "v": 1,
            "typeId": "login",
            "fields": {
                "password": { "kind": "password", "value": password }
            }
        }
    });
    let (status, json) = app
        .send_json(
            axum::http::Method::PUT,
            &format!("/v1/vaults/{}/items/{}", vault_id, item_id),
            Some(token),
            payload,
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "update item failed: {:?}",
        json
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_vault_client_server_roundtrip() {
    let app = TestApp::new_with_smk().await;
    let user = app.register("client-shared@example.com", "password").await;
    let token = user["access_token"].as_str().expect("token");

    let client_a = LocalClient::new("http://localhost").await;
    let client_b = LocalClient::new("http://localhost").await;

    let vault = app.create_shared_vault(token, "shared-client").await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("vault id");
    let vault_key_enc: Vec<u8> = vault["vault_key_enc"]
        .as_array()
        .map(|bytes| {
            bytes
                .iter()
                .filter_map(|b| b.as_u64().map(|v| v as u8))
                .collect()
        })
        .unwrap_or_default();

    client_a
        .add_shared_vault(vault_id, vault_key_enc.clone())
        .await;
    client_b.add_shared_vault(vault_id, vault_key_enc).await;

    let item_id = client_a
        .put_item(vault_id, "login", login_payload("pw-shared-a"))
        .await;
    let push_outcome = client_a.sync_shared(&app, token, vault_id).await;
    assert_eq!(push_outcome.conflicts, 0, "shared push should not conflict");
    assert!(push_outcome.applied > 0, "shared push should apply");
    assert_eq!(client_a.pending_count(vault_id).await, 0, "pending cleared");
    let seq_after_push = app.last_seq_for_vault(vault_id).await;
    assert!(seq_after_push > 0, "server seq advanced after shared push");

    let pull_outcome = client_b.sync_shared(&app, token, vault_id).await;
    assert_eq!(pull_outcome.conflicts, 0, "shared pull should not conflict");
    assert!(
        pull_outcome.pull_changes > 0,
        "shared pull should apply changes"
    );
    let payload = client_b.get_item_payload(item_id).await;
    assert_eq!(
        payload.fields["password"].value, "pw-shared-a",
        "shared pull should sync payload"
    );
    let cursor_after_pull = pull_outcome.cursor.clone();
    assert!(cursor_after_pull.is_some(), "cursor stored after pull");

    let noop_outcome = client_b.sync_shared(&app, token, vault_id).await;
    let cursor_after_noop = noop_outcome.cursor;
    assert_eq!(
        cursor_after_noop, cursor_after_pull,
        "cursor stable on noop"
    );
    assert_eq!(noop_outcome.pull_changes, 0, "shared noop should not pull");
    let payload = client_b.get_item_payload(item_id).await;
    assert_eq!(
        payload.fields["password"].value, "pw-shared-a",
        "shared noop should not change payload"
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_push_conflict_on_path_collision() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("shared-conflict@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token, "shared-conflict").await;
    let vault_id = vault["id"].as_str().expect("vault id");

    let server_payload = serde_json::to_value(login_payload("pw-server")).expect("payload json");
    app.create_shared_item(token, vault_id, "login", "login", server_payload)
        .await;

    let client_payload = serde_json::to_value(login_payload("pw-client")).expect("payload json");
    let change_id = Uuid::now_v7();
    let (status, json) = app
        .send_json(
            axum::http::Method::POST,
            "/v1/sync/shared/push",
            Some(token),
            serde_json::json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": change_id.to_string(),
                    "operation": ChangeType::Create.as_i32(),
                    "payload": client_payload,
                    "path": "login",
                    "name": "login",
                    "type_id": "login"
                }]
            }),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "shared push failed: {:?}",
        json
    );
    let conflicts = json["conflicts"].as_array().cloned().unwrap_or_default();
    assert_eq!(conflicts.len(), 1, "expected conflict: {:?}", json);
    assert_eq!(
        conflicts[0]["reason"].as_str(),
        Some("already_exists"),
        "unexpected conflict reason: {:?}",
        conflicts
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_vault_membership_allows_second_user_sync() {
    let app = TestApp::new_with_smk().await;
    let user_a = app
        .register("client-shared-a@example.com", "password")
        .await;
    let user_b = app
        .register("client-shared-b@example.com", "password")
        .await;
    let token_a = user_a["access_token"].as_str().expect("token");
    let token_b = user_b["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token_a, "shared-members").await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("vault id");
    let vault_key_enc: Vec<u8> = vault["vault_key_enc"]
        .as_array()
        .map(|bytes| {
            bytes
                .iter()
                .filter_map(|b| b.as_u64().map(|v| v as u8))
                .collect()
        })
        .unwrap_or_default();

    app.add_vault_member(
        vault_id,
        "client-shared-b@example.com",
        zann_core::VaultMemberRole::Member,
    )
    .await;

    let client_a = LocalClient::new("http://localhost").await;
    let client_b = LocalClient::new("http://localhost").await;

    client_a
        .add_shared_vault(vault_id, vault_key_enc.clone())
        .await;
    client_b.add_shared_vault(vault_id, vault_key_enc).await;

    let item_id = client_a
        .put_item(vault_id, "login", login_payload("pw-a"))
        .await;
    let push_outcome = client_a.sync_shared(&app, token_a, vault_id).await;
    assert_eq!(push_outcome.conflicts, 0, "shared push should not conflict");
    assert!(push_outcome.applied > 0, "shared push should apply");

    let pull_outcome = client_b.sync_shared(&app, token_b, vault_id).await;
    assert_eq!(pull_outcome.conflicts, 0, "shared pull should not conflict");
    assert!(
        pull_outcome.pull_changes > 0,
        "member pull should apply changes"
    );
    let payload = client_b.get_item_payload(item_id).await;
    assert_eq!(
        payload.fields["password"].value, "pw-a",
        "member should read shared payload"
    );

    client_b
        .update_item(item_id, "login", login_payload("pw-b"))
        .await;
    let update_outcome = client_b.sync_shared(&app, token_b, vault_id).await;
    assert_eq!(
        update_outcome.conflicts, 0,
        "member update should not conflict"
    );
    assert!(update_outcome.applied > 0, "member update should apply");
    let pull_outcome = client_a.sync_shared(&app, token_a, vault_id).await;
    assert_eq!(pull_outcome.conflicts, 0, "member pull should not conflict");
    assert!(
        pull_outcome.pull_changes > 0,
        "member pull should apply changes"
    );

    let payload = client_a.get_item_payload(item_id).await;
    assert_eq!(
        payload.fields["password"].value, "pw-b",
        "member update should sync back"
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_sync_includes_plaintext_history_tail() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("shared-sync-history@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");

    let vault = app.create_shared_vault(token, "shared-sync-history").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let item = create_item(&app, token, vault_id, "pw-1").await;
    let item_id = item["id"].as_str().expect("item id");

    update_item(&app, token, vault_id, item_id, "pw-2").await;
    update_item(&app, token, vault_id, item_id, "pw-3").await;

    let (status, json) = app
        .send_json(
            axum::http::Method::POST,
            "/v1/sync/shared/pull",
            Some(token),
            json!({ "vault_id": vault_id, "cursor": null, "limit": 100 }),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "shared sync pull failed: {:?}",
        json
    );
    let changes = json["changes"].as_array().expect("changes");
    let change = changes
        .iter()
        .find(|entry| entry["item_id"].as_str() == Some(item_id))
        .expect("item change");
    let history = change["history"].as_array().expect("history");
    assert!(!history.is_empty(), "history should be included");
    let payload = &history[0]["payload"];
    let password = payload["fields"]["password"]["value"].as_str();
    assert_eq!(
        password,
        Some("pw-2"),
        "shared history should include plaintext payload"
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_cache_key_mismatch_fails_decrypt() {
    let client = LocalClient::new("http://localhost").await;
    let vault_id = Uuid::now_v7();
    client.add_shared_vault(vault_id, Vec::new()).await;

    let item_id = client
        .put_item(vault_id, "login", login_payload("pw-a"))
        .await;

    let other_master = zann_core::crypto::SecretKey::generate();
    let services = zann_db::services::LocalServices::new(&client.pool, &other_master);
    let err = services
        .get_item(client.storage_id, item_id)
        .await
        .expect_err("decrypt should fail with wrong master key");
    assert_eq!(err.kind, "payload_decrypt_failed");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_pull_populates_cache_with_key_fp() {
    let app = TestApp::new_with_smk().await;
    let user = app.register("cache-shared@example.com", "password").await;
    let token = user["access_token"].as_str().expect("token");

    let client_a = LocalClient::new("http://localhost").await;
    let client_b = LocalClient::new("http://localhost").await;

    let vault = app.create_shared_vault(token, "shared-cache").await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("vault id");
    let vault_key_enc: Vec<u8> = vault["vault_key_enc"]
        .as_array()
        .map(|bytes| {
            bytes
                .iter()
                .filter_map(|b| b.as_u64().map(|v| v as u8))
                .collect()
        })
        .unwrap_or_default();

    client_a
        .add_shared_vault(vault_id, vault_key_enc.clone())
        .await;
    client_b.add_shared_vault(vault_id, vault_key_enc).await;

    let item_id = client_a
        .put_item(vault_id, "login", login_payload("pw-cache"))
        .await;
    client_a.sync_shared(&app, token, vault_id).await;
    let pull_outcome = client_b.sync_shared(&app, token, vault_id).await;
    assert!(pull_outcome.pull_changes > 0, "pull should apply changes");

    let repo = zann_db::local::LocalItemRepo::new(&client_b.pool);
    let item = repo
        .get_by_id(client_b.storage_id, item_id)
        .await
        .expect("cache get")
        .expect("cache item");
    assert_eq!(item.sync_status, SyncStatus::Synced);
    assert!(!item.payload_enc.is_empty(), "payload cached");
    assert_eq!(
        item.cache_key_fp.as_deref(),
        Some(key_fingerprint(&client_b.master_key).as_str()),
        "shared cache_key_fp should match master key"
    );
}
