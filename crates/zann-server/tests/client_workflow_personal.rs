mod client_workflow_support;
mod support;

use serde_json::json;
use uuid::Uuid;
use zann_core::crypto::SecretKey;
use zann_core::ItemsService;

use client_workflow_support::{
    decrypt_payload, encrypt_vault_key, key_fingerprint, login_payload, LocalClient, TestApp,
};

async fn create_item(
    app: &TestApp,
    token: &str,
    vault_id: Uuid,
    password: &str,
) -> serde_json::Value {
    let payload = json!({
        "path": "login",
        "name": "login",
        "type_id": "login",
        "payload_enc": password.as_bytes(),
        "checksum": format!("checksum-{}", password)
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

async fn update_item(app: &TestApp, token: &str, vault_id: Uuid, item_id: &str, password: &str) {
    let payload = json!({
        "path": "login",
        "name": "login",
        "type_id": "login",
        "payload_enc": password.as_bytes(),
        "checksum": format!("checksum-{}", password)
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
async fn personal_vault_client_server_roundtrip() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("client-personal@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");

    let client_a = LocalClient::new("http://localhost").await;

    let vault_id = app.personal_vault_id("client-personal@example.com").await;
    let vault_key = SecretKey::generate();
    let vault_key_enc = encrypt_vault_key(&client_a.master_key, vault_id, &vault_key);
    app.update_vault_key(token, vault_id, vault_key_enc.clone())
        .await;

    client_a
        .add_personal_vault(vault_id, vault_key_enc.clone())
        .await;

    let item_id = client_a
        .put_item(vault_id, "login", login_payload("pw-a"))
        .await;
    client_a.push_personal(&app, token, vault_id).await;
    assert_eq!(client_a.pending_count(vault_id).await, 0, "pending cleared");
    let payload_enc = app.item_payload_enc(item_id).await;
    let payload = decrypt_payload(&vault_key, vault_id, item_id, &payload_enc)
        .expect("server payload decrypt");
    assert_eq!(
        payload.fields["password"].value, "pw-a",
        "personal push should reach server"
    );
    let seq_after_create = app.last_seq_for_vault(vault_id).await;
    assert!(seq_after_create > 0, "server seq advanced after create");
    client_a.push_personal(&app, token, vault_id).await;
    let seq_after_noop = app.last_seq_for_vault(vault_id).await;
    assert_eq!(
        seq_after_noop, seq_after_create,
        "noop push should not advance seq"
    );

    client_a
        .update_item(item_id, "login", login_payload("pw-b"))
        .await;
    client_a.push_personal(&app, token, vault_id).await;
    let seq_after_update = app.last_seq_for_vault(vault_id).await;
    assert!(
        seq_after_update > seq_after_create,
        "seq advanced after update"
    );

    let client_b = LocalClient::new_with_master(
        "http://localhost",
        SecretKey::from_bytes(*client_a.master_key.as_bytes()),
    )
    .await;
    client_b
        .add_personal_vault(vault_id, vault_key_enc.clone())
        .await;
    let pull_outcome = client_b.pull_personal(&app, token, vault_id).await;
    assert!(
        pull_outcome.changes > 0,
        "personal pull should return changes"
    );
    assert!(pull_outcome.cursor.is_some(), "personal cursor stored");
    let payload = client_b.get_item_payload(item_id).await;
    assert_eq!(
        payload.fields["password"].value, "pw-b",
        "personal pull should sync payload"
    );

    let payload_enc = app.item_payload_enc(item_id).await;
    let payload = decrypt_payload(&vault_key, vault_id, item_id, &payload_enc)
        .expect("server payload decrypt");
    assert_eq!(
        payload.fields["password"].value, "pw-b",
        "personal update should roundtrip"
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_vault_key_mismatch_fails_decrypt() {
    let client = LocalClient::new("http://localhost").await;
    let vault_id = Uuid::now_v7();
    let vault_key = SecretKey::generate();
    let vault_key_enc = encrypt_vault_key(&client.master_key, vault_id, &vault_key);
    client.add_personal_vault(vault_id, vault_key_enc).await;

    let item_id = client
        .put_item(vault_id, "login", login_payload("pw-a"))
        .await;

    let other_master = SecretKey::generate();
    let services = zann_db::services::LocalServices::new(&client.pool, &other_master);
    let err = services
        .get_item(client.storage_id, item_id)
        .await
        .expect_err("decrypt should fail with wrong master key");
    assert_eq!(err.kind, "vault_key_decrypt_failed");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_pull_populates_cache_with_key_fp() {
    let app = TestApp::new_with_smk().await;
    let user = app.register("cache-personal@example.com", "password").await;
    let token = user["access_token"].as_str().expect("token");

    let client_a = LocalClient::new("http://localhost").await;
    let client_b = LocalClient::new_with_master(
        "http://localhost",
        SecretKey::from_bytes(*client_a.master_key.as_bytes()),
    )
    .await;

    let vault_id = app.personal_vault_id("cache-personal@example.com").await;
    let vault_key = SecretKey::generate();
    let vault_key_enc = encrypt_vault_key(&client_a.master_key, vault_id, &vault_key);
    app.update_vault_key(token, vault_id, vault_key_enc.clone())
        .await;
    client_a
        .add_personal_vault(vault_id, vault_key_enc.clone())
        .await;
    client_b.add_personal_vault(vault_id, vault_key_enc).await;

    let item_id = client_a
        .put_item(vault_id, "login", login_payload("pw-cache"))
        .await;
    client_a.push_personal(&app, token, vault_id).await;
    let pull_outcome = client_b.pull_personal(&app, token, vault_id).await;
    assert!(pull_outcome.changes > 0, "pull should apply changes");

    let repo = zann_db::local::LocalItemRepo::new(&client_b.pool);
    let item = repo
        .get_by_id(client_b.storage_id, item_id)
        .await
        .expect("cache get")
        .expect("cache item");
    assert_eq!(item.sync_status, "synced");
    assert!(!item.payload_enc.is_empty(), "payload cached");
    assert_eq!(
        item.cache_key_fp.as_deref(),
        Some(key_fingerprint(&vault_key).as_str()),
        "personal cache_key_fp should match vault key"
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_sync_includes_history_tail() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("personal-sync-history@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");
    let vault_id = app
        .personal_vault_id("personal-sync-history@example.com")
        .await;

    let item = create_item(&app, token, vault_id, "pw-1").await;
    let item_id = item["id"].as_str().expect("item id").to_string();
    update_item(&app, token, vault_id, &item_id, "pw-2").await;
    update_item(&app, token, vault_id, &item_id, "pw-3").await;

    let (status, json) = app
        .send_json(
            axum::http::Method::POST,
            "/v1/sync/pull",
            Some(token),
            json!({ "vault_id": vault_id, "cursor": null, "limit": 100 }),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "sync pull failed: {:?}",
        json
    );
    let changes = json["changes"].as_array().expect("changes");
    let change = changes
        .iter()
        .find(|entry| entry["item_id"].as_str() == Some(&item_id))
        .expect("item change");
    let history = change["history"].as_array().expect("history");
    assert!(!history.is_empty(), "history should be included");
    assert!(history.len() <= 5, "history tail should not exceed limit");
    let payload_enc = history[0]["payload_enc"].as_array().expect("payload_enc");
    assert!(
        !payload_enc.is_empty(),
        "history payload_enc should be present"
    );
}
