mod client_workflow_support;
mod support;

use uuid::Uuid;
use zann_core::crypto::SecretKey;
use zann_core::ItemsService;

use client_workflow_support::{
    decrypt_payload, encrypt_vault_key, key_fingerprint, login_payload, LocalClient, TestApp,
};

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
