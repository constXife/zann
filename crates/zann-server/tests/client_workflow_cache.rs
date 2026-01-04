mod client_workflow_support;
mod support;

use uuid::Uuid;

use client_workflow_support::{login_payload, LocalClient};

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn cache_update_does_not_duplicate_and_increments_version() {
    let client = LocalClient::new("http://localhost").await;
    let vault_id = Uuid::now_v7();
    client.add_shared_vault(vault_id, Vec::new()).await;

    let item_id = client
        .put_item(vault_id, "login", login_payload("pw-a"))
        .await;
    let repo = zann_db::local::LocalItemRepo::new(&client.pool);
    let item_before = repo
        .get_by_id(client.storage_id, item_id)
        .await
        .expect("cache get")
        .expect("cache item");

    client
        .update_item(item_id, "login", login_payload("pw-b"))
        .await;
    let item_after = repo
        .get_by_id(client.storage_id, item_id)
        .await
        .expect("cache get")
        .expect("cache item");
    let items = repo
        .list_by_vault(client.storage_id, vault_id, true)
        .await
        .expect("cache list");

    assert_eq!(items.len(), 1, "cache should keep single row");
    assert!(
        item_after.version > item_before.version,
        "version increments"
    );
    assert_ne!(
        item_after.checksum, item_before.checksum,
        "checksum changes"
    );
}
