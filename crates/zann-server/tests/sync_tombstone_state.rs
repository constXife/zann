mod client_workflow_support;
mod support;

use axum::http::{Method, StatusCode};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx_core::row::Row;
use sqlx_postgres::Postgres;
use uuid::Uuid;
use zann_core::{ChangeType, SyncStatus};
use zann_crypto::vault_crypto::payload_checksum;
use zann_db::PgPool;

use client_workflow_support::TestApp;

#[derive(Debug, PartialEq)]
struct ItemSnapshot {
    version: i64,
    row_version: i64,
    sync_status: i16,
    payload_enc: Vec<u8>,
    checksum: String,
    updated_at: DateTime<Utc>,
    deleted_at: Option<DateTime<Utc>>,
    deleted_by_user_id: Option<Uuid>,
    deleted_by_device_id: Option<Uuid>,
    current_seq: Option<i64>,
    history_count: i64,
    change_count: i64,
}

#[derive(Debug, PartialEq)]
struct AttachmentSnapshot {
    content_enc: Vec<u8>,
    checksum: String,
    created_at: DateTime<Utc>,
    deleted_at: Option<DateTime<Utc>>,
}

async fn item_snapshot(pool: &PgPool, vault_id: Uuid, item_id: Uuid) -> ItemSnapshot {
    let row = sqlx_core::query::query::<Postgres>(
        r#"
        SELECT
            item.version,
            item.row_version,
            item.sync_status,
            item.payload_enc,
            item.checksum,
            item.updated_at,
            item.deleted_at,
            item.deleted_by_user_id,
            item.deleted_by_device_id,
            (
                SELECT change.seq
                FROM changes AS change
                WHERE change.vault_id = item.vault_id
                  AND change.item_id = item.id
                  AND change.version = item.version
            ) AS current_seq,
            (SELECT COUNT(*) FROM item_history WHERE item_id = item.id) AS history_count,
            (SELECT COUNT(*) FROM changes WHERE item_id = item.id) AS change_count
        FROM items AS item
        WHERE item.vault_id = $1 AND item.id = $2
        "#,
    )
    .bind(vault_id)
    .bind(item_id)
    .fetch_one(pool)
    .await
    .expect("item snapshot");

    ItemSnapshot {
        version: row.try_get("version").expect("version"),
        row_version: row.try_get("row_version").expect("row version"),
        sync_status: row.try_get("sync_status").expect("sync status"),
        payload_enc: row.try_get("payload_enc").expect("payload"),
        checksum: row.try_get("checksum").expect("checksum"),
        updated_at: row.try_get("updated_at").expect("updated at"),
        deleted_at: row.try_get("deleted_at").expect("deleted at"),
        deleted_by_user_id: row.try_get("deleted_by_user_id").expect("deleted by user"),
        deleted_by_device_id: row
            .try_get("deleted_by_device_id")
            .expect("deleted by device"),
        current_seq: row.try_get("current_seq").expect("current sequence"),
        history_count: row.try_get("history_count").expect("history count"),
        change_count: row.try_get("change_count").expect("change count"),
    }
}

async fn attachment_snapshot(pool: &PgPool, attachment_id: Uuid) -> AttachmentSnapshot {
    let row = sqlx_core::query::query::<Postgres>(
        r#"
        SELECT content_enc, checksum, created_at, deleted_at
        FROM attachments
        WHERE id = $1
        "#,
    )
    .bind(attachment_id)
    .fetch_one(pool)
    .await
    .expect("attachment snapshot");
    AttachmentSnapshot {
        content_enc: row.try_get("content_enc").expect("attachment content"),
        checksum: row.try_get("checksum").expect("attachment checksum"),
        created_at: row.try_get("created_at").expect("attachment created at"),
        deleted_at: row.try_get("deleted_at").expect("attachment deleted at"),
    }
}

async fn create_item(
    app: &TestApp,
    token: &str,
    vault_id: Uuid,
    item_id: Uuid,
    path: &str,
    byte: u8,
) -> i64 {
    let payload = vec![byte];
    let (status, response) = app
        .send_json(
            Method::POST,
            "/v1/sync/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Create.as_i32(),
                    "payload_enc": payload,
                    "checksum": payload_checksum(&[byte]),
                    "path": path,
                    "name": path,
                    "type_id": "login",
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "create push: {response:?}");
    assert_eq!(response["conflicts"].as_array().map(Vec::len), Some(0));
    response["applied_changes"][0]["seq"]
        .as_i64()
        .expect("create sequence")
}

fn applied_seq(response: &Value) -> i64 {
    response["applied_changes"][0]["seq"]
        .as_i64()
        .expect("applied sequence")
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn tombstone_update_is_a_conflict_and_rolls_back_other_batch_writes() {
    let email = "sync-tombstone-update@example.com";
    let app = TestApp::new_with_smk().await;
    let registration = app.register(email, "password").await;
    let token = registration["access_token"].as_str().expect("token");
    let vault_id = app.personal_vault_id(email).await;
    app.update_vault_key(token, vault_id, vec![1, 2, 3]).await;
    let deleted_item_id = Uuid::now_v7();
    let active_item_id = Uuid::now_v7();
    let deleted_create_seq =
        create_item(&app, token, vault_id, deleted_item_id, "deleted-item", 1).await;
    let active_create_seq =
        create_item(&app, token, vault_id, active_item_id, "active-item", 2).await;

    let (status, deleted) = app
        .send_json(
            Method::POST,
            "/v1/sync/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": deleted_item_id,
                    "operation": ChangeType::Delete.as_i32(),
                    "base_seq": deleted_create_seq,
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "delete push: {deleted:?}");
    let delete_seq = applied_seq(&deleted);
    let deleted_before = item_snapshot(&app.pool, vault_id, deleted_item_id).await;
    let active_before = item_snapshot(&app.pool, vault_id, active_item_id).await;

    let (status, response) = app
        .send_json(
            Method::POST,
            "/v1/sync/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [
                    {
                        "item_id": active_item_id,
                        "operation": ChangeType::Update.as_i32(),
                        "base_seq": active_create_seq,
                        "payload_enc": [3],
                        "checksum": payload_checksum(&[3_u8]),
                    },
                    {
                        "item_id": deleted_item_id,
                        "operation": ChangeType::Update.as_i32(),
                        "base_seq": delete_seq,
                        "payload_enc": [4],
                        "checksum": payload_checksum(&[4_u8]),
                    }
                ],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "tombstone update: {response:?}");
    assert_eq!(response["applied"].as_array().map(Vec::len), Some(0));
    assert_eq!(
        response["applied_changes"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(response["conflicts"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        response["conflicts"][0]["item_id"],
        deleted_item_id.to_string()
    );
    assert_eq!(response["conflicts"][0]["reason"], "item_deleted");
    assert_eq!(response["conflicts"][0]["server_seq"], delete_seq);

    assert_eq!(
        item_snapshot(&app.pool, vault_id, deleted_item_id).await,
        deleted_before,
        "a tombstone update must not mutate the tombstone"
    );
    assert_eq!(
        item_snapshot(&app.pool, vault_id, active_item_id).await,
        active_before,
        "a later conflict must roll back earlier writes in the same batch"
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn repeated_delete_is_read_only_and_restore_reopens_updates() {
    let email = "sync-delete-retry@example.com";
    let app = TestApp::new_with_smk().await;
    let registration = app.register(email, "password").await;
    let token = registration["access_token"].as_str().expect("token");
    let vault_id = app.personal_vault_id(email).await;
    app.update_vault_key(token, vault_id, vec![1, 2, 3]).await;
    let item_id = Uuid::now_v7();
    let create_seq = create_item(&app, token, vault_id, item_id, "delete-retry", 1).await;
    let attachment_id = Uuid::now_v7();
    let attachment = vec![7_u8, 8, 9];
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO attachments (
            id, item_id, filename, size, mime_type, enc_mode, content_enc,
            checksum, storage_url, deleted_at, created_at
        )
        VALUES ($1, $2, 'proof.bin', $3, 'application/octet-stream', 'opaque', $4,
                $5, NULL, NULL, $6)
        "#,
    )
    .bind(attachment_id)
    .bind(item_id)
    .bind(i64::try_from(attachment.len()).expect("attachment size"))
    .bind(&attachment)
    .bind(payload_checksum(&attachment))
    .bind(Utc::now())
    .execute(&app.pool)
    .await
    .expect("insert attachment");

    let (status, deleted) = app
        .send_json(
            Method::POST,
            "/v1/sync/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Delete.as_i32(),
                    "base_seq": create_seq,
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "delete push: {deleted:?}");
    let delete_seq = applied_seq(&deleted);
    let tombstone_before_retry = item_snapshot(&app.pool, vault_id, item_id).await;
    assert_eq!(
        i32::from(tombstone_before_retry.sync_status),
        SyncStatus::Tombstone.as_i32()
    );
    assert!(tombstone_before_retry.deleted_at.is_some());
    let attachment_before_retry = attachment_snapshot(&app.pool, attachment_id).await;
    assert!(attachment_before_retry.deleted_at.is_some());

    let (status, stale) = app
        .send_json(
            Method::POST,
            "/v1/sync/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Delete.as_i32(),
                    "base_seq": create_seq,
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "stale delete: {stale:?}");
    assert_eq!(stale["applied"].as_array().map(Vec::len), Some(0));
    assert_eq!(stale["conflicts"][0]["reason"], "concurrent_modification");
    assert_eq!(stale["conflicts"][0]["server_seq"], delete_seq);
    assert_eq!(
        item_snapshot(&app.pool, vault_id, item_id).await,
        tombstone_before_retry
    );
    assert_eq!(
        attachment_snapshot(&app.pool, attachment_id).await,
        attachment_before_retry
    );

    let (status, retried) = app
        .send_json(
            Method::POST,
            "/v1/sync/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Delete.as_i32(),
                    "base_seq": delete_seq,
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "delete retry: {retried:?}");
    assert_eq!(retried["conflicts"].as_array().map(Vec::len), Some(0));
    assert_eq!(applied_seq(&retried), delete_seq);
    assert_eq!(
        item_snapshot(&app.pool, vault_id, item_id).await,
        tombstone_before_retry,
        "an exact delete retry must not advance item or change generations"
    );
    assert_eq!(
        attachment_snapshot(&app.pool, attachment_id).await,
        attachment_before_retry,
        "an exact delete retry must not extend attachment GC timing"
    );

    let (status, restored) = app
        .send_json(
            Method::POST,
            "/v1/sync/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Restore.as_i32(),
                    "base_seq": delete_seq,
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "restore push: {restored:?}");
    let restore_seq = applied_seq(&restored);
    let after_restore = item_snapshot(&app.pool, vault_id, item_id).await;
    assert_eq!(
        i32::from(after_restore.sync_status),
        SyncStatus::Active.as_i32()
    );
    assert!(after_restore.deleted_at.is_none());
    assert!(
        attachment_snapshot(&app.pool, attachment_id)
            .await
            .deleted_at
            .is_none(),
        "restore must clear attachment tombstones"
    );

    let (status, updated) = app
        .send_json(
            Method::POST,
            "/v1/sync/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Update.as_i32(),
                    "base_seq": restore_seq,
                    "payload_enc": [5],
                    "checksum": payload_checksum(&[5_u8]),
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "update after restore: {updated:?}");
    let after_update = item_snapshot(&app.pool, vault_id, item_id).await;
    assert_eq!(
        i32::from(after_update.sync_status),
        SyncStatus::Active.as_i32()
    );
    assert_eq!(after_update.version, after_restore.version + 1);
    assert_eq!(after_update.current_seq, Some(applied_seq(&updated)));
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn concurrent_deletes_with_one_base_have_one_winner() {
    let email = "sync-delete-race@example.com";
    let app = TestApp::new_with_smk().await;
    let registration = app.register(email, "password").await;
    let token = registration["access_token"].as_str().expect("token");
    let vault_id = app.personal_vault_id(email).await;
    app.update_vault_key(token, vault_id, vec![1, 2, 3]).await;
    let item_id = Uuid::now_v7();
    let create_seq = create_item(&app, token, vault_id, item_id, "delete-race", 1).await;
    let request = || {
        json!({
            "vault_id": vault_id,
            "changes": [{
                "item_id": item_id,
                "operation": ChangeType::Delete.as_i32(),
                "base_seq": create_seq,
            }],
        })
    };

    let (first, second) = tokio::join!(
        app.send_json(Method::POST, "/v1/sync/push", Some(token), request()),
        app.send_json(Method::POST, "/v1/sync/push", Some(token), request()),
    );
    assert_eq!(first.0, StatusCode::OK, "first delete: {:?}", first.1);
    assert_eq!(second.0, StatusCode::OK, "second delete: {:?}", second.1);
    let applied = first.1["applied"].as_array().map(Vec::len).unwrap_or(0)
        + second.1["applied"].as_array().map(Vec::len).unwrap_or(0);
    let conflicts = first.1["conflicts"].as_array().map(Vec::len).unwrap_or(0)
        + second.1["conflicts"].as_array().map(Vec::len).unwrap_or(0);
    assert_eq!(applied, 1);
    assert_eq!(conflicts, 1);
    let conflict = if first.1["conflicts"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty())
    {
        &first.1["conflicts"][0]
    } else {
        &second.1["conflicts"][0]
    };
    assert_eq!(conflict["reason"], "concurrent_modification");

    let snapshot = item_snapshot(&app.pool, vault_id, item_id).await;
    assert_eq!(snapshot.version, 2);
    assert_eq!(snapshot.history_count, 1);
    assert_eq!(snapshot.change_count, 2);
    assert_eq!(
        i32::from(snapshot.sync_status),
        SyncStatus::Tombstone.as_i32()
    );
}
