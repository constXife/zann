mod client_workflow_support;
mod support;

use axum::http::{Method, StatusCode};
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::json;
use sqlx_core::pool::PoolOptions;
use sqlx_core::raw_sql::raw_sql;
use sqlx_core::row::Row;
use sqlx_postgres::{PgConnectOptions, Postgres};
use std::collections::{HashMap, HashSet};
use std::env;
use std::str::FromStr;
use std::time::Duration;
use uuid::Uuid;
use zann_core::{Change, ChangeOp, ChangeType};
use zann_crypto::vault_crypto as core_crypto;
use zann_db::repo::{ChangeRepo, ItemRepo};
use zann_db::PgPool;

use client_workflow_support::{login_payload, TestApp};

async fn initialize_personal_vault(app: &TestApp, token: &str, vault_id: Uuid) {
    app.update_vault_key(token, vault_id, vec![1, 2, 3]).await;
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_pull_honors_server_page_cap() {
    let email = "personal-snapshot-pages@example.com";
    let app = TestApp::new_with_smk().await;
    let registration = app.register(email, "password").await;
    let token = registration["access_token"].as_str().expect("token");
    let vault_id = app.personal_vault_id(email).await;
    initialize_personal_vault(&app, token, vault_id).await;

    for index in 0..5 {
        let payload = format!("encrypted-{index}").into_bytes();
        let checksum = core_crypto::payload_checksum(&payload);
        let (status, item) = app
            .send_json(
                Method::POST,
                &format!("/v1/vaults/{vault_id}/items"),
                Some(token),
                json!({
                    "path": format!("personal-login-{index}"),
                    "name": format!("personal-login-{index}"),
                    "type_id": "login",
                    "payload_enc": payload,
                    "checksum": checksum,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create item: {item:?}");
    }

    let (status, first_page) = app
        .send_json(
            Method::POST,
            "/v1/sync/pull",
            Some(token),
            json!({ "vault_id": vault_id, "cursor": null, "limit": 100 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "first pull: {first_page:?}");
    assert_eq!(first_page["changes"].as_array().map(Vec::len), Some(4));
    assert_eq!(first_page["has_more"], true);

    let (status, second_page) = app
        .send_json(
            Method::POST,
            "/v1/sync/pull",
            Some(token),
            json!({
                "vault_id": vault_id,
                "cursor": first_page["next_cursor"],
                "limit": 100,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "second pull: {second_page:?}");
    assert_eq!(second_page["changes"].as_array().map(Vec::len), Some(1));
    assert_eq!(second_page["has_more"], false);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_push_verifies_payload_pairs_and_never_advances_pull_cursor() {
    let email = "personal-push-integrity@example.com";
    let app = TestApp::new_with_smk().await;
    let registration = app.register(email, "password").await;
    let token = registration["access_token"].as_str().expect("token");
    let vault_id = app.personal_vault_id(email).await;
    initialize_personal_vault(&app, token, vault_id).await;
    let item_id = Uuid::now_v7();
    let payload = vec![1_u8, 2, 3, 4];
    let checksum = core_crypto::payload_checksum(&payload);

    let (status, created) = app
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
                    "checksum": checksum,
                    "path": "push-integrity",
                    "name": "push-integrity",
                    "type_id": "login",
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "create push: {created:?}");
    assert_eq!(created["applied"].as_array().map(Vec::len), Some(1));
    assert_eq!(cursor_seq(&created["new_cursor"]), 0);
    let base_seq = created["applied_changes"][0]["seq"]
        .as_i64()
        .expect("create sequence");

    for (body, expected_error) in [
        (
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Update.as_i32(),
                    "base_seq": base_seq,
                    "payload_enc": [5, 6, 7],
                }],
            }),
            "missing_checksum",
        ),
        (
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Update.as_i32(),
                    "base_seq": base_seq,
                    "checksum": core_crypto::payload_checksum(&[5_u8, 6, 7]),
                }],
            }),
            "checksum_without_payload",
        ),
        (
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Update.as_i32(),
                    "base_seq": base_seq,
                    "payload_enc": [5, 6, 7],
                    "checksum": core_crypto::payload_checksum(&[9_u8, 9, 9]),
                }],
            }),
            "checksum_mismatch",
        ),
    ] {
        let (status, error) = app
            .send_json(Method::POST, "/v1/sync/push", Some(token), body)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "push error: {error:?}");
        assert_eq!(error["error"], expected_error);
    }

    for body in [
        json!({
            "vault_id": vault_id,
            "changes": [{
                "item_id": item_id,
                "operation": ChangeType::Update.as_i32(),
                "payload_enc": [5, 6, 7],
                "checksum": core_crypto::payload_checksum(&[5_u8, 6, 7]),
            }],
        }),
        json!({
            "vault_id": vault_id,
            "changes": [{
                "item_id": item_id,
                "operation": ChangeType::Update.as_i32(),
                "base_seq": 0,
                "payload_enc": [5, 6, 7],
                "checksum": core_crypto::payload_checksum(&[5_u8, 6, 7]),
            }],
        }),
        json!({
            "vault_id": vault_id,
            "changes": [{
                "item_id": item_id,
                "operation": ChangeType::Update.as_i32(),
                "base_seq": -1,
                "payload_enc": [5, 6, 7],
                "checksum": core_crypto::payload_checksum(&[5_u8, 6, 7]),
            }],
        }),
    ] {
        let (status, error) = app
            .send_json(Method::POST, "/v1/sync/push", Some(token), body)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "base shape: {error:?}");
        assert_eq!(error["error"], "base_seq_required");
    }

    let (status, response) = app
        .send_json(
            Method::POST,
            "/v1/sync/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Update.as_i32(),
                    "base_seq": base_seq + 100,
                    "payload_enc": [5, 6, 7],
                    "checksum": core_crypto::payload_checksum(&[5_u8, 6, 7]),
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "future base: {response:?}");
    assert_eq!(response["applied"].as_array().map(Vec::len), Some(0));
    assert_eq!(response["conflicts"].as_array().map(Vec::len), Some(1));

    let version: i64 =
        sqlx_core::query::query::<Postgres>("SELECT version FROM items WHERE id = $1")
            .bind(item_id)
            .fetch_one(&app.pool)
            .await
            .expect("item after rejected pushes")
            .try_get("version")
            .expect("version");
    assert_eq!(version, 1, "rejected pushes must roll back item changes");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_push_rolls_back_on_a_conflicting_history_generation() {
    let email = "personal-history-collision@example.com";
    let app = TestApp::new_with_smk().await;
    let registration = app.register(email, "password").await;
    let token = registration["access_token"].as_str().expect("token");
    let vault_id = app.personal_vault_id(email).await;
    initialize_personal_vault(&app, token, vault_id).await;
    let item_id = Uuid::now_v7();
    let original_payload = vec![1_u8, 2, 3];
    let original_checksum = core_crypto::payload_checksum(&original_payload);

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
                    "payload_enc": original_payload,
                    "checksum": original_checksum,
                    "path": "history-collision",
                    "name": "history-collision",
                    "type_id": "login",
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "create push: {response:?}");
    let base_seq = response["applied_changes"][0]["seq"]
        .as_i64()
        .expect("create sequence");

    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO item_history (
            id, item_id, version, payload_enc, checksum, change_type, fields_changed,
            changed_by_user_id, changed_by_email, changed_by_name, changed_by_device_id,
            changed_by_device_name, created_at
        )
        SELECT
            $2, item.id, item.version, $3, $5, 2, NULL,
            device.user_id, $4, NULL, item.device_id, NULL, NOW() - INTERVAL '1 hour'
        FROM items AS item
        JOIN devices AS device ON device.id = item.device_id
        WHERE item.id = $1
        "#,
    )
    .bind(item_id)
    .bind(Uuid::now_v7())
    .bind(vec![99_u8])
    .bind(email)
    .bind(core_crypto::payload_checksum(&[99_u8]))
    .execute(&app.pool)
    .await
    .expect("seed conflicting history generation");

    let replacement_payload = vec![4_u8, 5, 6];
    let (status, error) = app
        .send_json(
            Method::POST,
            "/v1/sync/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Update.as_i32(),
                    "base_seq": base_seq,
                    "payload_enc": replacement_payload,
                    "checksum": core_crypto::payload_checksum(&[4_u8, 5, 6]),
                }],
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "conflicting history push: {error:?}"
    );
    assert_eq!(error["error"], "db_error");

    let row =
        sqlx_core::query::query::<Postgres>("SELECT version, payload_enc FROM items WHERE id = $1")
            .bind(item_id)
            .fetch_one(&app.pool)
            .await
            .expect("item after history conflict");
    assert_eq!(row.try_get::<i64, _>("version").expect("version"), 1);
    assert_eq!(
        row.try_get::<Vec<u8>, _>("payload_enc").expect("payload"),
        [1_u8, 2, 3]
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn sync_update_accepts_the_authoritative_snapshot_from_an_ordinary_create() {
    let email = "ordinary-create-sync-update@example.com";
    let app = TestApp::new_with_smk().await;
    let registration = app.register(email, "password").await;
    let token = registration["access_token"].as_str().expect("token");
    let vault_id = app.personal_vault_id(email).await;
    initialize_personal_vault(&app, token, vault_id).await;
    let original = vec![1_u8, 2, 3];
    let (status, created) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{vault_id}/items"),
            Some(token),
            json!({
                "path": "ordinary-then-sync",
                "type_id": "login",
                "payload_enc": original,
                "checksum": core_crypto::payload_checksum(&[1_u8, 2, 3]),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "ordinary create: {created:?}");
    let item_id = Uuid::parse_str(created["id"].as_str().expect("item id")).expect("item uuid");
    let base_seq: i64 = sqlx_core::query::query::<Postgres>(
        r#"
        SELECT change.seq
        FROM items AS item
        JOIN changes AS change
          ON change.item_id = item.id
         AND change.vault_id = item.vault_id
         AND change.version = item.version
        WHERE item.id = $1
        "#,
    )
    .bind(item_id)
    .fetch_one(&app.pool)
    .await
    .expect("ordinary create generation")
    .try_get("seq")
    .expect("base sequence");

    let replacement = vec![4_u8, 5, 6];
    let (status, response) = app
        .send_json(
            Method::POST,
            "/v1/sync/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Update.as_i32(),
                    "base_seq": base_seq,
                    "payload_enc": replacement,
                    "checksum": core_crypto::payload_checksum(&[4_u8, 5, 6]),
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "sync update: {response:?}");
    assert_eq!(response["applied"].as_array().map(Vec::len), Some(1));
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_push_rejects_type_changes_without_mutating_item_history_or_changes() {
    let app = TestApp::new_with_smk().await;
    let registration = app
        .register("shared-type-immutable@example.com", "password")
        .await;
    let token = registration["access_token"].as_str().expect("token");
    let vault = app
        .create_shared_vault(token, "shared-type-immutable")
        .await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("vault uuid");
    let item_id = Uuid::now_v7();
    let (status, created) = app
        .send_json(
            Method::POST,
            "/v1/sync/shared/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Create.as_i32(),
                    "path": "immutable-type",
                    "name": "immutable-type",
                    "type_id": "login",
                    "payload": login_payload("before"),
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "create: {created:?}");
    let base_seq = created["applied_changes"][0]["seq"]
        .as_i64()
        .expect("create sequence");

    let before = sqlx_core::query::query::<Postgres>(
        r#"
        SELECT
            item.type_id,
            item.version,
            item.payload_enc,
            item.checksum,
            (SELECT COUNT(*) FROM item_history WHERE item_id = item.id) AS history_count,
            (SELECT COUNT(*) FROM changes WHERE item_id = item.id) AS change_count
        FROM items AS item
        WHERE item.id = $1 AND item.vault_id = $2
        "#,
    )
    .bind(item_id)
    .bind(vault_id)
    .fetch_one(&app.pool)
    .await
    .expect("item before rejected type change");

    let (status, error) = app
        .send_json(
            Method::POST,
            "/v1/sync/shared/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Update.as_i32(),
                    "base_seq": base_seq,
                    "path": "immutable-type",
                    "name": "immutable-type",
                    "type_id": "note",
                    "payload": {
                        "v": 1,
                        "typeId": "note",
                        "fields": {"body": {"kind": "text", "value": "after"}}
                    },
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "type change: {error:?}");
    assert_eq!(error["error"], "type_change_not_supported");

    let after = sqlx_core::query::query::<Postgres>(
        r#"
        SELECT
            item.type_id,
            item.version,
            item.payload_enc,
            item.checksum,
            (SELECT COUNT(*) FROM item_history WHERE item_id = item.id) AS history_count,
            (SELECT COUNT(*) FROM changes WHERE item_id = item.id) AS change_count
        FROM items AS item
        WHERE item.id = $1 AND item.vault_id = $2
        "#,
    )
    .bind(item_id)
    .bind(vault_id)
    .fetch_one(&app.pool)
    .await
    .expect("item after rejected type change");
    for column in ["type_id", "checksum"] {
        assert_eq!(
            before.try_get::<String, _>(column).expect("before text"),
            after.try_get::<String, _>(column).expect("after text")
        );
    }
    assert_eq!(
        before
            .try_get::<Vec<u8>, _>("payload_enc")
            .expect("before payload"),
        after
            .try_get::<Vec<u8>, _>("payload_enc")
            .expect("after payload")
    );
    for column in ["version", "history_count", "change_count"] {
        assert_eq!(
            before.try_get::<i64, _>(column).expect("before number"),
            after.try_get::<i64, _>(column).expect("after number")
        );
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn item_type_retype_authorization_is_transaction_local_and_exactly_scoped() {
    let app = TestApp::new_with_smk().await;
    let registration = app
        .register("scoped-type-retype@example.com", "password")
        .await;
    let token = registration["access_token"].as_str().expect("token");
    let vault = app.create_shared_vault(token, "scoped-type-retype").await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("vault uuid");
    let item_id = Uuid::now_v7();
    let (status, created) = app
        .send_json(
            Method::POST,
            "/v1/sync/shared/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Create.as_i32(),
                    "path": "scoped-retype",
                    "name": "scoped-retype",
                    "type_id": "login",
                    "payload": login_payload("before"),
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "create: {created:?}");

    for (authorized_item_id, authorized_from, authorized_to) in [
        (Uuid::now_v7(), "login", "kv"),
        (item_id, "note", "kv"),
        (item_id, "login", "note"),
    ] {
        assert_retype_authorization_rejected(
            &app.pool,
            item_id,
            authorized_item_id,
            authorized_from,
            authorized_to,
        )
        .await;
    }

    let repo = ItemRepo::new(&app.pool);
    let mut tx = app.pool.begin().await.expect("begin exact retype");
    repo.authorize_type_retype_in(&mut tx, item_id, "login", "kv")
        .await
        .expect("authorize exact retype");
    update_item_type_for_trigger_test(&mut tx, item_id, "kv").await;
    raw_sql("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await
        .expect("exactly scoped retype must pass deferred trigger");
    tx.rollback().await.expect("roll back exact retype probe");

    let row = sqlx_core::query::query::<Postgres>(
        r#"
        SELECT
            type_id,
            version,
            (SELECT COUNT(*) FROM changes WHERE item_id = items.id) AS change_count
        FROM items
        WHERE id = $1
        "#,
    )
    .bind(item_id)
    .fetch_one(&app.pool)
    .await
    .expect("item after scoped retype probes");
    assert_eq!(row.try_get::<String, _>("type_id").expect("type"), "login");
    assert_eq!(row.try_get::<i64, _>("version").expect("version"), 1);
    assert_eq!(
        row.try_get::<i64, _>("change_count").expect("change count"),
        1
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_push_rejects_wrong_typed_version_and_outer_type_before_mutation() {
    let app = TestApp::new_with_smk().await;
    let registration = app
        .register("shared-typed-validation@example.com", "password")
        .await;
    let token = registration["access_token"].as_str().expect("token");
    let vault = app
        .create_shared_vault(token, "shared-typed-validation")
        .await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("vault uuid");

    for (index, payload) in [
        (
            0,
            json!({
                "v": 2,
                "typeId": "login",
                "fields": {"password": {"kind": "password", "value": "secret"}}
            }),
        ),
        (
            1,
            json!({
                "v": 1,
                "typeId": "note",
                "fields": {"body": {"kind": "text", "value": "secret"}}
            }),
        ),
    ] {
        let (status, error) = app
            .send_json(
                Method::POST,
                "/v1/sync/shared/push",
                Some(token),
                json!({
                    "vault_id": vault_id,
                    "changes": [{
                        "item_id": Uuid::now_v7(),
                        "operation": ChangeType::Create.as_i32(),
                        "path": format!("invalid-typed-{index}"),
                        "name": format!("invalid-typed-{index}"),
                        "type_id": "login",
                        "payload": payload,
                    }],
                }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "typed payload: {error:?}");
        assert_eq!(error["error"], "invalid_payload");
    }

    let item_count: i64 = sqlx_core::query::query::<Postgres>(
        "SELECT COUNT(*) AS count FROM items WHERE vault_id = $1",
    )
    .bind(vault_id)
    .fetch_one(&app.pool)
    .await
    .expect("items after rejected typed payloads")
    .try_get("count")
    .expect("count");
    assert_eq!(item_count, 0);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_push_treats_a_wrong_vault_item_as_missing_without_mutation() {
    let app = TestApp::new_with_smk().await;
    let registration = app
        .register("shared-push-wrong-vault@example.com", "password")
        .await;
    let token = registration["access_token"].as_str().expect("token");
    let first = app.create_shared_vault(token, "push-wrong-first").await;
    let second = app.create_shared_vault(token, "push-wrong-second").await;
    let first_id = Uuid::parse_str(first["id"].as_str().expect("first id")).expect("vault uuid");
    let second_id = Uuid::parse_str(second["id"].as_str().expect("second id")).expect("vault uuid");
    let item_id = Uuid::now_v7();
    let (status, created) = app
        .send_json(
            Method::POST,
            "/v1/sync/shared/push",
            Some(token),
            json!({
                "vault_id": second_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Create.as_i32(),
                    "path": "wrong-vault-item",
                    "name": "wrong-vault-item",
                    "type_id": "login",
                    "payload": login_payload("before"),
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "create: {created:?}");
    let base_seq = created["applied_changes"][0]["seq"]
        .as_i64()
        .expect("create sequence");
    let before = sqlx_core::query::query::<Postgres>(
        "SELECT version, payload_enc, checksum FROM items WHERE id = $1 AND vault_id = $2",
    )
    .bind(item_id)
    .bind(second_id)
    .fetch_one(&app.pool)
    .await
    .expect("item before wrong-vault push");

    let (status, response) = app
        .send_json(
            Method::POST,
            "/v1/sync/shared/push",
            Some(token),
            json!({
                "vault_id": first_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Update.as_i32(),
                    "base_seq": base_seq,
                    "path": "wrong-vault-item",
                    "name": "wrong-vault-item",
                    "type_id": "login",
                    "payload": login_payload("after"),
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "wrong-vault push: {response:?}");
    let conflicts = response["conflicts"].as_array().expect("conflicts");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0]["reason"], "missing_item");
    assert_eq!(cursor_seq(&response["new_cursor"]), 0);

    let after = sqlx_core::query::query::<Postgres>(
        "SELECT version, payload_enc, checksum FROM items WHERE id = $1 AND vault_id = $2",
    )
    .bind(item_id)
    .bind(second_id)
    .fetch_one(&app.pool)
    .await
    .expect("item after wrong-vault push");
    assert_eq!(
        before.try_get::<i64, _>("version").expect("before version"),
        after.try_get::<i64, _>("version").expect("after version")
    );
    assert_eq!(
        before
            .try_get::<Vec<u8>, _>("payload_enc")
            .expect("before payload"),
        after
            .try_get::<Vec<u8>, _>("payload_enc")
            .expect("after payload")
    );
    assert_eq!(
        before
            .try_get::<String, _>("checksum")
            .expect("before checksum"),
        after
            .try_get::<String, _>("checksum")
            .expect("after checksum")
    );
    let first_vault_changes: i64 = sqlx_core::query::query::<Postgres>(
        "SELECT COUNT(*) AS count FROM changes WHERE vault_id = $1 AND item_id = $2",
    )
    .bind(first_id)
    .bind(item_id)
    .fetch_one(&app.pool)
    .await
    .expect("first vault changes")
    .try_get("count")
    .expect("count");
    assert_eq!(first_vault_changes, 0);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_pull_rejects_oversized_current_items_without_returning_payloads() {
    let email = "personal-oversized-item@example.com";
    let app = TestApp::new_with_smk().await;
    let registration = app.register(email, "password").await;
    let token = registration["access_token"].as_str().expect("token");
    let vault_id = app.personal_vault_id(email).await;
    initialize_personal_vault(&app, token, vault_id).await;
    let initial_payload = vec![1_u8, 2, 3];
    let initial_checksum = core_crypto::payload_checksum(&initial_payload);

    let (status, item) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{vault_id}/items"),
            Some(token),
            json!({
                "path": "oversized-current",
                "name": "oversized-current",
                "type_id": "login",
                "payload_enc": initial_payload,
                "checksum": initial_checksum,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create item: {item:?}");
    let item_id = Uuid::parse_str(item["id"].as_str().expect("item id")).expect("item uuid");
    let oversized_payload = vec![7_u8; 256 * 1_024 + 257];
    let oversized_checksum = core_crypto::payload_checksum(&oversized_payload);
    // Simulate a dirty imported row in this isolated test schema. Production
    // installs retain the database bound and cannot create this state.
    sqlx_core::query::query::<Postgres>("ALTER TABLE items DROP CONSTRAINT items_payload_bounds")
        .execute(&app.pool)
        .await
        .expect("disable item payload bound for corruption fixture");
    sqlx_core::query::query::<Postgres>(
        r#"
        UPDATE items
        SET payload_enc = $2,
            checksum = $3,
            version = version + 1,
            row_version = row_version + 1,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(item_id)
    .bind(oversized_payload)
    .bind(oversized_checksum)
    .execute(&app.pool)
    .await
    .expect("seed oversized current item");

    let (status, error) = app
        .send_json(
            Method::POST,
            "/v1/sync/pull",
            Some(token),
            json!({ "vault_id": vault_id, "cursor": null, "limit": 100 }),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "pull: {error:?}");
    assert_eq!(error["error"], "sync_item_too_large");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_pull_rejects_oversized_history_without_returning_payloads() {
    let email = "personal-oversized-history@example.com";
    let app = TestApp::new_with_smk().await;
    let registration = app.register(email, "password").await;
    let token = registration["access_token"].as_str().expect("token");
    let vault_id = app.personal_vault_id(email).await;
    initialize_personal_vault(&app, token, vault_id).await;
    let initial_payload = vec![1_u8, 2, 3];
    let initial_checksum = core_crypto::payload_checksum(&initial_payload);

    let (status, item) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{vault_id}/items"),
            Some(token),
            json!({
                "path": "oversized-history",
                "name": "oversized-history",
                "type_id": "login",
                "payload_enc": initial_payload,
                "checksum": initial_checksum,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create item: {item:?}");
    let item_id = Uuid::parse_str(item["id"].as_str().expect("item id")).expect("item uuid");
    let oversized_payload = vec![8_u8; 256 * 1_024 + 257];
    let oversized_checksum = core_crypto::payload_checksum(&oversized_payload);
    // Simulate a dirty imported history row in this isolated test schema.
    sqlx_core::query::query::<Postgres>(
        "ALTER TABLE item_history DROP CONSTRAINT item_history_payload_bounds",
    )
    .execute(&app.pool)
    .await
    .expect("disable history payload bound for corruption fixture");
    sqlx_core::query::query::<Postgres>(
        r#"
        UPDATE item_history
        SET payload_enc = $2,
            checksum = $3
        WHERE item_id = $1
        "#,
    )
    .bind(item_id)
    .bind(oversized_payload)
    .bind(oversized_checksum)
    .execute(&app.pool)
    .await
    .expect("seed oversized history");

    let (status, error) = app
        .send_json(
            Method::POST,
            "/v1/sync/pull",
            Some(token),
            json!({ "vault_id": vault_id, "cursor": null, "limit": 100 }),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "pull: {error:?}");
    assert_eq!(error["error"], "sync_history_too_large");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_pull_rejects_an_oversized_dirty_vault_before_key_materialization() {
    let app = TestApp::new_with_smk().await;
    let registration = app
        .register("shared-oversized-vault@example.com", "password")
        .await;
    let token = registration["access_token"].as_str().expect("token");
    let vault = app
        .create_shared_vault(token, "shared-oversized-vault")
        .await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("vault uuid");

    // Simulate an imported dirty row in this isolated schema; production keeps
    // the constraint and never materializes an oversized encrypted key.
    sqlx_core::query::query::<Postgres>("ALTER TABLE vaults DROP CONSTRAINT vaults_key_bounds")
        .execute(&app.pool)
        .await
        .expect("disable vault key bound for corruption fixture");
    sqlx_core::query::query::<Postgres>("UPDATE vaults SET vault_key_enc = $2 WHERE id = $1")
        .bind(vault_id)
        .bind(vec![7_u8; 64 * 1_024 + 1])
        .execute(&app.pool)
        .await
        .expect("seed oversized vault key");

    let (status, error) = app
        .send_json(
            Method::POST,
            "/v1/sync/shared/pull",
            Some(token),
            json!({ "vault_id": vault_id, "cursor": null, "limit": 1 }),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "pull: {error:?}");
    assert_eq!(error["error"], "sync_vault_too_large");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_pull_does_not_leak_a_wrong_vault_change_row() {
    let app = TestApp::new_with_smk().await;
    let registration = app
        .register("shared-wrong-vault@example.com", "password")
        .await;
    let token = registration["access_token"].as_str().expect("token");
    let first_vault = app.create_shared_vault(token, "wrong-vault-first").await;
    let second_vault = app.create_shared_vault(token, "wrong-vault-second").await;
    let first_vault_id =
        Uuid::parse_str(first_vault["id"].as_str().expect("first vault id")).expect("vault uuid");
    let second_vault_id =
        Uuid::parse_str(second_vault["id"].as_str().expect("second vault id")).expect("vault uuid");
    let (status, item) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{second_vault_id}/items"),
            Some(token),
            json!({
                "path": "wrong-vault-item",
                "type_id": "login",
                "payload": login_payload("secret"),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create item: {item:?}");
    let item_id = Uuid::parse_str(item["id"].as_str().expect("item id")).expect("item uuid");

    let mut corruption_tx = app.pool.begin().await.expect("begin corruption fixture");
    sqlx_core::query::query::<Postgres>(
        "ALTER TABLE changes DISABLE TRIGGER changes_10_validate_semantics",
    )
    .execute(&mut *corruption_tx)
    .await
    .expect("disable change semantic validation");
    sqlx_core::query::query::<Postgres>("UPDATE changes SET vault_id = $2 WHERE item_id = $1")
        .bind(item_id)
        .bind(first_vault_id)
        .execute(&mut *corruption_tx)
        .await
        .expect("seed wrong-vault change");
    sqlx_core::query::query::<Postgres>(
        "ALTER TABLE changes ENABLE TRIGGER changes_10_validate_semantics",
    )
    .execute(&mut *corruption_tx)
    .await
    .expect("enable change semantic validation");
    corruption_tx
        .commit()
        .await
        .expect("commit corruption fixture");

    let (status, response) = app
        .send_json(
            Method::POST,
            "/v1/sync/shared/pull",
            Some(token),
            json!({ "vault_id": first_vault_id, "cursor": null, "limit": 100 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "wrong-vault pull: {response:?}");
    assert_eq!(response["changes"].as_array().map(Vec::len), Some(0));
    assert_eq!(response["has_more"], false);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_initial_pull_honors_page_limit_and_advances_cursor() {
    let app = TestApp::new_with_smk().await;
    let registration = app
        .register("shared-snapshot-pages@example.com", "password")
        .await;
    let token = registration["access_token"].as_str().expect("token");
    let vault = app
        .create_shared_vault(token, "shared-snapshot-pages")
        .await;
    let vault_id = vault["id"].as_str().expect("vault id");

    let mut item_ids = Vec::new();
    for index in 0..6 {
        let (status, item) = app
            .send_json(
                Method::POST,
                &format!("/v1/vaults/{vault_id}/items"),
                Some(token),
                json!({
                    "path": format!("login-{index}"),
                    "type_id": "login",
                    "payload": login_payload(&format!("password-{index}")),
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create item: {item:?}");
        item_ids.push(item["id"].as_str().expect("item id").to_string());
    }

    for version in 0..5 {
        let (status, body) = app
            .send_json(
                Method::PUT,
                &format!("/v1/vaults/{vault_id}/items/{}", item_ids[0]),
                Some(token),
                json!({
                    "path": "login-0",
                    "name": "login-0",
                    "type_id": "login",
                    "payload": login_payload(&format!("updated-{version}")),
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "update item: {body:?}");
    }

    for item_id in [&item_ids[4], &item_ids[5]] {
        let (status, body) = app
            .send_json(
                Method::DELETE,
                &format!("/v1/vaults/{vault_id}/items/{item_id}"),
                Some(token),
                serde_json::Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "delete item: {body:?}");
    }
    let restored_item_id = &item_ids[4];
    let deleted_item_id = &item_ids[5];
    let restore_base_seq: i64 = sqlx_core::query::query::<Postgres>(
        r#"
        SELECT change.seq
        FROM items AS item
        JOIN changes AS change
          ON change.item_id = item.id
         AND change.vault_id = item.vault_id
         AND change.version = item.version
        WHERE item.id = $1
        "#,
    )
    .bind(Uuid::parse_str(restored_item_id).expect("restored item id"))
    .fetch_one(&app.pool)
    .await
    .expect("restore base generation")
    .try_get("seq")
    .expect("restore base sequence");
    let (status, restored) = app
        .send_json(
            Method::POST,
            "/v1/sync/shared/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": restored_item_id,
                    "operation": ChangeType::Restore.as_i32(),
                    "base_seq": restore_base_seq,
                    "payload": login_payload("restored"),
                    "path": "login-4",
                    "name": "login-4",
                    "type_id": "login",
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "restore item: {restored:?}");
    assert_eq!(restored["conflicts"].as_array().map(Vec::len), Some(0));
    assert_eq!(cursor_seq(&restored["new_cursor"]), 0);

    let (status, first_page) = app
        .send_json(
            Method::POST,
            "/v1/sync/shared/pull",
            Some(token),
            json!({ "vault_id": vault_id, "cursor": null, "limit": 100 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "first pull: {first_page:?}");
    let first_changes = first_page["changes"].as_array().expect("first changes");
    assert_eq!(first_changes.len(), 4, "server-side page cap");
    assert_eq!(first_page["has_more"], true);
    let first_cursor = first_page["next_cursor"]
        .as_str()
        .expect("first cursor")
        .to_string();

    let (status, second_page) = app
        .send_json(
            Method::POST,
            "/v1/sync/shared/pull",
            Some(token),
            json!({ "vault_id": vault_id, "cursor": first_cursor, "limit": 100 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "second pull: {second_page:?}");
    let second_changes = second_page["changes"].as_array().expect("second changes");
    assert_eq!(second_changes.len(), 2);
    assert_eq!(second_page["has_more"], false);
    let second_cursor = second_page["next_cursor"]
        .as_str()
        .expect("second cursor")
        .to_string();

    let all_changes: Vec<&serde_json::Value> =
        first_changes.iter().chain(second_changes.iter()).collect();
    let sequences: Vec<i64> = all_changes
        .iter()
        .map(|change| change["seq"].as_i64().expect("change seq"))
        .collect();
    assert!(
        sequences.windows(2).all(|window| window[0] < window[1]),
        "sequences must progress strictly: {sequences:?}"
    );
    assert_eq!(
        sequences.len(),
        6,
        "only each current generation is visible"
    );
    let unique_items: HashSet<&str> = all_changes
        .iter()
        .map(|change| change["item_id"].as_str().expect("item id"))
        .collect();
    assert_eq!(unique_items.len(), 6, "older generations must be filtered");

    let delete = all_changes
        .iter()
        .find(|change| {
            change["item_id"].as_str() == Some(deleted_item_id.as_str())
                && change["operation"].as_i64() == Some(i64::from(ChangeType::Delete.as_i32()))
        })
        .expect("delete generation");
    assert!(
        delete["payload"].is_null(),
        "delete payload must stay absent"
    );
    let restored = all_changes
        .iter()
        .find(|change| change["item_id"].as_str() == Some(restored_item_id.as_str()))
        .expect("restored generation");
    assert_eq!(
        restored["operation"].as_i64(),
        Some(i64::from(ChangeType::Update.as_i32()))
    );
    assert!(!restored["payload"].is_null());

    let (status, final_page) = app
        .send_json(
            Method::POST,
            "/v1/sync/shared/pull",
            Some(token),
            json!({ "vault_id": vault_id, "cursor": second_cursor, "limit": 100 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "final pull: {final_page:?}");
    assert_eq!(final_page["changes"].as_array().map(Vec::len), Some(0));
    assert_eq!(final_page["has_more"], false);
    assert_eq!(final_page["next_cursor"], second_page["next_cursor"]);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn shared_push_reports_a_generation_collision_as_a_conflict() {
    let app = TestApp::new_with_smk().await;
    let registration = app
        .register("shared-generation-conflict@example.com", "password")
        .await;
    let token = registration["access_token"].as_str().expect("token");
    let vault = app
        .create_shared_vault(token, "shared-generation-conflict")
        .await;
    let vault_id = Uuid::parse_str(vault["id"].as_str().expect("vault id")).expect("vault uuid");

    let item_id = Uuid::now_v7();
    let (status, item) = app
        .send_json(
            Method::POST,
            "/v1/sync/shared/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Create.as_i32(),
                    "path": "collision-item",
                    "name": "collision-item",
                    "type_id": "login",
                    "payload": login_payload("before"),
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "create item: {item:?}");
    assert_eq!(item["applied"].as_array().map(Vec::len), Some(1));
    let base_seq = item["applied_changes"][0]["seq"]
        .as_i64()
        .expect("create sequence");
    let item_row = sqlx_core::query::query::<Postgres>("SELECT device_id FROM items WHERE id = $1")
        .bind(item_id)
        .fetch_one(&app.pool)
        .await
        .expect("item row");
    let device_id: Uuid = item_row.try_get("device_id").expect("device id");

    let mut corruption_tx = app.pool.begin().await.expect("begin corruption fixture");
    sqlx_core::query::query::<Postgres>(
        "ALTER TABLE changes DISABLE TRIGGER changes_10_validate_semantics",
    )
    .execute(&mut *corruption_tx)
    .await
    .expect("disable change validation trigger");
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
        VALUES ($1, $2, 3, 2, $3, $4)
        "#,
    )
    .bind(vault_id)
    .bind(item_id)
    .bind(device_id)
    .bind(Utc::now())
    .execute(&mut *corruption_tx)
    .await
    .expect("seed conflicting future generation");
    sqlx_core::query::query::<Postgres>(
        "ALTER TABLE changes ENABLE TRIGGER changes_10_validate_semantics",
    )
    .execute(&mut *corruption_tx)
    .await
    .expect("enable change validation trigger");
    corruption_tx
        .commit()
        .await
        .expect("commit corruption fixture");

    let (status, response) = app
        .send_json(
            Method::POST,
            "/v1/sync/shared/push",
            Some(token),
            json!({
                "vault_id": vault_id,
                "changes": [{
                    "item_id": item_id,
                    "operation": ChangeType::Update.as_i32(),
                    "base_seq": base_seq,
                    "payload": login_payload("after"),
                    "path": "collision-item",
                    "name": "collision-item",
                    "type_id": "login"
                }]
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "shared push: {response:?}");
    assert_eq!(response["applied"].as_array().map(Vec::len), Some(0));
    let conflicts = response["conflicts"].as_array().expect("conflicts");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0]["reason"], "generation_conflict");
    assert_eq!(cursor_seq(&response["new_cursor"]), 0);

    let version: i64 =
        sqlx_core::query::query::<Postgres>("SELECT version FROM items WHERE id = $1")
            .bind(item_id)
            .fetch_one(&app.pool)
            .await
            .expect("item after conflict")
            .try_get("version")
            .expect("version");
    assert_eq!(version, 1, "conflicting push transaction must roll back");
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn migration_normalizes_legacy_secret_paths_as_a_new_current_generation() {
    let pool = setup_legacy_schema().await;
    let now = Utc::now();
    let device_id = Uuid::now_v7();
    let vault_id = Uuid::now_v7();
    let item_id = Uuid::now_v7();
    seed_legacy_device_and_vault(&pool, device_id, vault_id, "legacy-secret-normalize", now).await;
    insert_legacy_item(&pool, vault_id, device_id, item_id, 1, false, now).await;
    sqlx_core::query::query::<Postgres>(
        "UPDATE items SET path = '/folder/secret', name = 'secret', type_id = 'secret' WHERE id = $1",
    )
    .bind(item_id)
    .execute(&pool)
    .await
    .expect("seed slash-prefixed legacy secret");
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (seq, vault_id, item_id, op, version, device_id, created_at)
        VALUES (17, $1, $2, 1, 1, $3, $4)
        "#,
    )
    .bind(vault_id)
    .bind(item_id)
    .bind(device_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("seed legacy secret generation");

    let mut migration_tx = pool.begin().await.expect("begin migration");
    raw_sql(include_str!(
        "../migrations/0002_changes_current_generation.sql"
    ))
    .execute(&mut *migration_tx)
    .await
    .expect("normalize legacy secret path");
    migration_tx.commit().await.expect("commit migration");

    let item = sqlx_core::query::query::<Postgres>(
        "SELECT path, name, version, row_version FROM items WHERE id = $1",
    )
    .bind(item_id)
    .fetch_one(&pool)
    .await
    .expect("normalized item");
    assert_eq!(
        item.try_get::<String, _>("path").expect("path"),
        "folder/secret"
    );
    assert_eq!(item.try_get::<String, _>("name").expect("name"), "secret");
    assert_eq!(item.try_get::<i64, _>("version").expect("version"), 2);
    assert_eq!(
        item.try_get::<i64, _>("row_version").expect("row version"),
        2
    );

    let current = sqlx_core::query::query::<Postgres>(
        "SELECT seq, op FROM changes WHERE item_id = $1 AND version = 2",
    )
    .bind(item_id)
    .fetch_one(&pool)
    .await
    .expect("normalization generation");
    assert!(current.try_get::<i64, _>("seq").expect("seq") > 17);
    assert_eq!(
        current.try_get::<i16, _>("op").expect("op"),
        ChangeOp::Update.as_i32() as i16
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn migration_rejects_a_legacy_secret_path_normalization_collision() {
    let pool = setup_legacy_schema().await;
    let now = Utc::now();
    let device_id = Uuid::now_v7();
    let vault_id = Uuid::now_v7();
    let secret_id = Uuid::now_v7();
    let existing_id = Uuid::now_v7();
    seed_legacy_device_and_vault(&pool, device_id, vault_id, "legacy-secret-collision", now).await;
    insert_legacy_item(&pool, vault_id, device_id, secret_id, 1, false, now).await;
    insert_legacy_item(
        &pool,
        vault_id,
        device_id,
        existing_id,
        1,
        true,
        now + ChronoDuration::microseconds(1),
    )
    .await;
    sqlx_core::query::query::<Postgres>(
        "UPDATE items SET path = '/collision', name = 'collision', type_id = 'secret' WHERE id = $1",
    )
    .bind(secret_id)
    .execute(&pool)
    .await
    .expect("seed slash-prefixed secret");
    sqlx_core::query::query::<Postgres>(
        "UPDATE items SET path = 'collision', name = 'collision' WHERE id = $1",
    )
    .bind(existing_id)
    .execute(&pool)
    .await
    .expect("seed tombstoned colliding item");

    let mut migration_tx = pool.begin().await.expect("begin migration");
    let error = raw_sql(include_str!(
        "../migrations/0002_changes_current_generation.sql"
    ))
    .execute(&mut *migration_tx)
    .await
    .expect_err("normalization collision must fail closed");
    migration_tx.rollback().await.expect("rollback migration");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("items_secret_path_normalization_collision")
    );
    let secret =
        sqlx_core::query::query::<Postgres>("SELECT path, version FROM items WHERE id = $1")
            .bind(secret_id)
            .fetch_one(&pool)
            .await
            .expect("legacy secret after rollback");
    assert_eq!(
        secret.try_get::<String, _>("path").expect("path"),
        "/collision"
    );
    assert_eq!(secret.try_get::<i64, _>("version").expect("version"), 1);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn migration_backfills_current_generations_and_future_version_writes() {
    let pool = setup_legacy_schema().await;
    let now = Utc::now();
    let device_id = Uuid::now_v7();
    let vault_id = Uuid::now_v7();

    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO devices (id, user_id, name, fingerprint, created_at)
        VALUES ($1, '00000000-0000-0000-0000-000000000000', 'legacy', 'legacy', $2)
        "#,
    )
    .bind(device_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert legacy device");
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO vaults (
            id, slug, name, kind, encryption_type, vault_key_enc, cache_policy, created_at
        )
        VALUES ($1, 'legacy-shared', 'Legacy Shared', 2, 2, $2, 1, $3)
        "#,
    )
    .bind(vault_id)
    .bind(vec![1_u8, 2, 3])
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert legacy vault");

    let create_item_id = Uuid::now_v7();
    let update_item_id = Uuid::now_v7();
    let delete_item_id = Uuid::now_v7();
    let duplicate_item_id = Uuid::now_v7();
    insert_legacy_item(&pool, vault_id, device_id, create_item_id, 1, false, now).await;
    insert_legacy_item(
        &pool,
        vault_id,
        device_id,
        update_item_id,
        7,
        false,
        now + ChronoDuration::seconds(1),
    )
    .await;
    insert_legacy_item(
        &pool,
        vault_id,
        device_id,
        delete_item_id,
        3,
        true,
        now + ChronoDuration::seconds(2),
    )
    .await;
    let duplicate_updated_at = now + ChronoDuration::seconds(3);
    insert_legacy_item(
        &pool,
        vault_id,
        device_id,
        duplicate_item_id,
        4,
        false,
        duplicate_updated_at,
    )
    .await;

    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (seq, vault_id, item_id, op, version, device_id, created_at)
        VALUES
            (41, $1, $2, 2, 4, $3, $4),
            (100, $1, $2, 2, 4, $3, $4)
        "#,
    )
    .bind(vault_id)
    .bind(duplicate_item_id)
    .bind(device_id)
    .bind(duplicate_updated_at)
    .execute(&pool)
    .await
    .expect("insert duplicate legacy generations");

    let mut migration_tx = pool.begin().await.expect("begin migration");
    raw_sql(include_str!(
        "../migrations/0002_changes_current_generation.sql"
    ))
    .execute(&mut *migration_tx)
    .await
    .expect("apply current-generation migration");
    migration_tx.commit().await.expect("commit migration");

    let rows = sqlx_core::query::query::<Postgres>(
        r#"
        SELECT seq, item_id, op, version
        FROM changes
        WHERE vault_id = $1
        ORDER BY seq ASC
        "#,
    )
    .bind(vault_id)
    .fetch_all(&pool)
    .await
    .expect("read migrated changes");
    assert_eq!(rows.len(), 4, "one row per current item generation");

    let mut generations = HashMap::new();
    let mut sequences = HashSet::new();
    for row in rows {
        let seq: i64 = row.try_get("seq").expect("seq");
        let item_id: Uuid = row.try_get("item_id").expect("item id");
        let op: i16 = row.try_get("op").expect("op");
        let version: i64 = row.try_get("version").expect("version");
        assert!(sequences.insert(seq), "sequence {seq} must be distinct");
        generations.insert(item_id, (seq, op, version));
    }

    assert_generation(&generations, create_item_id, 1, ChangeOp::Create);
    assert_generation(&generations, update_item_id, 7, ChangeOp::Update);
    assert_generation(&generations, delete_item_id, 3, ChangeOp::Delete);
    assert_eq!(
        generations.get(&duplicate_item_id),
        Some(&(41, ChangeOp::Update.as_i32() as i16, 4)),
        "deduplication keeps the first issued sequence"
    );
    assert!(
        generations
            .iter()
            .filter(|(item_id, _)| **item_id != duplicate_item_id)
            .all(|(_, (seq, _, _))| *seq > 100),
        "backfill must not reuse a previously issued cursor"
    );

    let next_updated_at = now + ChronoDuration::minutes(1);
    sqlx_core::query::query::<Postgres>(
        r#"
        UPDATE items
        SET version = version + 1,
            row_version = row_version + 1,
            updated_at = $2
        WHERE id = $1
        "#,
    )
    .bind(update_item_id)
    .bind(next_updated_at)
    .execute(&pool)
    .await
    .expect("advance item without an application change insert");

    let triggered = sqlx_core::query::query::<Postgres>(
        r#"
        SELECT seq, op, version
        FROM changes
        WHERE item_id = $1 AND version = 8
        "#,
    )
    .bind(update_item_id)
    .fetch_one(&pool)
    .await
    .expect("deferred trigger change");
    let triggered_seq: i64 = triggered.try_get("seq").expect("triggered seq");
    let triggered_op: i16 = triggered.try_get("op").expect("triggered op");
    assert!(
        triggered_seq > 100,
        "removed high-water sequence was reused"
    );
    assert!(triggered_seq > *sequences.iter().max().expect("migrated seq"));
    assert_eq!(triggered_op, ChangeOp::Update.as_i32() as i16);

    let clock_before_retry = change_clock(&pool).await;
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
        VALUES ($1, $2, 2, 7, $3, $4)
        ON CONFLICT (item_id, version) DO NOTHING
        "#,
    )
    .bind(vault_id)
    .bind(update_item_id)
    .bind(device_id)
    .bind(now + ChronoDuration::seconds(1))
    .execute(&pool)
    .await
    .expect("raw exact historical retry is idempotent");
    assert_eq!(
        change_clock(&pool).await,
        clock_before_retry,
        "an exact historical retry must not allocate a sequence"
    );
    let repo = ChangeRepo::new(&pool);
    repo.create(&Change {
        seq: 0,
        vault_id,
        item_id: update_item_id,
        op: ChangeOp::Update,
        version: 8,
        device_id,
        created_at: next_updated_at,
    })
    .await
    .expect("explicit application insert is idempotent");
    assert_eq!(
        change_clock(&pool).await,
        clock_before_retry,
        "an exact repository retry must not allocate a sequence"
    );
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
        VALUES ($1, $2, 2, 8, $3, $4)
        ON CONFLICT (item_id, version) DO NOTHING
        "#,
    )
    .bind(vault_id)
    .bind(update_item_id)
    .bind(device_id)
    .bind(next_updated_at)
    .execute(&pool)
    .await
    .expect("raw exact retry is idempotent");
    assert_eq!(
        change_clock(&pool).await,
        clock_before_retry,
        "an exact SQL retry must not allocate a sequence"
    );
    let generated_row = sqlx_core::query::query::<Postgres>(
        "SELECT COUNT(*) AS count, MIN(seq) AS seq FROM changes WHERE item_id = $1 AND version = 8",
    )
    .bind(update_item_id)
    .fetch_one(&pool)
    .await
    .expect("read generated change");
    let generation_count: i64 = generated_row.try_get("count").expect("count");
    assert_eq!(generation_count, 1);
    let idempotent_seq: Option<i64> = generated_row.try_get("seq").expect("idempotent seq");
    assert_eq!(idempotent_seq, Some(triggered_seq));

    let conflicting_repo_error = repo
        .create(&Change {
            seq: 0,
            vault_id,
            item_id: update_item_id,
            op: ChangeOp::Delete,
            version: 8,
            device_id,
            created_at: next_updated_at,
        })
        .await
        .expect_err("conflicting repository retry must fail");
    assert!(
        conflicting_repo_error
            .to_string()
            .contains("conflicting change generation semantics"),
        "unexpected repository error: {conflicting_repo_error}"
    );

    let second_vault_id = Uuid::now_v7();
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO vaults (
            id, slug, name, kind, encryption_type, vault_key_enc, cache_policy, created_at
        )
        VALUES ($1, 'legacy-shared-second', 'Legacy Shared Second', 2, 2, $2, 1, $3)
        "#,
    )
    .bind(second_vault_id)
    .bind(vec![4_u8, 5, 6])
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert second vault");

    let wrong_vault_error = sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
        VALUES ($1, $2, 2, 2, $3, $4)
        "#,
    )
    .bind(second_vault_id)
    .bind(create_item_id)
    .bind(device_id)
    .bind(now + ChronoDuration::minutes(2))
    .execute(&pool)
    .await
    .expect_err("cross-vault change must be rejected");
    assert_eq!(
        wrong_vault_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("changes_item_vault_matches")
    );

    let future_generation_error = sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
        VALUES ($1, $2, 2, 2, $3, $4)
        "#,
    )
    .bind(vault_id)
    .bind(create_item_id)
    .bind(device_id)
    .bind(now + ChronoDuration::minutes(2))
    .execute(&pool)
    .await
    .expect_err("non-current generation must be rejected");
    assert_eq!(
        future_generation_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("changes_current_generation_matches_item")
    );

    let immutable_change_error =
        sqlx_core::query::query::<Postgres>("UPDATE changes SET op = 3 WHERE item_id = $1")
            .bind(create_item_id)
            .execute(&pool)
            .await
            .expect_err("change semantics must be immutable");
    assert_eq!(
        immutable_change_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("changes_generation_immutable")
    );

    let direct_delete_error =
        sqlx_core::query::query::<Postgres>("DELETE FROM changes WHERE item_id = $1")
            .bind(create_item_id)
            .execute(&pool)
            .await
            .expect_err("direct change deletion must be rejected");
    assert_eq!(
        direct_delete_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("changes_generation_delete_forbidden")
    );

    let cascade_item_id = Uuid::now_v7();
    insert_legacy_item(
        &pool,
        vault_id,
        device_id,
        cascade_item_id,
        1,
        false,
        now + ChronoDuration::minutes(2),
    )
    .await;
    sqlx_core::query::query::<Postgres>("DELETE FROM items WHERE id = $1")
        .bind(cascade_item_id)
        .execute(&pool)
        .await
        .expect("parent cascade may delete its change");
    let cascaded_changes: i64 = sqlx_core::query::query::<Postgres>(
        "SELECT COUNT(*) AS count FROM changes WHERE item_id = $1",
    )
    .bind(cascade_item_id)
    .fetch_one(&pool)
    .await
    .expect("read cascaded changes")
    .try_get("count")
    .expect("count");
    assert_eq!(cascaded_changes, 0);

    let vault_move_error =
        sqlx_core::query::query::<Postgres>("UPDATE items SET vault_id = $2 WHERE id = $1")
            .bind(create_item_id)
            .bind(second_vault_id)
            .execute(&pool)
            .await
            .expect_err("vault move must be rejected");
    assert_eq!(
        vault_move_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("items_vault_immutable")
    );

    let type_change_error = sqlx_core::query::query::<Postgres>(
        r#"
        UPDATE items
        SET type_id = 'note',
            version = version + 1,
            row_version = row_version + 1,
            updated_at = $2
        WHERE id = $1
        "#,
    )
    .bind(create_item_id)
    .bind(now + ChronoDuration::minutes(2))
    .execute(&pool)
    .await
    .expect_err("type changes must be rejected even with a version advance");
    assert_eq!(
        type_change_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("items_type_immutable")
    );

    let deletion_error = sqlx_core::query::query::<Postgres>(
        r#"
        UPDATE items
        SET sync_status = 2,
            deleted_at = $2,
            deleted_by_user_id = '00000000-0000-0000-0000-000000000000',
            deleted_by_device_id = $3,
            updated_at = $2
        WHERE id = $1
        "#,
    )
    .bind(create_item_id)
    .bind(now + ChronoDuration::minutes(2))
    .bind(device_id)
    .execute(&pool)
    .await
    .expect_err("deletion without a version advance must be rejected");
    assert_eq!(
        deletion_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("items_deletion_requires_version")
    );

    let rotation_result = sqlx_core::query::query::<Postgres>(
        r#"
        UPDATE items
        SET rotation_state = 'rotating',
            rotation_started_at = $2
        WHERE id = $1
        "#,
    )
    .bind(create_item_id)
    .bind(now + ChronoDuration::minutes(2))
    .execute(&pool)
    .await
    .expect("rotation metadata may change without a semantic version");
    assert_eq!(rotation_result.rows_affected(), 1);

    let sync_field_error = sqlx_core::query::query::<Postgres>(
        r#"
        UPDATE items
        SET path = 'mutated-without-version',
            name = 'mutated-without-version',
            payload_enc = $2,
            checksum = $4,
            updated_at = $3
        WHERE id = $1
        "#,
    )
    .bind(create_item_id)
    .bind(vec![9_u8, 9, 9])
    .bind(now + ChronoDuration::minutes(3))
    .bind(core_crypto::payload_checksum(&[9_u8, 9, 9]))
    .execute(&pool)
    .await
    .expect_err("sync-visible fields require a version advance");
    assert_eq!(
        sync_field_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("items_sync_fields_require_version")
    );

    let conflicting_updated_at = now + ChronoDuration::minutes(3);
    let mut conflicting_tx = pool.begin().await.expect("begin conflicting generation");
    sqlx_core::query::query::<Postgres>(
        r#"
        UPDATE items
        SET version = 9,
            row_version = row_version + 1,
            updated_at = $2
        WHERE id = $1
        "#,
    )
    .bind(update_item_id)
    .bind(conflicting_updated_at)
    .execute(&mut *conflicting_tx)
    .await
    .expect("stage item version");
    sqlx_core::query::query::<Postgres>(
        "ALTER TABLE changes DISABLE TRIGGER changes_10_validate_semantics",
    )
    .execute(&mut *conflicting_tx)
    .await
    .expect("disable change validation trigger");
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
        VALUES ($1, $2, 3, 9, $3, $4)
        "#,
    )
    .bind(vault_id)
    .bind(update_item_id)
    .bind(device_id)
    .bind(conflicting_updated_at)
    .execute(&mut *conflicting_tx)
    .await
    .expect("stage conflicting generation");
    sqlx_core::query::query::<Postgres>(
        "ALTER TABLE changes ENABLE TRIGGER changes_10_validate_semantics",
    )
    .execute(&mut *conflicting_tx)
    .await
    .expect("enable change validation trigger");
    let conflict_error = conflicting_tx
        .commit()
        .await
        .expect_err("trigger must reject conflicting generation semantics");
    assert_eq!(
        conflict_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("changes_current_generation_matches_item")
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn change_clock_serializes_commits_and_reuses_only_rolled_back_sequences() {
    let pool = setup_legacy_schema().await;
    let now = Utc::now();
    let device_id = Uuid::now_v7();
    let vault_id = Uuid::now_v7();
    let first_item_id = Uuid::now_v7();
    let second_item_id = Uuid::now_v7();

    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO devices (id, user_id, name, fingerprint, created_at)
        VALUES ($1, '00000000-0000-0000-0000-000000000000', 'clock', 'clock', $2)
        "#,
    )
    .bind(device_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert clock device");
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO vaults (
            id, slug, name, kind, encryption_type, vault_key_enc, cache_policy, created_at
        )
        VALUES ($1, 'clock-shared', 'Clock Shared', 2, 2, $2, 1, $3)
        "#,
    )
    .bind(vault_id)
    .bind(vec![1_u8, 2, 3])
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert clock vault");
    insert_legacy_item(&pool, vault_id, device_id, first_item_id, 1, false, now).await;
    insert_legacy_item(
        &pool,
        vault_id,
        device_id,
        second_item_id,
        1,
        false,
        now + ChronoDuration::milliseconds(1),
    )
    .await;

    let mut migration_tx = pool.begin().await.expect("begin clock migration");
    raw_sql(include_str!(
        "../migrations/0002_changes_current_generation.sql"
    ))
    .execute(&mut *migration_tx)
    .await
    .expect("apply clock migration");
    migration_tx.commit().await.expect("commit clock migration");
    let initial_clock = change_clock(&pool).await;

    let first_updated_at = now + ChronoDuration::minutes(1);
    let mut transaction_a = pool.begin().await.expect("begin transaction A");
    sqlx_core::query::query::<Postgres>(
        r#"
        UPDATE items
        SET version = 2, row_version = row_version + 1, updated_at = $2
        WHERE id = $1
        "#,
    )
    .bind(first_item_id)
    .bind(first_updated_at)
    .execute(&mut *transaction_a)
    .await
    .expect("stage transaction A item");
    let sequence_a: i64 = sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
        VALUES ($1, $2, 2, 2, $3, $4)
        RETURNING seq
        "#,
    )
    .bind(vault_id)
    .bind(first_item_id)
    .bind(device_id)
    .bind(first_updated_at)
    .fetch_one(&mut *transaction_a)
    .await
    .expect("allocate transaction A sequence")
    .try_get("seq")
    .expect("transaction A sequence");
    assert_eq!(sequence_a, initial_clock + 1);

    let pool_for_b = pool.clone();
    let second_updated_at = now + ChronoDuration::minutes(2);
    let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
    let mut transaction_b = tokio::spawn(async move {
        let mut tx = pool_for_b.begin().await.expect("begin transaction B");
        sqlx_core::query::query::<Postgres>(
            r#"
            UPDATE items
            SET version = 2, row_version = row_version + 1, updated_at = $2
            WHERE id = $1
            "#,
        )
        .bind(second_item_id)
        .bind(second_updated_at)
        .execute(&mut *tx)
        .await
        .expect("stage transaction B item");
        started_sender.send(()).expect("signal transaction B");
        let sequence: i64 = sqlx_core::query::query::<Postgres>(
            r#"
            INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
            VALUES ($1, $2, 2, 2, $3, $4)
            RETURNING seq
            "#,
        )
        .bind(vault_id)
        .bind(second_item_id)
        .bind(device_id)
        .bind(second_updated_at)
        .fetch_one(&mut *tx)
        .await
        .expect("allocate transaction B sequence")
        .try_get("seq")
        .expect("transaction B sequence");
        tx.commit().await.expect("commit transaction B");
        sequence
    });
    started_receiver.await.expect("transaction B started");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut transaction_b)
            .await
            .is_err(),
        "a higher sequence must wait for the lower transaction to finish"
    );

    let visible_max: i64 =
        sqlx_core::query::query::<Postgres>("SELECT COALESCE(MAX(seq), 0) AS seq FROM changes")
            .fetch_one(&pool)
            .await
            .expect("read visible sequence while transaction A is pending")
            .try_get("seq")
            .expect("visible sequence");
    assert_eq!(visible_max, initial_clock);

    transaction_a.commit().await.expect("commit transaction A");
    let sequence_b = transaction_b.await.expect("join transaction B");
    assert_eq!(sequence_b, sequence_a + 1);

    let rolled_back_updated_at = now + ChronoDuration::minutes(3);
    let mut rolled_back_tx = pool.begin().await.expect("begin rolled-back transaction");
    sqlx_core::query::query::<Postgres>(
        r#"
        UPDATE items
        SET version = 3, row_version = row_version + 1, updated_at = $2
        WHERE id = $1
        "#,
    )
    .bind(first_item_id)
    .bind(rolled_back_updated_at)
    .execute(&mut *rolled_back_tx)
    .await
    .expect("stage rolled-back item");
    let rolled_back_sequence: i64 = sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
        VALUES ($1, $2, 2, 3, $3, $4)
        RETURNING seq
        "#,
    )
    .bind(vault_id)
    .bind(first_item_id)
    .bind(device_id)
    .bind(rolled_back_updated_at)
    .fetch_one(&mut *rolled_back_tx)
    .await
    .expect("allocate rolled-back sequence")
    .try_get("seq")
    .expect("rolled-back sequence");
    rolled_back_tx
        .rollback()
        .await
        .expect("roll back allocated sequence");
    assert_eq!(change_clock(&pool).await, sequence_b);

    let mut retry_tx = pool.begin().await.expect("begin retry transaction");
    sqlx_core::query::query::<Postgres>(
        r#"
        UPDATE items
        SET version = 3, row_version = row_version + 1, updated_at = $2
        WHERE id = $1
        "#,
    )
    .bind(first_item_id)
    .bind(rolled_back_updated_at)
    .execute(&mut *retry_tx)
    .await
    .expect("stage retry item");
    let retry_sequence: i64 = sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
        VALUES ($1, $2, 2, 3, $3, $4)
        RETURNING seq
        "#,
    )
    .bind(vault_id)
    .bind(first_item_id)
    .bind(device_id)
    .bind(rolled_back_updated_at)
    .fetch_one(&mut *retry_tx)
    .await
    .expect("allocate retry sequence")
    .try_get("seq")
    .expect("retry sequence");
    retry_tx.commit().await.expect("commit retry transaction");
    assert_eq!(retry_sequence, rolled_back_sequence);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn migration_contract_preflight_is_deterministic_and_non_mutating() {
    let pool = setup_legacy_schema().await;
    let now = Utc::now();
    let device_id = Uuid::now_v7();
    let vault_id = Uuid::now_v7();
    let item_id = Uuid::now_v7();

    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO devices (id, user_id, name, fingerprint, created_at)
        VALUES ($1, '00000000-0000-0000-0000-000000000000', 'legacy', 'legacy', $2)
        "#,
    )
    .bind(device_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert legacy device");
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO vaults (
            id, slug, name, kind, encryption_type, vault_key_enc, cache_policy, created_at
        )
        VALUES ($1, 'legacy-dirty-contract', 'Legacy Dirty Contract', 2, 2, $2, 1, $3)
        "#,
    )
    .bind(vault_id)
    .bind(vec![1_u8, 2, 3])
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert legacy vault");
    insert_legacy_item(&pool, vault_id, device_id, item_id, 1, false, now).await;

    // An explicit legacy sequence does not advance BIGSERIAL. It makes any
    // premature setval observable even though the migration later rolls back.
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (seq, vault_id, item_id, op, version, device_id, created_at)
        VALUES (500, $1, $2, 1, 1, $3, $4)
        "#,
    )
    .bind(vault_id)
    .bind(item_id)
    .bind(device_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert explicit legacy change");
    let sequence_before = legacy_change_sequence_state(&pool).await;

    sqlx_core::query::query::<Postgres>(
        r#"
        UPDATE items
        SET path = ' folder/item',
            name = 'wrong',
            type_id = ' login',
            payload_enc = $2,
            checksum = $3
        WHERE id = $1
        "#,
    )
    .bind(item_id)
    .bind(Vec::<u8>::new())
    .bind("A".repeat(64))
    .execute(&pool)
    .await
    .expect("seed dirty legacy item");
    sqlx_core::query::query::<Postgres>("UPDATE vaults SET vault_key_enc = $2 WHERE id = $1")
        .bind(vault_id)
        .bind(Vec::<u8>::new())
        .execute(&pool)
        .await
        .expect("seed dirty legacy vault");

    assert_eq!(
        rejected_migration_constraint(&pool).await,
        "items_path_canonical"
    );
    sqlx_core::query::query::<Postgres>("UPDATE items SET path = 'folder/item' WHERE id = $1")
        .bind(item_id)
        .execute(&pool)
        .await
        .expect("repair legacy path");

    assert_eq!(
        rejected_migration_constraint(&pool).await,
        "items_name_matches_path"
    );
    sqlx_core::query::query::<Postgres>("UPDATE items SET name = 'item' WHERE id = $1")
        .bind(item_id)
        .execute(&pool)
        .await
        .expect("repair legacy name");

    assert_eq!(
        rejected_migration_constraint(&pool).await,
        "items_type_id_canonical"
    );
    sqlx_core::query::query::<Postgres>("UPDATE items SET type_id = 'login' WHERE id = $1")
        .bind(item_id)
        .execute(&pool)
        .await
        .expect("repair legacy type");

    assert_eq!(
        rejected_migration_constraint(&pool).await,
        "items_payload_bounds"
    );
    let payload = vec![1_u8, 1, 2];
    sqlx_core::query::query::<Postgres>("UPDATE items SET payload_enc = $2 WHERE id = $1")
        .bind(item_id)
        .bind(&payload)
        .execute(&pool)
        .await
        .expect("repair legacy payload");

    assert_eq!(
        rejected_migration_constraint(&pool).await,
        "items_checksum_format"
    );
    sqlx_core::query::query::<Postgres>("UPDATE items SET checksum = $2 WHERE id = $1")
        .bind(item_id)
        .bind(core_crypto::payload_checksum(&payload))
        .execute(&pool)
        .await
        .expect("repair legacy checksum");

    assert_eq!(
        rejected_migration_constraint(&pool).await,
        "vaults_key_bounds"
    );
    assert_eq!(
        legacy_change_sequence_state(&pool).await,
        sequence_before,
        "failed preflights must not advance the non-transactional sequence"
    );

    sqlx_core::query::query::<Postgres>("UPDATE vaults SET vault_key_enc = $2 WHERE id = $1")
        .bind(vault_id)
        .bind(vec![1_u8, 2, 3])
        .execute(&pool)
        .await
        .expect("repair legacy vault key");

    let mut migration_tx = pool.begin().await.expect("begin repaired migration");
    raw_sql(include_str!(
        "../migrations/0002_changes_current_generation.sql"
    ))
    .execute(&mut *migration_tx)
    .await
    .expect("apply migration after deterministic remediation");
    migration_tx
        .commit()
        .await
        .expect("commit repaired migration");

    let error =
        sqlx_core::query::query::<Postgres>("UPDATE items SET path = 'folder//item' WHERE id = $1")
            .bind(item_id)
            .execute(&pool)
            .await
            .expect_err("installed canonical path constraint must reject dirty writes");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("items_path_canonical")
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn migration_rejects_disagreeing_duplicate_generations() {
    let pool = setup_legacy_schema().await;
    let now = Utc::now();
    let device_id = Uuid::now_v7();
    let vault_id = Uuid::now_v7();
    let item_id = Uuid::now_v7();

    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO devices (id, user_id, name, fingerprint, created_at)
        VALUES ($1, '00000000-0000-0000-0000-000000000000', 'legacy', 'legacy', $2)
        "#,
    )
    .bind(device_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert legacy device");
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO vaults (
            id, slug, name, kind, encryption_type, vault_key_enc, cache_policy, created_at
        )
        VALUES ($1, 'legacy-conflict', 'Legacy Conflict', 2, 2, $2, 1, $3)
        "#,
    )
    .bind(vault_id)
    .bind(vec![1_u8, 2, 3])
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert legacy vault");
    insert_legacy_item(&pool, vault_id, device_id, item_id, 4, false, now).await;
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (seq, vault_id, item_id, op, version, device_id, created_at)
        VALUES
            (11, $1, $2, 2, 4, $3, $4),
            (12, $1, $2, 3, 4, $3, $4)
        "#,
    )
    .bind(vault_id)
    .bind(item_id)
    .bind(device_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert disagreeing generations");

    let mut migration_tx = pool.begin().await.expect("begin migration");
    let error = raw_sql(include_str!(
        "../migrations/0002_changes_current_generation.sql"
    ))
    .execute(&mut *migration_tx)
    .await
    .expect_err("migration must reject ambiguous duplicate semantics");
    migration_tx
        .rollback()
        .await
        .expect("roll back rejected migration");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("changes_generation_semantics")
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn migration_rejects_logically_oversized_compressible_tags() {
    let pool = setup_legacy_schema().await;
    let now = Utc::now();
    let device_id = Uuid::now_v7();
    let vault_id = Uuid::now_v7();
    seed_legacy_device_and_vault(&pool, device_id, vault_id, "large-tags", now).await;

    // A repeated string compresses well enough that pg_column_size can remain
    // small while the logical JSON representation is far beyond the wire cap.
    sqlx_core::query::query::<Postgres>("UPDATE vaults SET tags = $2 WHERE id = $1")
        .bind(vault_id)
        .bind(json!(["x".repeat(70_000)]))
        .execute(&pool)
        .await
        .expect("seed compressible oversized tags");

    let mut migration_tx = pool.begin().await.expect("begin migration");
    let error = raw_sql(include_str!(
        "../migrations/0002_changes_current_generation.sql"
    ))
    .execute(&mut *migration_tx)
    .await
    .expect_err("migration must reject logically oversized tags");
    migration_tx
        .rollback()
        .await
        .expect("roll back rejected migration");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("vaults_tags_storage_bounds")
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn migration_rejects_oversized_legacy_attachments() {
    let pool = setup_legacy_schema().await;
    let now = Utc::now();
    let device_id = Uuid::now_v7();
    let vault_id = Uuid::now_v7();
    let item_id = Uuid::now_v7();
    seed_legacy_device_and_vault(&pool, device_id, vault_id, "large-attachment", now).await;
    insert_legacy_item(&pool, vault_id, device_id, item_id, 1, false, now).await;
    let content = vec![7_u8; 10 * 1024 * 1024 + 1025];
    let checksum = core_crypto::payload_checksum(&content);
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO attachments (
            id, item_id, filename, size, mime_type, enc_mode, content_enc,
            checksum, created_at
        )
        VALUES ($1, $2, 'large.bin', $3, 'application/octet-stream', 'opaque', $4, $5, $6)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(item_id)
    .bind(content.len() as i64)
    .bind(content)
    .bind(checksum)
    .bind(now)
    .execute(&pool)
    .await
    .expect("seed oversized attachment");

    let mut migration_tx = pool.begin().await.expect("begin migration");
    let error = raw_sql(include_str!(
        "../migrations/0002_changes_current_generation.sql"
    ))
    .execute(&mut *migration_tx)
    .await
    .expect_err("migration must reject oversized attachments");
    migration_tx
        .rollback()
        .await
        .expect("roll back rejected migration");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("attachments_bounded_contract")
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn migration_rejects_legacy_cross_vault_changes() {
    let pool = setup_legacy_schema().await;
    let now = Utc::now();
    let device_id = Uuid::now_v7();
    let item_vault_id = Uuid::now_v7();
    let change_vault_id = Uuid::now_v7();
    let item_id = Uuid::now_v7();

    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO devices (id, user_id, name, fingerprint, created_at)
        VALUES ($1, '00000000-0000-0000-0000-000000000000', 'legacy', 'legacy', $2)
        "#,
    )
    .bind(device_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert legacy device");
    for (vault_id, slug) in [
        (item_vault_id, "legacy-item-vault"),
        (change_vault_id, "legacy-change-vault"),
    ] {
        sqlx_core::query::query::<Postgres>(
            r#"
            INSERT INTO vaults (
                id, slug, name, kind, encryption_type, vault_key_enc, cache_policy, created_at
            )
            VALUES ($1, $2, $2, 2, 2, $3, 1, $4)
            "#,
        )
        .bind(vault_id)
        .bind(slug)
        .bind(vec![1_u8, 2, 3])
        .bind(now)
        .execute(&pool)
        .await
        .expect("insert legacy vault");
    }
    insert_legacy_item(&pool, item_vault_id, device_id, item_id, 1, false, now).await;
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
        VALUES ($1, $2, 1, 1, $3, $4)
        "#,
    )
    .bind(change_vault_id)
    .bind(item_id)
    .bind(device_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert legacy cross-vault change");

    let mut migration_tx = pool.begin().await.expect("begin migration");
    let error = raw_sql(include_str!(
        "../migrations/0002_changes_current_generation.sql"
    ))
    .execute(&mut *migration_tx)
    .await
    .expect_err("migration must reject cross-vault legacy changes");
    migration_tx
        .rollback()
        .await
        .expect("roll back rejected migration");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("changes_item_vault_matches")
    );
}

fn assert_generation(
    generations: &HashMap<Uuid, (i64, i16, i64)>,
    item_id: Uuid,
    version: i64,
    operation: ChangeOp,
) {
    let (_, actual_op, actual_version) = generations.get(&item_id).expect("item generation");
    assert_eq!(*actual_version, version);
    assert_eq!(*actual_op, operation.as_i32() as i16);
}

async fn change_clock(pool: &PgPool) -> i64 {
    sqlx_core::query::query::<Postgres>("SELECT last_seq FROM changes_commit_clock WHERE singleton")
        .fetch_one(pool)
        .await
        .expect("read change commit clock")
        .try_get("last_seq")
        .expect("last seq")
}

async fn legacy_change_sequence_state(pool: &PgPool) -> (i64, bool) {
    let row =
        sqlx_core::query::query::<Postgres>("SELECT last_value, is_called FROM changes_seq_seq")
            .fetch_one(pool)
            .await
            .expect("read legacy change sequence");
    (
        row.try_get("last_value").expect("last sequence value"),
        row.try_get("is_called").expect("sequence called state"),
    )
}

async fn rejected_migration_constraint(pool: &PgPool) -> String {
    let mut migration_tx = pool.begin().await.expect("begin rejected migration");
    let error = raw_sql(include_str!(
        "../migrations/0002_changes_current_generation.sql"
    ))
    .execute(&mut *migration_tx)
    .await
    .expect_err("dirty legacy state must fail migration preflight");
    migration_tx
        .rollback()
        .await
        .expect("roll back rejected migration");
    error
        .as_database_error()
        .and_then(|error| error.constraint())
        .expect("migration error constraint")
        .to_string()
}

async fn assert_retype_authorization_rejected(
    pool: &PgPool,
    item_id: Uuid,
    authorized_item_id: Uuid,
    authorized_from: &str,
    authorized_to: &str,
) {
    let repo = ItemRepo::new(pool);
    let mut tx = pool.begin().await.expect("begin rejected retype");
    repo.authorize_type_retype_in(&mut tx, authorized_item_id, authorized_from, authorized_to)
        .await
        .expect("set mismatched retype authorization");
    update_item_type_for_trigger_test(&mut tx, item_id, "kv").await;
    let error = raw_sql("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await
        .expect_err("mismatched retype authorization must fail closed");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("items_type_immutable")
    );
    tx.rollback().await.expect("roll back rejected retype");
}

async fn update_item_type_for_trigger_test(
    tx: &mut sqlx_core::transaction::Transaction<'_, Postgres>,
    item_id: Uuid,
    type_id: &str,
) {
    sqlx_core::query::query::<Postgres>(
        r#"
        UPDATE items
        SET type_id = $2,
            version = version + 1,
            row_version = row_version + 1,
            updated_at = clock_timestamp()
        WHERE id = $1
        "#,
    )
    .bind(item_id)
    .bind(type_id)
    .execute(&mut **tx)
    .await
    .expect("stage item type update");
}

fn cursor_seq(value: &serde_json::Value) -> i64 {
    let encoded = value.as_str().expect("encoded cursor");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("base64 cursor");
    serde_json::from_slice::<serde_json::Value>(&bytes).expect("cursor json")["seq"]
        .as_i64()
        .expect("cursor seq")
}

async fn setup_legacy_schema() -> PgPool {
    let db_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set for Postgres tests");
    let schema = format!("zann_sync_snapshot_{}", Uuid::now_v7().simple());
    let admin_options =
        PgConnectOptions::from_str(&db_url).expect("failed to parse TEST_DATABASE_URL");
    let admin_pool = PoolOptions::new()
        .max_connections(1)
        .connect_with(admin_options.clone())
        .await
        .expect("connect admin pool");
    sqlx_core::query::query::<Postgres>(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&admin_pool)
        .await
        .expect("create legacy schema");

    let options = admin_options.options([("search_path", schema.as_str())]);
    let pool = PoolOptions::new()
        .max_connections(3)
        .connect_with(options)
        .await
        .expect("connect legacy pool");
    raw_sql(include_str!("../migrations/0001_init.sql"))
        .execute(&pool)
        .await
        .expect("apply legacy schema");
    pool
}

async fn seed_legacy_device_and_vault(
    pool: &PgPool,
    device_id: Uuid,
    vault_id: Uuid,
    slug: &str,
    created_at: DateTime<Utc>,
) {
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO devices (id, user_id, name, fingerprint, created_at)
        VALUES ($1, '00000000-0000-0000-0000-000000000000', 'legacy', $2, $3)
        "#,
    )
    .bind(device_id)
    .bind(format!("legacy-{device_id}"))
    .bind(created_at)
    .execute(pool)
    .await
    .expect("insert legacy device");
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO vaults (
            id, slug, name, kind, encryption_type, vault_key_enc, cache_policy, created_at
        )
        VALUES ($1, $2, $2, 2, 2, $3, 1, $4)
        "#,
    )
    .bind(vault_id)
    .bind(slug)
    .bind(vec![1_u8, 2, 3])
    .bind(created_at)
    .execute(pool)
    .await
    .expect("insert legacy vault");
}

#[allow(clippy::too_many_arguments)]
async fn insert_legacy_item(
    pool: &PgPool,
    vault_id: Uuid,
    device_id: Uuid,
    item_id: Uuid,
    version: i64,
    deleted: bool,
    updated_at: DateTime<Utc>,
) {
    let deleted_at = deleted.then_some(updated_at);
    let deleted_by_user_id = deleted.then_some(Uuid::from_u128(0));
    let deleted_by_device_id = deleted.then_some(device_id);
    let sync_status: i16 = if deleted { 2 } else { 1 };
    let payload = vec![version as u8, 1, 2];
    let checksum = core_crypto::payload_checksum(&payload);
    sqlx_core::query::query::<Postgres>(
        r#"
        INSERT INTO items (
            id, vault_id, path, name, type_id, favorite, payload_enc, checksum,
            version, device_id, sync_status, deleted_at, deleted_by_user_id,
            deleted_by_device_id, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $3, 'login', FALSE, $4, $5,
            $6, $7, $8, $9, $10, $11, $12, $12
        )
        "#,
    )
    .bind(item_id)
    .bind(vault_id)
    .bind(format!("legacy-{item_id}"))
    .bind(payload)
    .bind(checksum)
    .bind(version)
    .bind(device_id)
    .bind(sync_status)
    .bind(deleted_at)
    .bind(deleted_by_user_id)
    .bind(deleted_by_device_id)
    .bind(updated_at)
    .execute(pool)
    .await
    .expect("insert legacy item");
}
