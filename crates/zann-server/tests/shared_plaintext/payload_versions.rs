use super::*;
use sqlx_core::query::query;
use sqlx_core::row::Row;
use sqlx_postgres::Postgres;
use uuid::Uuid;
use zann_db::repo::{ItemRepo, VaultRepo};

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn future_shared_payload_cannot_be_overwritten_through_any_item_write_surface() {
    let app = TestApp::new_with_smk().await;
    let user = app.register("future-payload@example.com", "password").await;
    let token = user["access_token"].as_str().expect("token");
    let vault = app.create_shared_vault(token, "future-payload").await;
    let vault_id = vault["id"].as_str().expect("vault id");
    let created = app.create_item(token, vault_id, "future", "fixture").await;
    let item_id = created["id"].as_str().expect("item id");
    app.update_item(token, vault_id, item_id, "future", "previous")
        .await;
    let id = Uuid::parse_str(item_id).expect("UUID");
    let vault = VaultRepo::new(&app.pool)
        .get_by_id(Uuid::parse_str(vault_id).expect("UUID"))
        .await
        .expect("vault read")
        .expect("vault");
    let key = zann_crypto::decrypt_vault_key(&app.master_key, vault.id, &vault.vault_key_enc)
        .expect("fixture key");
    let future = zann_crypto::encrypt_payload_bytes(
        &key,
        vault.id,
        id,
        br#"{"fields":{"x":{"kind":"future-kind"}},"v":2}"#,
    )
    .expect("future fixture");
    query::<Postgres>(
        "UPDATE items SET payload_enc=$1,checksum=$2,version=version+1,
         row_version=row_version+1,updated_at=updated_at+INTERVAL '1 microsecond' WHERE id=$3",
    )
    .bind(&future)
    .bind(zann_crypto::payload_checksum(&future))
    .bind(id)
    .execute(&app.pool)
    .await
    .expect("install future fixture");
    let snapshot = || async {
        let row = query::<Postgres>(
            "SELECT payload_enc,checksum,version,row_version,path,sync_status,
             (SELECT COUNT(*) FROM item_history WHERE item_id=$1) AS history_count,
             (SELECT COUNT(*) FROM changes WHERE item_id=$1) AS change_count,
             (SELECT MAX(seq) FROM changes WHERE item_id=$1) AS base_seq
             FROM items WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&app.pool)
        .await
        .expect("snapshot");
        (
            row.get::<Vec<u8>, _>("payload_enc"),
            row.get::<String, _>("checksum"),
            row.get::<i64, _>("version"),
            row.get::<i64, _>("row_version"),
            row.get::<String, _>("path"),
            row.get::<i16, _>("sync_status"),
            row.get::<i64, _>("history_count"),
            row.get::<i64, _>("change_count"),
            row.get::<i64, _>("base_seq"),
        )
    };
    let before = snapshot().await;
    let payload = json!({"v":1,"typeId":"login","fields":{
        "password":{"kind":"password","value":"replacement"}
    }});
    let ordinary = format!("/v1/vaults/{vault_id}/items/{item_id}");
    let shared = format!("/v1/shared/items/{item_id}");
    for (method, uri, body) in [
        (Method::PUT, ordinary.clone(), json!({"payload":payload})),
        (Method::DELETE, ordinary.clone(), json!({})),
        (Method::PUT, shared.clone(), json!({"payload":payload})),
        (Method::DELETE, shared, json!({})),
        (
            Method::POST,
            format!("{ordinary}/versions/1/restore"),
            json!({}),
        ),
        (
            Method::POST,
            "/v1/sync/push".into(),
            json!({
                "vault_id":vault_id,"changes":[{
                    "item_id":id,"operation":zann_core::ChangeType::Update.as_i32(),
                    "base_seq":before.8,"path":"future","name":"future","type_id":"login",
                    "tags":null,"favorite":false,"payload":payload
                }]
            }),
        ),
    ] {
        let (status, response) = app.send_json(method, &uri, Some(token), body).await;
        assert_eq!(status, StatusCode::CONFLICT, "{uri}: {response:?}");
        assert_eq!(response["error"], "unsupported_payload_version", "{uri}");
        assert_eq!(snapshot().await, before, "mutation escaped refusal: {uri}");
    }
    let item = ItemRepo::new(&app.pool)
        .get_by_id(id)
        .await
        .expect("read")
        .expect("item");
    assert!(item.deleted_at.is_none());
}
