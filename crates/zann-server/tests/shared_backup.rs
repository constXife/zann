mod client_workflow_support;
#[path = "shared_backup/guards.rs"]
mod guards;
mod support;

use axum::http::{Method, StatusCode};
use client_workflow_support::TestApp;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use uuid::Uuid;
use zann_db::repo::{ItemRepo, VaultRepo};
use zann_server::domains::backup::{self, ExportOptions, ImportOptions};

async fn fresh_database() -> zann_db::PgPool {
    use sqlx_core::pool::PoolOptions;
    use sqlx_postgres::{PgConnectOptions, Postgres};
    use std::str::FromStr;
    let options = PgConnectOptions::from_str(&std::env::var("TEST_DATABASE_URL").expect("test DB"))
        .expect("options");
    let admin = PoolOptions::<Postgres>::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .expect("admin");
    let schema = format!("backup_target_{}", Uuid::now_v7().simple());
    sqlx_core::query::query::<Postgres>(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&admin)
        .await
        .expect("fresh schema");
    let pool = PoolOptions::new()
        .max_connections(5)
        .connect_with(options.options([("search_path", schema.as_str())]))
        .await
        .expect("fresh database");
    zann_db::migrate(&pool)
        .await
        .expect("fresh schema migrations");
    pool
}

fn options(path: &std::path::Path) -> ExportOptions {
    ExportOptions {
        vaults: Vec::new(),
        all_shared: true,
        include_deleted: true,
        output: Some(path.into()),
        confirmed: true,
    }
}
fn comparable_items(value: &Value) -> Vec<Value> {
    let mut result = Vec::new();
    for vault in value["vaults"].as_array().expect("vaults") {
        for item in vault["items"].as_array().expect("items") {
            let mut item = item.clone();
            item.as_object_mut().expect("item").remove("checksum");
            item["vault_slug"] = vault["slug"].clone();
            result.push(item);
        }
    }
    result.sort_by_key(|v| v["id"].as_str().expect("id").to_string());
    result
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn streaming_backup_restores_more_than_120_items_with_new_smk_and_target_uuid() {
    let source = TestApp::new_with_smk().await;
    let user = source
        .register("backup-source@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");
    let vault = source.create_shared_vault(token, "backup-shared").await;
    let source_vault = vault["id"].as_str().expect("vault id").to_string();
    source.create_shared_vault(token, "empty-shared").await;
    let mut deleted_id = String::new();
    for i in 0..131 {
        let (status,item)=source.send_json(Method::POST,&format!("/v1/vaults/{source_vault}/items"),Some(token),json!({
            "path":format!("entries/item-{i:03}"),"type_id":"login","tags":["roundtrip","русский"],"favorite":i%2==0,
            "payload":{"v":1,"typeId":"login","fields":{
                "password":{"kind":"password","value":format!("fixture {i}\n café 🔐"),"meta":{"masked":true,"copyable":false}},
                "username":{"kind":"text","value":"fixture-user"}},"extra":{"origin":"backup"}}
        })).await;
        assert_eq!(status, StatusCode::CREATED);
        if i == 130 {
            deleted_id = item["id"].as_str().expect("id").to_string();
        }
    }
    let (status, _) = source
        .send_json(
            Method::DELETE,
            &format!("/v1/vaults/{source_vault}/items/{deleted_id}"),
            Some(token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = source
        .send_json(
            Method::PUT,
            &format!("/v1/vaults/{source_vault}/secrets/roundtrip/value"),
            Some(token),
            json!({"value":"fixture-secret"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let directory = tempfile::tempdir().expect("directory");
    let file = directory.path().join("export.json");
    backup::export(&source.pool, &source.master_key, &options(&file))
        .await
        .expect("stream export");
    assert_eq!(
        std::fs::metadata(&file)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let before: Value =
        serde_json::from_reader(std::fs::File::open(&file).expect("source")).expect("export JSON");
    assert_eq!(before["vaults"].as_array().expect("vaults").len(), 2); // personal vault omitted
    assert_eq!(comparable_items(&before).len(), 132);
    let old_key = source.master_key.clone();
    drop(source);

    let target = TestApp::new_with_database(fresh_database().await).await;
    let user = target
        .register("backup-target@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("target token");
    let target_vault = target.create_shared_vault(token, "backup-shared").await;
    let target_id = target_vault["id"].as_str().expect("target vault");
    assert_ne!(target_id, source_vault);
    let report = backup::import_file(
        &target.pool,
        &target.master_key,
        ImportOptions {
            input: file.clone(),
            owner_email: "backup-target@example.com".into(),
            confirmed: true,
        },
    )
    .await
    .expect("import under new SMK");
    assert_eq!((report.vaults, report.items), (2, 132));
    let second = directory.path().join("restored.json");
    backup::export(&target.pool, &target.master_key, &options(&second))
        .await
        .expect("re-export");
    let after: Value =
        serde_json::from_reader(std::fs::File::open(&second).expect("restored file"))
            .expect("restored JSON");
    assert_eq!(comparable_items(&before), comparable_items(&after));
    let wrapped = VaultRepo::new(&target.pool)
        .get_by_id(Uuid::parse_str(target_id).expect("UUID"))
        .await
        .expect("read")
        .expect("vault");
    assert!(zann_crypto::decrypt_vault_key(&old_key, wrapped.id, &wrapped.vault_key_enc).is_err());
    let restored = ItemRepo::new(&target.pool)
        .get_by_id(Uuid::parse_str(&deleted_id).expect("UUID"))
        .await
        .expect("read")
        .expect("item");
    assert!(restored.deleted_at.is_some());
    let (status, body) = target
        .send_json(
            Method::GET,
            &format!("/v1/vaults/{target_id}/secrets/roundtrip/value"),
            Some(token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"], "fixture-secret");
    let active = comparable_items(&after)
        .into_iter()
        .find(|v| v["type_id"] == "login" && v["deleted_at"].is_null())
        .expect("active item");
    let (status, body) = target
        .send_json(
            Method::GET,
            &format!("/v1/shared/items/{}", active["id"].as_str().expect("id")),
            Some(token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["payload"], active["payload"]);
    // Re-importing must refuse the occupied destination, never overwrite it.
    assert!(backup::import_file(
        &target.pool,
        &target.master_key,
        ImportOptions {
            input: file,
            owner_email: "backup-target@example.com".into(),
            confirmed: true
        }
    )
    .await
    .is_err());
}
