use super::*;
use sqlx_core::row::Row;
use sqlx_postgres::Postgres;
use std::io::Write;

async fn counts(pool: &zann_db::PgPool) -> [i64; 6] {
    let row=sqlx_core::query::query::<Postgres>("SELECT
        (SELECT COUNT(*) FROM vaults) AS vaults,(SELECT COUNT(*) FROM items) AS items,
        (SELECT COUNT(*) FROM devices) AS devices,(SELECT COUNT(*) FROM vault_members) AS members,
        (SELECT COUNT(*) FROM changes) AS changes,(SELECT last_seq FROM changes_commit_clock) AS clock")
        .fetch_one(pool).await.expect("counts");
    ["vaults", "items", "devices", "members", "changes", "clock"].map(|key| row.get(key))
}

fn record(id: Uuid, path: &str) -> Value {
    json!({"id":id.to_string(),"path":path,"name":path,"type_id":"login","tags":null,"favorite":false,
        "payload":{"v":1,"typeId":"login","fields":{"password":{"kind":"password","value":"synthetic-private-sentinel"}}},
        "checksum":"a".repeat(64),"version":1,"deleted_at":null,"updated_at":"2026-11-14T00:00:00Z"})
}
fn document(items: Vec<Value>) -> Value {
    json!({"version":1,"scope":"shared","plaintext":true,"exported_at":"2026-11-14T00:00:00Z","vaults":[{
        "id":Uuid::now_v7().to_string(),"slug":"new-import-target","name":"New import target","item_count":items.len(),"items":items
    }]})
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn late_conflict_and_invalid_input_leave_every_publication_row_unchanged() {
    let app = TestApp::new_with_database(fresh_database().await).await;
    let owner = "backup-rollback@example.com";
    let user = app.register(owner, "password").await;
    let token = user["access_token"].as_str().expect("token");
    let vault = app.create_shared_vault(token, "occupied").await;
    let (status, created) = app
        .send_json(
            Method::POST,
            &format!("/v1/vaults/{}/items", vault["id"].as_str().expect("vault")),
            Some(token),
            json!({
                "path":"occupied","type_id":"login","payload":{"v":1,"typeId":"login","fields":{}}
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let collision = Uuid::parse_str(created["id"].as_str().expect("id")).expect("UUID");
    let value = document(vec![
        record(Uuid::now_v7(), "first"),
        record(collision, "second"),
    ]);
    let before = counts(&app.pool).await;
    let mut file = tempfile::NamedTempFile::new().expect("private file");
    file.write_all(value.to_string().as_bytes()).expect("write");
    let result = backup::import_file(
        &app.pool,
        &app.master_key,
        ImportOptions {
            input: file.path().into(),
            owner_email: owner.into(),
            confirmed: true,
        },
    )
    .await;
    assert!(matches!(result, Err(backup::BackupError::Database(_))));
    assert_eq!(counts(&app.pool).await, before); // includes device, membership and commit clock
    assert!(VaultRepo::new(&app.pool)
        .get_by_slug("new-import-target")
        .await
        .expect("lookup")
        .is_none());

    let mut invalid = document(vec![
        record(Uuid::now_v7(), "first"),
        record(Uuid::now_v7(), "second"),
    ]);
    invalid["vaults"][0]["items"][1]["payload"]["fields"]["password"]["kind"] =
        json!("synthetic-private-sentinel");
    file.as_file_mut().set_len(0).expect("truncate");
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0)).expect("rewind");
    file.write_all(invalid.to_string().as_bytes())
        .expect("write");
    let error = backup::import_file(
        &app.pool,
        &app.master_key,
        ImportOptions {
            input: file.path().into(),
            owner_email: owner.into(),
            confirmed: true,
        },
    )
    .await
    .expect_err("invalid late payload");
    assert!(!format!("{error:?} {error}").contains("sentinel"));
    assert_eq!(counts(&app.pool).await, before);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn export_failure_preserves_destination_and_excludes_personal_vaults() {
    let app = TestApp::new_with_database(fresh_database().await).await;
    let user = app.register("export-refusal@example.com", "password").await;
    let token = user["access_token"].as_str().expect("token");
    app.create_shared_vault(token, "shared-refusal").await;
    let dir = tempfile::tempdir().expect("directory");
    let path = dir.path().join("existing.json");
    std::fs::write(&path, "previous-backup").expect("previous backup");
    assert!(backup::export(
        &app.pool,
        &zann_crypto::SecretKey::generate(),
        &options(&path)
    )
    .await
    .is_err());
    assert_eq!(
        std::fs::read_to_string(&path).expect("old backup"),
        "previous-backup"
    );
    assert_eq!(std::fs::read_dir(dir.path()).expect("directory").count(), 1);
    let personal = app.personal_vault_id("export-refusal@example.com").await;
    let mut args = options(&path);
    args.all_shared = false;
    args.vaults = vec![personal.to_string()];
    assert!(matches!(
        backup::export(&app.pool, &app.master_key, &args).await,
        Err(backup::BackupError::Invalid(
            "vault_not_shared_server_encrypted"
        ))
    ));
    args.confirmed = false;
    assert!(matches!(
        backup::export(&app.pool, &app.master_key, &args).await,
        Err(backup::BackupError::Invalid(
            "plaintext_confirmation_required"
        ))
    ));
    assert_eq!(
        std::fs::read_to_string(path).expect("unchanged backup"),
        "previous-backup"
    );
}
