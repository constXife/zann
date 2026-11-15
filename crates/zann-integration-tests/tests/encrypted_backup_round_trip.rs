//! Real server restore through authenticated readers, without a plaintext staging file.
use super::*;
use zann_client::app::local::{BackupRecipient, ItemsFilter, Page};
fn phrase() -> BackupRecipient {
    BackupRecipient::Passphrase {
        passphrase: "synthetic portable recovery phrase".into(),
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_archive_restores_through_the_canonical_server_importer_and_pulls_on_a_clean_device(
) {
    let app = server_app::TestApp::new_with_smk().await;
    let login = app
        .register("encrypted-backup@example.test", "Test password 123!")
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let router = app.router();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let pool = app.pool.clone();
    tokio::task::spawn_blocking(move||{
        let root=tempdir();let core=open(root.path());connect(&core,&url,&login);
        let payload=json!({"v":1,"typeId":"note","fields":{"notes":{"kind":"text","value":"synthetic encrypted recovery sentinel"}}});
        core.item_create(ItemCreate{title:"Portable note".into(),path:"Portable note".into(),type_id:"note".into(),payload_json:payload.to_string()}).unwrap();core.remote_sync(None,None).unwrap();
        let handle=core.backup_begin(account_replicas::operation()).unwrap();core.backup_add_recipient(handle.clone(),phrase()).unwrap();let path=root.path().join("recovery.zann");assert_eq!(core.backup_export_encrypted(path.display().to_string(),handle).unwrap().items_count,1);
        let runtime=tokio::runtime::Runtime::new().unwrap();runtime.block_on(sqlx_core::query::query("TRUNCATE items, changes, item_history CASCADE").execute(&pool)).unwrap();
        let restored=tempdir();let other=open(restored.path());connect(&other,&url,&login);let target=other.current_storage_id().unwrap();
        let handle=other.backup_open_encrypted(path.display().to_string(),0,phrase(),account_replicas::operation()).unwrap();let inspection=other.backup_inspect_encrypted(handle.clone()).unwrap();assert_eq!(inspection.items_count,1);let source=inspection.storages[0].id.clone();
        let report=other.backup_import_encrypted(handle,source,BackupImportOptions{target_storage_id:Some(target.clone())}).unwrap();assert_eq!(report.imported_items,1);assert_eq!(other.pending_change_count(target).unwrap(),0);assert!(other.verify().unwrap().problems.is_empty());
        let clean=tempdir();let pulled=open(clean.path());connect(&pulled,&url,&login);let page=pulled.items_list(ItemsFilter{query:None,include_deleted:false},Page{limit:10,cursor:None}).unwrap();assert_eq!(page.items.len(),1);let detail=pulled.item_get(page.items[0].id.clone()).unwrap();let actual:Value=serde_json::from_str(&detail.payload_json).unwrap();assert_eq!(actual,payload);
        assert!(!std::fs::read_dir(root.path()).unwrap().any(|entry|entry.unwrap().file_name().to_string_lossy().starts_with(".zann-export-")));
    }).await.unwrap();
    server.abort();
}
