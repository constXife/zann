//! Real HTTP + Postgres + canonical LocalVault: export, wipe, restore, then pull on a clean device.
#![cfg(feature = "postgres-tests")]
#[path = "../../zann-server/tests/client_workflow_support/app.rs"]
mod server_app;
#[path = "../../zann-server/tests/support.rs"]
mod support;

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use zann_client::app::local::{BackupImportOptions, ItemCreate};
use zann_client::config::{
    CredentialId, CredentialPortError, CredentialSecret, CredentialStore, LegacyCredentialLocator,
    LegacyCredentialSource,
};
use zann_client_sqlite::local_vault::{LocalVault, LocalVaultPorts};

#[derive(Default)]
struct Credentials(Mutex<BTreeMap<String, String>>);
impl CredentialStore for Credentials {
    fn put(&self, id: &CredentialId, value: &CredentialSecret) -> Result<(), CredentialPortError> {
        self.0
            .lock()
            .unwrap()
            .insert(id.as_str().into(), value.expose_secret().into());
        Ok(())
    }
    fn get(&self, id: &CredentialId) -> Result<Option<CredentialSecret>, CredentialPortError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(id.as_str())
            .map(|s| CredentialSecret::new(s.clone()).unwrap()))
    }
    fn delete(&self, id: &CredentialId) -> Result<(), CredentialPortError> {
        self.0.lock().unwrap().remove(id.as_str());
        Ok(())
    }
}
impl LegacyCredentialSource for Credentials {
    fn get(
        &self,
        _: &LegacyCredentialLocator,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        Ok(None)
    }
}
fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
}

fn open(root: &Path) -> Arc<LocalVault> {
    let credentials = Arc::new(Credentials::default());
    LocalVault::open(
        zann_db::SqliteFileLocation::from_path(&root.join("local.sqlite")).unwrap(),
        LocalVaultPorts {
            keystore: Arc::new(zann_keystore::UnsupportedKeystore),
            authenticator: Arc::new(zann_keystore::UnsupportedAuthenticator),
            credentials: credentials.clone(),
            legacy_credentials: credentials,
        },
    )
    .unwrap()
}
fn connect(core: &LocalVault, url: &str, login: &Value) {
    core.import_legacy_account(
        url.into(),
        "Backup test".into(),
        "default".into(),
        Some(uuid::Uuid::now_v7().to_string()),
        login["access_token"].as_str().unwrap().into(),
        login["refresh_token"].as_str().unwrap().into(),
        Some(
            (chrono::Utc::now() + chrono::Duration::seconds(login["expires_in"].as_i64().unwrap()))
                .to_rfc3339(),
        ),
    )
    .unwrap();
    core.initialize_master_password("test device unlock password".into())
        .unwrap();
    core.enroll_account_key("test master password".into())
        .unwrap();
    core.remote_sync(None, None).unwrap();
}
fn normalized(path: &Path) -> Vec<Value> {
    let backup: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let names: BTreeMap<_, _> = backup["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v["id"].as_str().unwrap(), v["name"].clone()))
        .collect();
    let mut items = backup["items"].as_array().unwrap().iter().filter(|i|i["deleted_at"].is_null()).map(|i| json!({
        "vault":names[i["vault_id"].as_str().unwrap()],"path":i["path"],"type_id":i["type_id"],"payload":i["payload"],"tags":i["tags"],"favorite":i["favorite"]
    })).collect::<Vec<_>>();
    items.sort_by_key(|i| i.to_string());
    items
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_server_backup_preserves_items_metadata_and_encryption_planes() {
    let app = server_app::TestApp::new_with_smk().await;
    let login = app
        .register("backup@example.test", "Test password 123!")
        .await;
    let token = login["access_token"].as_str().unwrap();
    app.create_shared_vault(token, "backup-shared").await;
    app.create_shared_vault(token, "backup-shared-same-name")
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let router = app.router();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let pool = app.pool.clone();
    tokio::task::spawn_blocking(move || {
        let root = tempdir();
        let core = open(root.path());
        connect(&core,&url,&login);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let location = zann_db::SqliteFileLocation::from_path(&root.path().join("local.sqlite")).unwrap();
        let local = runtime.block_on(zann_db::connect_sqlite_file_with_max(&location,2)).unwrap();
        for (idx,vault) in core.list_vaults().unwrap().iter().enumerate() {
            core.set_current_vault(vault.id.clone()).unwrap();
            for kind in ["login","note"] {
                let item = core.item_create(ItemCreate { title:kind.into(),path:format!("backup/{kind}"),type_id:kind.into(),payload_json:json!({"v":1,"typeId":kind,"fields":{"password":{"kind":"password","value":format!("secret-{idx}-{kind}")}},"extra":{"fixture":"roundtrip"}}).to_string() }).unwrap();
                let metadata = zann_core::ItemMetadata { tags:Some(vec!["backup".into(),format!("tag-{idx}")]),favorite: kind=="login" };
                runtime.block_on(async {
                    sqlx_core::query::query("UPDATE items_cache SET metadata = ? WHERE id = ?").bind(sqlx_core::types::Json(&metadata)).bind(uuid::Uuid::parse_str(&item.id).unwrap()).execute(&local).await.unwrap();
                    sqlx_core::query::query("UPDATE pending_changes SET metadata = ? WHERE item_id = ?").bind(sqlx_core::types::Json(&metadata)).bind(uuid::Uuid::parse_str(&item.id).unwrap()).execute(&local).await.unwrap();
                });
            }
        }
        core.remote_sync(None, None).unwrap();
        let backup = root.path().join("backup.json");
        assert_eq!(core.backup_export_file(backup.display().to_string()).unwrap().items_count,6);

        let mut document: Value = serde_json::from_slice(&std::fs::read(&backup).unwrap()).unwrap();
        // Cross the per-vault 16 x 64 push budget: success must drain all changes.
        for index in 0..1025 {
            let mut item = document["items"][0].clone();
            item["id"] = json!(uuid::Uuid::now_v7().to_string());
            item["path"] = json!(format!("bulk/item-{index}")); item["name"] = json!(format!("item-{index}"));
            document["items"].as_array_mut().unwrap().push(item);
        }
        let mut deleted = document["items"][0].clone(); deleted["path"] = json!("deleted-entry"); deleted["name"] = json!("deleted-entry"); deleted["deleted_at"] = json!("2026-01-01T00:00:00Z");
        document["items"].as_array_mut().unwrap().push(deleted);
        std::fs::write(&backup,serde_json::to_vec(&document).unwrap()).unwrap();
        let expected = normalized(&backup);
        // Wipe only this isolated test database's content. Retain accounts and vault keys.
        runtime.block_on(async {
            sqlx_core::query::query("TRUNCATE items, changes, item_history CASCADE").execute(&pool).await.unwrap();
            sqlx_core::query::query("DELETE FROM vaults WHERE kind = 2").execute(&pool).await.unwrap();
        });
        runtime.block_on(local.close());
        drop(core);
        let restored_root = tempdir();
        let core = open(restored_root.path());
        connect(&core,&url,&login);
        let storage = core.current_storage_id().unwrap();
        let options = || BackupImportOptions { target_storage_id:Some(storage.clone()) };
        let invalid = root.path().join("invalid.json");
        let mut unsupported = document.clone(); unsupported["version"] = json!(99);
        std::fs::write(&invalid,serde_json::to_vec(&unsupported).unwrap()).unwrap();
        assert!(core.backup_import_file(invalid.display().to_string(),options()).is_err());
        assert_eq!(core.list_vaults().unwrap().len(),1,"invalid backup must not create shared vaults");
        let mut malformed = document.clone(); malformed["items"][1]["path"] = json!("../invalid");
        std::fs::write(&invalid,serde_json::to_vec(&malformed).unwrap()).unwrap();
        assert!(core.backup_import_file(invalid.display().to_string(),options()).is_err());
        assert_eq!(core.list_vaults().unwrap().len(),1);
        let report = core.backup_import_file(backup.display().to_string(),options()).unwrap_or_else(|error| {
            let mut cause: &dyn std::error::Error = &error;
            while let Some(next) = cause.source() { eprintln!("test import cause: {next}"); cause = next; }
            panic!("import failed: {error}");
        });
        assert_eq!(report.imported_items,1031);
        assert_eq!(report.skipped_deleted,1);
        assert_eq!(core.pending_change_count(storage.clone()).unwrap(),0);
        assert!(core.verify().unwrap().problems.is_empty());
        assert_eq!(core.backup_import_file(backup.display().to_string(),options()).unwrap().skipped_existing,1031);
        let restored = root.path().join("restored.json");core.backup_export_file(restored.display().to_string()).unwrap();
        assert_eq!(normalized(&restored),expected);
        // A second device pulls from the real server: this catches metadata lost in push or pull.
        let second = tempdir();let other = open(second.path());connect(&other,&url,&login);
        let pulled = second.path().join("pulled.json");other.backup_export_file(pulled.display().to_string()).unwrap();
        assert_eq!(normalized(&pulled),expected);
        assert!(other.verify().unwrap().problems.is_empty());
    }).await.unwrap();
    server.abort();
}
