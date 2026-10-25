use super::*;
use std::collections::VecDeque;
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
#[derive(Serialize, Deserialize)]
struct PlainBackup {
    version: u32,
    exported_at: String,
    storages: Vec<PlainBackupStorage>,
    vaults: Vec<PlainBackupVault>,
    items: Vec<PlainBackupItem>,
}

struct VecItemSource {
    items: VecDeque<PlainBackupItem>,
}

impl BackupItemSource for VecItemSource {
    fn next_item<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<PlainBackupItem>, anyhow::Error>> + Send + 'a>>
    {
        Box::pin(async move { Ok(self.items.pop_front()) })
    }
}

fn sample_payload() -> EncryptedPayload {
    let mut payload = EncryptedPayload::new("login");
    payload.fields.insert(
        "username".to_string(),
        FieldValue {
            kind: FieldKind::Text,
            value: "user@example.com".to_string(),
            meta: None,
        },
    );
    payload
}

fn temp_path(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("zann-{label}-{}.json", Uuid::now_v7()));
    path
}

fn temp_csv_path(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("zann-{label}-{}.csv", Uuid::now_v7()));
    path
}

#[test]
fn preflights_apple_passwords_without_counting_embedded_newlines_as_rows() {
    let path = temp_csv_path("apple-preflight");
    std::fs::write(
        &path,
        concat!(
            "Title,URL,Username,Password,Notes,OTPAuth\n",
            "Mail,https://example.com,first,pw,\"line one\nline two\",\n",
            "Mail,https://example.org,second,pw2,,\n",
            ",https://invalid.example,user,pw,,\n",
        ),
    )
    .expect("write CSV");

    let report = apple_passwords_preflight(&path).expect("preflight");
    assert_eq!(report.total_rows, 3);
    assert_eq!(report.importable_items, 2);
    assert_eq!(report.duplicate_rows, 1);
    assert_eq!(report.invalid_rows, 1);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn preflight_rejects_non_apple_csv_headers() {
    let path = temp_csv_path("apple-headers");
    std::fs::write(&path, "name,login,secret\nExample,user,pw\n").expect("write CSV");

    let err = apple_passwords_preflight(&path).expect_err("invalid headers");
    assert_eq!(err.kind, "apple_csv_headers_invalid");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn duplicate_suffix_keeps_the_item_name_within_the_path_limit() {
    let base = "x".repeat(MAX_ITEM_NAME_LEN);
    let candidate = suffixed_import_path(&base, 2);

    assert_eq!(candidate.len(), MAX_ITEM_NAME_LEN);
    assert!(candidate.ends_with(" (2)"));
}

#[test]
fn reads_metadata_and_streams_items() {
    let path = temp_path("backup-meta");
    let backup = PlainBackup {
        version: BACKUP_VERSION,
        exported_at: "2024-01-01T00:00:00Z".to_string(),
        storages: vec![PlainBackupStorage {
            id: Uuid::nil().to_string(),
            kind: StorageKind::LocalOnly.as_i32(),
            name: "Local".to_string(),
            server_url: None,
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: false,
            auth_method: None,
        }],
        vaults: vec![PlainBackupVault {
            id: Uuid::now_v7().to_string(),
            storage_id: Uuid::nil().to_string(),
            name: "Default".to_string(),
            kind: VaultKind::Personal.as_i32(),
            is_default: true,
        }],
        items: vec![
            PlainBackupItem {
                id: Some(Uuid::now_v7().to_string()),
                storage_id: Uuid::nil().to_string(),
                vault_id: Uuid::now_v7().to_string(),
                path: "example".to_string(),
                name: "Example".to_string(),
                type_id: "login".to_string(),
                payload: sample_payload(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
                version: 1,
                deleted_at: None,
            },
            PlainBackupItem {
                id: Some(Uuid::now_v7().to_string()),
                storage_id: Uuid::nil().to_string(),
                vault_id: Uuid::now_v7().to_string(),
                path: "example2".to_string(),
                name: "Example 2".to_string(),
                type_id: "login".to_string(),
                payload: sample_payload(),
                updated_at: "2024-01-02T00:00:00Z".to_string(),
                version: 1,
                deleted_at: None,
            },
        ],
    };

    let file = File::create(&path).expect("create temp backup");
    serde_json::to_writer(file, &backup).expect("write backup");

    let meta = read_backup_metadata(&path).expect("read metadata");
    assert_eq!(meta.version, BACKUP_VERSION);
    assert_eq!(meta.storages.len(), 1);
    assert_eq!(meta.vaults.len(), 1);

    let mut streamed = Vec::new();
    stream_backup_items(&path, |item, _index| {
        streamed.push(item);
        Ok(())
    })
    .expect("stream items");
    assert_eq!(streamed.len(), 2);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn streams_items_async() {
    let path = temp_path("backup-stream-async");
    let backup = PlainBackup {
        version: BACKUP_VERSION,
        exported_at: "2024-01-01T00:00:00Z".to_string(),
        storages: vec![],
        vaults: vec![],
        items: vec![
            PlainBackupItem {
                id: Some(Uuid::now_v7().to_string()),
                storage_id: Uuid::nil().to_string(),
                vault_id: Uuid::now_v7().to_string(),
                path: "one".to_string(),
                name: "One".to_string(),
                type_id: "login".to_string(),
                payload: sample_payload(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
                version: 1,
                deleted_at: None,
            },
            PlainBackupItem {
                id: Some(Uuid::now_v7().to_string()),
                storage_id: Uuid::nil().to_string(),
                vault_id: Uuid::now_v7().to_string(),
                path: "two".to_string(),
                name: "Two".to_string(),
                type_id: "login".to_string(),
                payload: sample_payload(),
                updated_at: "2024-01-02T00:00:00Z".to_string(),
                version: 1,
                deleted_at: None,
            },
        ],
    };

    let file = File::create(&path).expect("create temp backup");
    serde_json::to_writer(file, &backup).expect("write backup");

    let items = Arc::new(Mutex::new(Vec::new()));
    let items_clone = Arc::clone(&items);
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            stream_backup_items_async(&path, |item, _index| {
                let items_clone = Arc::clone(&items_clone);
                async move {
                    let mut guard = items_clone.lock().expect("lock items");
                    guard.push(item);
                    Ok(())
                }
            })
            .await
            .expect("stream async");
        });

    let guard = items.lock().expect("lock items");
    assert_eq!(guard.len(), 2);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn writes_backup_streaming() {
    let path = temp_path("backup-write");
    let storages = vec![PlainBackupStorage {
        id: Uuid::nil().to_string(),
        kind: StorageKind::LocalOnly.as_i32(),
        name: "Local".to_string(),
        server_url: None,
        server_name: None,
        server_fingerprint: None,
        account_subject: None,
        personal_vaults_enabled: false,
        auth_method: None,
    }];
    let vaults = vec![PlainBackupVault {
        id: Uuid::now_v7().to_string(),
        storage_id: Uuid::nil().to_string(),
        name: "Default".to_string(),
        kind: VaultKind::Personal.as_i32(),
        is_default: true,
    }];
    let items = VecDeque::from(vec![
        PlainBackupItem {
            id: Some(Uuid::now_v7().to_string()),
            storage_id: Uuid::nil().to_string(),
            vault_id: Uuid::now_v7().to_string(),
            path: "alpha".to_string(),
            name: "Alpha".to_string(),
            type_id: "login".to_string(),
            payload: sample_payload(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
            version: 1,
            deleted_at: None,
        },
        PlainBackupItem {
            id: Some(Uuid::now_v7().to_string()),
            storage_id: Uuid::nil().to_string(),
            vault_id: Uuid::now_v7().to_string(),
            path: "beta".to_string(),
            name: "Beta".to_string(),
            type_id: "login".to_string(),
            payload: sample_payload(),
            updated_at: "2024-01-02T00:00:00Z".to_string(),
            version: 1,
            deleted_at: None,
        },
    ]);
    let mut source = VecItemSource { items };

    let file = File::create(&path).expect("create temp backup");
    let mut writer = BufWriter::new(file);
    let items_count = tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            write_backup_streaming(
                &mut writer,
                BACKUP_VERSION,
                "2024-01-01T00:00:00Z",
                &storages,
                &vaults,
                &mut source,
            )
            .await
            .expect("write backup")
        });
    writer.flush().expect("flush");
    assert_eq!(items_count, 2);

    let meta = read_backup_metadata(&path).expect("read metadata");
    assert_eq!(meta.version, BACKUP_VERSION);
    assert_eq!(meta.storages.len(), 1);
    assert_eq!(meta.vaults.len(), 1);

    let mut streamed = Vec::new();
    stream_backup_items(&path, |item, _index| {
        streamed.push(item);
        Ok(())
    })
    .expect("stream items");
    assert_eq!(streamed.len(), 2);
    let _ = std::fs::remove_file(&path);
}
