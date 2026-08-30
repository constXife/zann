//! Export and import through the facade.
//!
//! Until now `backup_export_file` and `backup_import_file` were
//! `Unimplemented` stubs, which meant a client reaching the vault only through
//! `zann-ffi` — COSMIC — had no way to get its own data out. These tests are
//! the proof that it does now, and that what comes out goes back in.

use std::fs;
use std::path::PathBuf;

use uuid::Uuid;
use zann_ffi::{create_core, BackupImportOptions, ItemsFilter, Page};

fn temp_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("zann-ffi-backup-{}-{}", tag, Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create temp dir");
    root
}

fn db_url(root: &std::path::Path) -> String {
    format!("sqlite://{}", root.join("local.sqlite").display())
}

#[test]
fn exports_a_vault_to_an_explicit_path() {
    let root = temp_root("export");
    let core = create_core(db_url(&root)).expect("create core");
    core.initialize_master_password(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");
    core.debug_create_kv_item("secrets/api".into(), "token".into(), "s3cr3t".into())
        .expect("create item");

    let target = root.join("export.json");
    let report = core
        .backup_export_file(target.display().to_string())
        .expect("export");

    assert_eq!(report.items_count, 1);
    assert!(report.vaults_count >= 1);
    assert_eq!(report.path, target.display().to_string());
    assert!(target.exists(), "the export file was not written");
    assert!(
        fs::metadata(&target).expect("stat export").len() > 0,
        "the export file is empty"
    );

    let _ = fs::remove_dir_all(&root);
}

/// The case that matters for a client with no file picker: hand it nothing and
/// it still lands somewhere sensible under the vault directory.
#[test]
fn an_empty_path_falls_back_to_the_vault_directory() {
    let root = temp_root("default");
    let core = create_core(db_url(&root)).expect("create core");
    core.initialize_master_password(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");
    core.debug_create_kv_item("secrets/api".into(), "token".into(), "s3cr3t".into())
        .expect("create item");

    let report = core.backup_export_file(String::new()).expect("export");

    let written = PathBuf::from(&report.path);
    assert!(written.exists(), "no file at the reported path");
    assert!(
        written.starts_with(&root),
        "expected the export under {}, got {}",
        root.display(),
        report.path
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn what_is_exported_can_be_imported_into_a_fresh_vault() {
    let source_root = temp_root("src");
    let password = format!("pw-{}", Uuid::now_v7());

    let source = create_core(db_url(&source_root)).expect("create source core");
    source
        .initialize_master_password(password.clone())
        .expect("initialize master password");
    source
        .debug_create_kv_item("secrets/one".into(), "token".into(), "first".into())
        .expect("create first item");
    source
        .debug_create_kv_item("secrets/two".into(), "token".into(), "second".into())
        .expect("create second item");

    let backup = source_root.join("export.json");
    let exported = source
        .backup_export_file(backup.display().to_string())
        .expect("export");
    assert_eq!(exported.items_count, 2);
    drop(source);

    let target_root = temp_root("dst");
    let target = create_core(db_url(&target_root)).expect("create target core");
    target
        .initialize_master_password(password)
        .expect("initialize master password");

    let report = target
        .backup_import_file(
            backup.display().to_string(),
            BackupImportOptions {
                target_storage_id: None,
            },
        )
        .expect("import");

    assert_eq!(report.imported_items, 2);
    assert_eq!(report.skipped_existing, 0);

    let _ = fs::remove_dir_all(&source_root);
    let _ = fs::remove_dir_all(&target_root);
}

#[test]
fn an_empty_import_path_is_rejected_rather_than_guessed() {
    let root = temp_root("noguess");
    let core = create_core(db_url(&root)).expect("create core");
    core.initialize_master_password(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");

    let err = core
        .backup_import_file(
            "  ".to_string(),
            BackupImportOptions {
                target_storage_id: None,
            },
        )
        .expect_err("an empty import path must not be guessed at");
    assert!(err.to_string().contains("empty"), "unexpected error: {err}");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn exporting_a_locked_vault_fails() {
    let root = temp_root("locked");
    let core = create_core(db_url(&root)).expect("create core");
    core.initialize_master_password(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");
    core.lock().expect("lock");

    core.backup_export_file(root.join("nope.json").display().to_string())
        .expect_err("a locked vault must not export");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn apple_passwords_preflight_and_import_keep_distinct_duplicate_titles() {
    let root = temp_root("apple");
    let core = create_core(db_url(&root)).expect("create core");
    core.initialize_master_password(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");
    let csv = root.join("Passwords.csv");
    fs::write(
        &csv,
        concat!(
            "Title,URL,Username,Password,Notes,OTPAuth\n",
            "Mail,https://example.com,first@example.com,first-password,,\n",
            "Mail,https://example.org,second@example.com,second-password,,\n",
            ",https://invalid.example,invalid,password,,\n",
        ),
    )
    .expect("write Apple CSV");

    let preflight = core
        .apple_passwords_preflight_file(csv.display().to_string())
        .expect("preflight");
    assert_eq!(preflight.total_rows, 3);
    assert_eq!(preflight.importable_items, 2);
    assert_eq!(preflight.duplicate_rows, 1);
    assert_eq!(preflight.invalid_rows, 1);

    let target_storage_id = core.current_storage_id();
    let report = core
        .apple_passwords_import_file(
            csv.display().to_string(),
            BackupImportOptions {
                target_storage_id: Some(target_storage_id),
            },
        )
        .expect("import");
    assert_eq!(report.imported_items, 2);
    assert_eq!(report.renamed_items, 1);
    assert_eq!(report.skipped_invalid, 1);

    let page = core
        .items_list(
            ItemsFilter {
                query: None,
                include_deleted: false,
            },
            Page {
                limit: 10,
                cursor: None,
            },
        )
        .expect("list imported items");
    let mut usernames = page
        .items
        .iter()
        .map(|item| {
            let detail = core.item_get(item.id.clone()).expect("read imported item");
            let payload: serde_json::Value =
                serde_json::from_str(&detail.payload_json).expect("decode imported payload");
            payload["fields"]["username"]["value"]
                .as_str()
                .expect("username value")
                .to_string()
        })
        .collect::<Vec<_>>();
    usernames.sort();
    assert_eq!(
        usernames,
        vec![
            "first@example.com".to_string(),
            "second@example.com".to_string()
        ]
    );
    let mut paths = page
        .items
        .into_iter()
        .map(|item| item.path)
        .collect::<Vec<_>>();
    paths.sort();
    assert_eq!(paths, vec!["Mail".to_string(), "Mail (2)".to_string()]);

    let _ = fs::remove_dir_all(&root);
}
