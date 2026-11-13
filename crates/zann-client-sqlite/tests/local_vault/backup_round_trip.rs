//! Export and import through the facade.
//!
//! Until now `backup_export_file` and `backup_import_file` were
//! `Unimplemented` stubs, which meant a client reaching the vault only through
//! `zann-ffi` — COSMIC — had no way to get its own data out. These tests are
//! the proof that it does now, and that what comes out goes back in.

use crate::support::CanonicalTempDir;
use zann_client_sqlite::local_vault::open_vault as create_core;

use std::fs;
use std::path::PathBuf;

use uuid::Uuid;
use zann_client::app::local::{BackupImportOptions, ItemsFilter, Page};

fn db_url(root: &std::path::Path) -> String {
    format!("sqlite://{}", root.join("local.sqlite").display())
}

#[test]
fn exports_a_vault_to_an_explicit_path() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    core.seed_offline_fixture(format!("pw-{}", Uuid::now_v7()))
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
}

/// The case that matters for a client with no file picker: hand it nothing and
/// it still lands somewhere sensible under the vault directory.
#[test]
fn an_empty_path_falls_back_to_the_vault_directory() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    core.seed_offline_fixture(format!("pw-{}", Uuid::now_v7()))
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
}

#[test]
fn importing_requires_an_explicit_server_destination() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("core");
    core.seed_offline_fixture("correct horse battery".into())
        .expect("fixture");
    let path = root.join("backup.json");
    core.backup_export_file(path.display().to_string())
        .expect("export");
    core.backup_import_file(
        path.display().to_string(),
        BackupImportOptions {
            target_storage_id: None,
        },
    )
    .expect_err("no implicit local import destination");
}

#[test]
fn an_empty_import_path_is_rejected_rather_than_guessed() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    core.seed_offline_fixture(format!("pw-{}", Uuid::now_v7()))
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
}

#[test]
fn exporting_a_locked_vault_fails() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    core.seed_offline_fixture(format!("pw-{}", Uuid::now_v7()))
        .expect("initialize master password");
    core.lock().expect("lock");

    core.backup_export_file(root.join("nope.json").display().to_string())
        .expect_err("a locked vault must not export");
}

#[test]
fn apple_passwords_preflight_and_import_keep_distinct_duplicate_titles() {
    let root = CanonicalTempDir::new();
    let core = create_core(db_url(&root)).expect("create core");
    core.seed_offline_fixture(format!("pw-{}", Uuid::now_v7()))
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

    let target_storage_id = core.current_storage_id().expect("selected server storage");
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
}
