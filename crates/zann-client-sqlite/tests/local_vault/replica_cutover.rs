//! Refuse old account ownership before SQLite or credential side effects.
use crate::support::CanonicalTempDir;
use zann_client::config::{ClientPaths, ConfigRepository};
use zann_client_sqlite::local_vault::{initialize_database, open_vault};

#[test]
fn old_primary_backup_and_embedded_journals_leave_every_file_unchanged() {
    for name in [
        "client-config.json",
        "client-config.backup.json",
        "client-config.restore.json",
        "client-config.credential-intent.json",
        "client-auth.intent.json",
        "config.json",
    ] {
        let root = CanonicalTempDir::new();
        let path = root.join(name);
        let database = root.join("local.sqlite");
        let old = if name == "config.json" {
            br#"{"contexts":{"old":{"addr":"https://test.invalid","storage_id":"old"}}}"#.as_slice()
        } else {
            br#"{"candidate":{"connections":{"old":{"metadata":{"address":"https://test.invalid","storage_id":null,"expected_master_key_fp":null}}}}}"#.as_slice()
        };
        std::fs::write(&path, old).unwrap();
        // A database-open attempt would fail on this file; the format error
        // must win before SQLite can touch or replace it.
        std::fs::write(&database, b"untouched-test-database").unwrap();
        let error = ConfigRepository::new(ClientPaths::new(root.path()))
            .validate_existing_replica_format()
            .unwrap_err();
        assert!(error.to_string().contains("pre-profile replica"));
        let error = open_vault(format!("sqlite://{}", database.display()))
            .err()
            .expect("refuse old format");
        assert!(error.to_string().contains("pre-profile replica"));
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let location = zann_db::SqliteFileLocation::from_path(&database).unwrap();
        assert!(runtime
            .block_on(initialize_database(&location))
            .unwrap_err()
            .to_string()
            .contains("pre-profile replica"));
        assert_eq!(std::fs::read(&path).unwrap(), old);
        assert_eq!(
            std::fs::read(&database).unwrap(),
            b"untouched-test-database"
        );
        assert_eq!(
            std::fs::read_dir(root.path()).unwrap().count(),
            2,
            "no journal, backup or WAL created"
        );
    }
}

#[test]
fn auth_intent_without_a_current_primary_is_refused_before_database_open() {
    let root = CanonicalTempDir::new();
    let intent = root.join("client-auth.intent.json");
    // Real auth-intent topology: endpoint storage and a source digest, no
    // embedded Config metadata on which a replica-format probe could rely.
    let bytes = br#"{"journal_version":2,"operation_id":"018f4f08-7f1d-7d57-bd43-bb4b7c520001","operation":"password_login","state":"armed","repository_binding_digest":"synthetic","connection_id":"conn_synthetic","profile_name":"first","endpoint":{"address":"https://test.invalid","server_id":"server","server_fingerprint":"pin","storage_id":"018f4f08-7f1d-7d57-bd43-bb4b7c520002"},"source":{"revision":1,"raw_digest":"synthetic","credentials":{},"profile_present":false,"client_present":true}}"#;
    std::fs::write(&intent, bytes).unwrap();
    let database = root.join("local.sqlite");
    std::fs::write(&database, b"unchanged-schema-receipts").unwrap();
    let error = open_vault(format!("sqlite://{}", database.display()))
        .err()
        .expect("refuse orphan auth intent");
    assert!(error.to_string().contains("recovery is required"));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let location = zann_db::SqliteFileLocation::from_path(&database).unwrap();
    assert!(runtime
        .block_on(initialize_database(&location))
        .unwrap_err()
        .to_string()
        .contains("recovery is required"));
    assert_eq!(std::fs::read(&intent).unwrap(), bytes);
    assert_eq!(
        std::fs::read(&database).unwrap(),
        b"unchanged-schema-receipts"
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
}
