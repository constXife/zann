use super::*;
use std::time::{Duration, Instant};
const PASSWORD: &str = "synthetic device password";
fn operation() -> SessionOperation {
    SessionOperation::new(Instant::now() + Duration::from_secs(120)).0
}
fn fixture() -> (tempfile::TempDir, Arc<LocalVault>, PasskeyTarget) {
    let dir = tempfile::tempdir().expect("passkey fixture operation");
    let core = open_vault_at_path(
        &dir.path().join("local.sqlite"),
        LocalVaultPorts::system_default(),
    )
    .expect("passkey fixture operation");
    core.seed_offline_fixture(PASSWORD.into())
        .expect("passkey fixture operation");
    let target = core
        .passkey_targets()
        .expect("passkey fixture operation")
        .remove(0)
        .target;
    (dir, core, target)
}
fn source() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/passkey-exchange/cxf.json")
        .display()
        .to_string()
}
fn authorization(core: &LocalVault) -> ExportAuthorization {
    core.authorize_export(ExportStepUp::device_password(PASSWORD.into()), operation())
        .expect("passkey fixture operation")
}
fn payloads(core: &LocalVault) -> Vec<EncryptedPayload> {
    let page = core
        .items_list(
            ItemsFilter {
                updated: None,
                query: None,
                include_deleted: false,
            },
            Page {
                limit: 100,
                cursor: None,
            },
        )
        .expect("passkey fixture operation");
    page.items
        .into_iter()
        .filter(|i| i.type_id == "passkey")
        .map(|i| {
            EncryptedPayload::from_bytes(
                core.item_get(i.id)
                    .expect("passkey fixture operation")
                    .payload_json
                    .as_bytes(),
            )
            .expect("passkey fixture operation")
        })
        .collect()
}
#[test]
fn external_import_step_up_cxf_plain_encrypted_verify_and_snapshot_preserve_passkeys() {
    let (dir, core, target) = fixture();
    let preview = core
        .passkey_preflight_file(source(), PasskeyExchangeFormat::Cxf)
        .expect("passkey fixture operation");
    assert_eq!(preview.credentials, 1);
    assert_eq!(
        core.passkey_import_file(
            source(),
            PasskeyExchangeFormat::Cxf,
            target.clone(),
            operation()
        )
        .expect("passkey fixture operation")
        .imported,
        1
    );
    assert_eq!(
        core.passkey_import_file(
            source(),
            PasskeyExchangeFormat::Cxf,
            target.clone(),
            operation()
        )
        .expect("passkey fixture operation")
        .skipped_existing,
        1
    );
    let original = payloads(&core);
    assert_eq!(original.len(), 1);
    assert!(core
        .verify()
        .expect("passkey fixture operation")
        .problems
        .is_empty());
    let cxf = dir.path().join("export.cxf.json");
    let fake = ExportAuthorization::from_token("forged".into());
    assert!(core
        .passkey_export_cxf(cxf.display().to_string(), target.clone(), fake)
        .is_err());
    assert!(!cxf.exists());
    let proof = authorization(&core);
    let replay = ExportAuthorization::from_token(proof.token().into());
    core.passkey_export_cxf(cxf.display().to_string(), target.clone(), proof)
        .expect("passkey fixture operation");
    assert!(core
        .passkey_export_cxf(cxf.display().to_string(), target, replay)
        .is_err());
    let decoded = exchange::import(
        std::fs::File::open(&cxf).expect("passkey fixture operation"),
        PasskeyExchangeFormat::Cxf,
    )
    .expect("passkey fixture operation");
    assert_eq!(
        decoded.entries[0]
            .payload(0)
            .expect("passkey fixture operation"),
        original[0]
    );
    let plain = dir.path().join("backup.json");
    core.backup_export_file(plain.display().to_string(), authorization(&core))
        .expect("passkey fixture operation");
    let backup: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&plain).expect("passkey fixture operation"))
            .expect("passkey fixture operation");
    assert_eq!(
        serde_json::from_value::<EncryptedPayload>(backup["items"][0]["payload"].clone())
            .expect("passkey fixture operation"),
        original[0]
    );
    let archive = core
        .backup_begin(operation())
        .expect("passkey fixture operation");
    let recipient = || BackupRecipient::Passphrase {
        passphrase: "synthetic backup recovery phrase".into(),
    };
    core.backup_add_recipient(archive.clone(), recipient())
        .expect("passkey fixture operation");
    let encrypted = dir.path().join("backup.zann");
    core.backup_export_encrypted(encrypted.display().to_string(), archive)
        .expect("passkey fixture operation");
    let opened = core
        .backup_open_encrypted(encrypted.display().to_string(), 0, recipient(), operation())
        .expect("passkey fixture operation");
    assert_eq!(
        core.backup_inspect_encrypted(opened.clone())
            .expect("passkey fixture operation")
            .items_count,
        1
    );
    core.backup_cancel(opened)
        .expect("passkey fixture operation");
    assert!(!std::fs::read(&encrypted)
        .expect("passkey fixture operation")
        .windows(b"synthetic-login-secret".len())
        .any(|w| w == b"synthetic-login-secret"));
    let snapshot = core
        .snapshot_create(None)
        .expect("passkey fixture operation");
    let row = core
        .items_list(
            ItemsFilter {
                updated: None,
                query: None,
                include_deleted: false,
            },
            Page {
                limit: 10,
                cursor: None,
            },
        )
        .expect("passkey fixture operation")
        .items
        .remove(0);
    core.item_update(
        row.id,
        ItemUpdate {
            title: "Renamed".into(),
            path: "Renamed".into(),
            type_id: "passkey".into(),
            payload_json: serde_json::to_string(&original[0]).expect("passkey fixture operation"),
        },
    )
    .expect("passkey fixture operation");
    core.snapshot_restore(snapshot.path)
        .expect("passkey fixture operation");
    assert!(
        !core
            .vault_status()
            .expect("passkey fixture operation")
            .unlocked
    );
    core.unlock(PASSWORD.into())
        .expect("passkey fixture operation");
    assert_eq!(payloads(&core), original);
    assert!(core
        .verify()
        .expect("passkey fixture operation")
        .problems
        .is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for file in [&cxf, &plain, &encrypted] {
            assert_eq!(
                std::fs::metadata(file)
                    .expect("passkey fixture operation")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}
#[test]
fn shared_targets_cancelled_operations_and_late_invalid_entries_commit_nothing() {
    let (dir, core, target) = fixture();
    let pool = core.pool();
    let storage = Uuid::parse_str(&target.storage_id).expect("passkey fixture operation");
    let mut vault = core
        .runtime
        .block_on(LocalVaultRepo::new(&pool).get_by_id(
            storage,
            Uuid::parse_str(&target.vault_id).expect("passkey fixture operation"),
        ))
        .expect("passkey fixture operation")
        .expect("passkey fixture operation");
    vault.id = Uuid::now_v7();
    vault.slug = "shared-test".into();
    vault.kind = zann_core::VaultKind::Shared;
    vault.key_wrap_type = zann_db::local::KeyWrapType::RemoteServer;
    core.runtime
        .block_on(LocalVaultRepo::new(&pool).create(&vault))
        .expect("passkey fixture operation");
    let shared = PasskeyTarget {
        storage_id: target.storage_id.clone(),
        vault_id: vault.id.to_string(),
    };
    assert!(core
        .passkey_import_file(source(), PasskeyExchangeFormat::Cxf, shared, operation())
        .is_err());
    assert!(payloads(&core).is_empty());
    let (op, cancel) = SessionOperation::new(Instant::now() + Duration::from_secs(120));
    cancel.cancel();
    assert!(matches!(
        core.passkey_import_file(source(), PasskeyExchangeFormat::Cxf, target.clone(), op),
        Err(LocalError::Cancelled)
    ));
    let mut wire: serde_json::Value =
        serde_json::from_slice(&std::fs::read(source()).expect("passkey fixture operation"))
            .expect("passkey fixture operation");
    let mut second = wire["accounts"][0]["items"][0].clone();
    second["id"] = serde_json::json!("c2Vjb25k");
    second["title"] = serde_json::json!("x".repeat(201));
    second["credentials"][0]["credentialId"] = serde_json::json!("c2Vjb25k");
    wire["accounts"][0]["items"]
        .as_array_mut()
        .expect("passkey fixture operation")
        .push(second);
    let input = dir.path().join("late-invalid.json");
    std::fs::write(
        &input,
        serde_json::to_vec(&wire).expect("passkey fixture operation"),
    )
    .expect("passkey fixture operation");
    assert!(core
        .passkey_import_file(
            input.display().to_string(),
            PasskeyExchangeFormat::Cxf,
            target,
            operation()
        )
        .is_err());
    assert!(payloads(&core).is_empty());
}

#[test]
fn lock_cancels_target_and_import_database_waits_without_retaining_account_keys() {
    for importing in [false, true] {
        let (_dir, core, target) = fixture();
        let _runtime = core.runtime.enter();
        let pool = core.pool();
        let held = core.runtime.block_on(async {
            let mut held = Vec::new();
            for _ in 0..pool.options().get_max_connections() {
                held.push(pool.acquire().await.expect("passkey fixture operation"));
            }
            held
        });
        let key = Arc::downgrade(&core.account_key().expect("passkey fixture operation"));
        let worker = core.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let result = if importing {
                worker
                    .passkey_import_file(source(), PasskeyExchangeFormat::Cxf, target, operation())
                    .map(|_| ())
            } else {
                worker.passkey_targets().map(|_| ())
            };
            send.send(result).expect("passkey fixture operation");
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while if importing {
            core.syncs.len() == 0
        } else {
            core.item_reads.len() == 0
        } {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        core.lock().expect("passkey fixture operation");
        let result = receive
            .recv_timeout(Duration::from_secs(5))
            .expect("lock must cancel SQLite wait");
        assert!(matches!(
            result,
            Err(LocalError::Cancelled)
                | Err(LocalError::Locked)
                | Err(LocalError::InvalidArgument(_))
        ));
        thread.join().expect("passkey fixture operation");
        assert!(key.upgrade().is_none());
        drop(held);
    }
}
#[test]
fn unlocked_verify_refuses_semantically_invalid_passkeys_without_leaking_the_payload() {
    let (_dir, core, target) = fixture();
    let pool = core.pool();
    let key = core.account_key().expect("passkey fixture operation");
    let services = LocalServices::new(&pool, &key);
    let mut payload = EncryptedPayload::new("passkey");
    payload.fields.insert(
        "private_key".into(),
        zann_core::FieldValue {
            kind: zann_core::FieldKind::Password,
            value: "sentinel-private-key".into(),
            meta: None,
        },
    );
    core.runtime
        .block_on(services.put_item(
            Uuid::parse_str(&target.storage_id).expect("passkey fixture operation"),
            Uuid::parse_str(&target.vault_id).expect("passkey fixture operation"),
            "Invalid fixture".into(),
            "passkey".into(),
            payload,
        ))
        .expect("passkey fixture operation");
    let report = core.verify().expect("passkey fixture operation");
    assert_eq!(report.problems.len(), 1);
    assert_eq!(report.problems[0].kind, "passkey_invalid");
    assert!(!format!("{report:?}").contains("sentinel"));
}
