use super::*;
use zann_db::local::LocalStorage;

pub(super) fn fixture() -> (tempfile::TempDir, Arc<LocalVault>, Uuid, Uuid) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().canonicalize().expect("canonical root");
    let core =
        open_vault(format!("sqlite://{}", root.join("local.sqlite").display())).expect("open");
    core.seed_offline_fixture("context fixture password".into())
        .expect("initialize");
    let pool = core.pool();
    let first = core.storage_id().expect("first storage");
    let remote = LocalStorage {
        id: Uuid::now_v7(),
        kind: zann_core::StorageKind::Remote,
        name: "Remote".into(),
        server_url: Some("https://second.example.test".into()),
        server_name: None,
        server_fingerprint: None,
        account_subject: None,
        personal_vaults_enabled: true,
        auth_method: None,
    };
    core.runtime
        .block_on(LocalStorageRepo::new(&pool).upsert(&remote))
        .expect("storage");
    let mut vault = core
        .runtime
        .block_on(LocalVaultRepo::new(&pool).list_by_storage(first))
        .expect("vaults")
        .remove(0);
    // The same vault ID in two storage contexts must never mix their items.
    let first_key = core.account_key().expect("first key");
    let remote_key = Arc::new(SecretKey::generate());
    vault.vault_key_enc =
        vault_crypto::rewrap_vault_key(&first_key, &remote_key, vault.id, &vault.vault_key_enc)
            .expect("independent wrapping");
    let keyring = core.device_unlock().expect("keyring");
    let mut candidate = keyring.clone();
    candidate
        .insert_account(
            &core.root_key().expect("root"),
            remote.id.to_string(),
            "second-server".into(),
            "second-subject".into(),
            &remote_key,
        )
        .expect("enroll fixture");
    core.commit_device_unlock(Some(&keyring), &candidate)
        .expect("commit fixture");
    core.account_keys
        .lock()
        .expect("keys")
        .insert(remote.id.to_string(), remote_key);
    vault.storage_id = remote.id;
    core.runtime
        .block_on(LocalVaultRepo::new(&pool).insert_if_absent(&vault))
        .expect("vault");
    (dir, core, first, remote.id)
}

fn page(core: &LocalVault) -> ItemPage {
    core.items_list(
        ItemsFilter {
            query: None,
            include_deleted: false,
        },
        Page {
            limit: 20,
            cursor: None,
        },
    )
    .expect("items")
}

#[test]
fn selection_opens_target_vault_and_isolates_reads_and_writes() {
    let (_dir, core, first, remote) = fixture();
    let local_vault = core.current_vault_id();
    let local_item = core
        .debug_create_kv_item("Local".into(), "key".into(), "local value".into())
        .expect("item");
    core.set_current_storage(remote.to_string())
        .expect("switch");
    assert_eq!(core.current_vault_id(), local_vault);
    assert!(page(&core).items.is_empty());
    assert!(core.item_get(local_item.clone()).is_err());
    core.debug_create_kv_item("Remote".into(), "key".into(), "remote value".into())
        .expect("item");
    assert_eq!(page(&core).items[0].path, "Remote");
    core.set_current_storage(first.to_string()).expect("back");
    assert_eq!(page(&core).items[0].id, local_item);
    assert_eq!(page(&core).items.len(), 1);
}

#[test]
fn selection_round_trips_storage_with_personal_and_server_wrapped_shared_vaults() {
    let (_dir, core, first, remote) = fixture();
    let pool = core.pool();
    let personal = Uuid::parse_str(&core.current_vault_id().expect("personal")).expect("id");
    let shared = zann_db::local::LocalVault {
        id: Uuid::now_v7(),
        storage_id: remote,
        slug: "infra".into(),
        name: "Infrastructure".into(),
        kind: zann_core::VaultKind::Shared,
        is_default: false,
        // An opaque server envelope is not a key wrapped by the master key.
        vault_key_enc: vec![4, 5, 6],
        key_wrap_type: zann_db::local::KeyWrapType::RemoteServer,
        cache_key_fp: Some(zann_crypto::cache_key_fingerprint(
            &core.account_key_for_storage(remote).expect("remote key"),
        )),
        last_synced_at: None,
    };
    core.runtime
        .block_on(LocalVaultRepo::new(&pool).insert_if_absent(&shared))
        .expect("shared vault");
    core.set_current_storage(remote.to_string())
        .expect("remote");
    core.set_current_vault(shared.id.to_string())
        .expect("shared");
    let item = core
        .debug_create_kv_item("Shared".into(), "key".into(), "fixture value".into())
        .expect("shared item");
    core.set_current_storage(first.to_string()).expect("local");
    assert!(page(&core).items.is_empty());
    core.set_current_storage(remote.to_string())
        .expect("return to remote");
    core.set_current_vault(shared.id.to_string())
        .expect("shared again");
    assert!(
        core.item_get(item).is_ok(),
        "shared payload still opens with its canonical key"
    );

    core.set_current_storage(first.to_string())
        .expect("local again");
    core.runtime
        .block_on(LocalVaultRepo::new(&pool).update_key(
            remote,
            personal,
            &[0u8; 72],
            zann_db::local::KeyWrapType::Master,
        ))
        .expect("corrupt personal wrapping");
    let error = core
        .set_current_storage(remote.to_string())
        .expect_err("wrong personal key");
    assert!(matches!(&error, LocalError::Unlock { kind, .. } if kind == "storage_key_mismatch"));
    assert!(std::error::Error::source(&error).is_some());
    assert_eq!(
        core.current_storage_id().expect("storage"),
        first.to_string()
    );
}

#[test]
fn incompatible_keys_and_empty_storage_leave_selection_unchanged() {
    let (_dir, core, first, remote) = fixture();
    let before = core.current_vault_id();
    let pool = core.pool();
    let vault_id = Uuid::parse_str(before.as_ref().expect("vault")).expect("id");
    core.runtime
        .block_on(LocalVaultRepo::new(&pool).update_key(
            remote,
            vault_id,
            &[0u8; 72],
            zann_db::local::KeyWrapType::Master,
        ))
        .expect("change key");
    let error = core
        .set_current_storage(remote.to_string())
        .expect_err("wrong key");
    assert!(matches!(&error, LocalError::Unlock { kind, .. } if kind == "storage_key_mismatch"));
    assert!(std::error::Error::source(&error).is_some());
    assert_eq!(
        core.current_storage_id().expect("storage"),
        first.to_string()
    );
    assert_eq!(core.current_vault_id(), before);
    core.runtime
        .block_on(LocalVaultRepo::new(&pool).delete_by_storage(remote))
        .expect("empty");
    core.set_current_storage(remote.to_string())
        .expect("empty server catalog");
    assert_eq!(
        core.current_storage_id().expect("storage"),
        remote.to_string()
    );
    assert!(core.current_vault_id().is_none());
    assert!(page(&core).items.is_empty());
}

#[test]
fn selection_waits_for_item_context_and_lock_supersedes_pending_unlock() {
    let (_dir, core, first, remote) = fixture();
    let lease = core.context_gate.read().expect("lease");
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let other = core.clone();
    let worker = std::thread::spawn(move || {
        started_tx.send(()).expect("started");
        let result = other.set_current_storage(remote.to_string());
        done_tx.send(result).expect("done");
    });
    started_rx.recv().expect("started");
    assert!(done_rx
        .recv_timeout(std::time::Duration::from_millis(50))
        .is_err());
    assert_eq!(core.storage_id().expect("storage"), first);
    drop(lease);
    done_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("finished")
        .expect("switch");
    worker.join().expect("worker");
    let generation = core.context_generation.load(Ordering::SeqCst);
    let key = core.account_key().expect("key");
    core.lock().expect("lock");
    assert!(core.finish_unlock(key, generation).is_err());
    assert!(matches!(
        core.set_current_storage(first.to_string()),
        Err(LocalError::Locked)
    ));
    assert!(!core.vault_status().expect("status").unlocked);
}

#[test]
fn a_late_sync_target_cannot_replace_an_explicitly_selected_empty_replica() {
    let (_dir, core, first, second) = fixture();
    core.runtime
        .block_on(LocalVaultRepo::new(&core.pool()).delete_by_storage(second))
        .expect("empty second catalog");
    core.set_current_storage(second.to_string())
        .expect("second replica");
    let key = core.account_key().expect("key");
    for target in [Some(first.to_string()), None] {
        let generation = core.context_generation.load(Ordering::SeqCst);
        core.select_synced_catalog(target, Some(second), &key, generation)
            .expect("a completed sync preserves explicit navigation");
        assert_eq!(core.current_storage_id(), Some(second.to_string()));
        assert!(core.current_vault_id().is_none());
    }
}

#[test]
fn one_password_change_keeps_both_independent_accounts_readable_after_restart() {
    let (dir, core, first, remote) = fixture();
    let first_key = core.account_key_for_storage(first).expect("first key");
    let second_key = core.account_key_for_storage(remote).expect("second key");
    assert!(first_key.as_bytes() != second_key.as_bytes());
    let first_item = core
        .debug_create_kv_item("First".into(), "key".into(), "first secret".into())
        .expect("first item");
    core.set_current_storage(remote.to_string())
        .expect("second account");
    let second_item = core
        .debug_create_kv_item("Second".into(), "key".into(), "second secret".into())
        .expect("second item");
    let pool = core.pool();
    let before = core
        .runtime
        .block_on(LocalVaultRepo::new(&pool).list_by_storage(remote))
        .expect("envelopes");
    assert!(
        vault_crypto::decrypt_vault_key(&first_key, before[0].id, &before[0].vault_key_enc)
            .is_err()
    );
    core.change_unlock_password(
        "context fixture password".into(),
        "replacement device password".into(),
    )
    .expect("change password");
    let after = core
        .runtime
        .block_on(LocalVaultRepo::new(&pool).list_by_storage(remote))
        .expect("envelopes");
    assert_eq!(before[0].vault_key_enc, after[0].vault_key_enc);
    assert_eq!(before[0].cache_key_fp, after[0].cache_key_fp);
    drop(pool);
    drop(core);
    let path = dir
        .path()
        .canonicalize()
        .expect("root")
        .join("local.sqlite");
    let core = open_vault(format!("sqlite://{}", path.display())).expect("reopen");
    assert!(core.unlock("context fixture password".into()).is_err());
    core.unlock("replacement device password".into())
        .expect("offline unlock");
    core.set_current_storage(first.to_string()).expect("first");
    assert!(core.item_get(first_item).is_ok());
    core.set_current_storage(remote.to_string())
        .expect("second");
    assert!(core.item_get(second_item).is_ok());
    let export = dir.path().join("both-accounts.json");
    let report = core
        .backup_export_file(export.to_str().expect("path").into())
        .expect("multi-account export");
    assert_eq!(report.items_count, 2);
    assert_eq!(core.verify().expect("verify").items_ok, 2);
}
