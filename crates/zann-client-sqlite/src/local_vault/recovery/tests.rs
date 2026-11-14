use super::*;

fn fixture() -> (tempfile::TempDir, Arc<LocalVault>, String) {
    let dir = tempfile::tempdir().expect("root");
    let root = dir.path().canonicalize().expect("canonical root");
    let core = open_vault_at_path(
        &root.join("local.sqlite"),
        LocalVaultPorts::system_default(),
    )
    .expect("core");
    let password = Uuid::now_v7().to_string();
    core.seed_offline_fixture(password.clone())
        .expect("fixture");
    (dir, core, password)
}

#[test]
fn locked_account_forget_preserves_other_keys_and_recoverable_snapshot() {
    let _serial = super::super::MAINTENANCE_TEST_LOCK.lock().expect("serial");
    let (_dir, core, password) = fixture();
    let first = core.current_storage_id().expect("first");
    let item = core
        .debug_create_kv_item("unsent".into(), "key".into(), "value".into())
        .expect("item");
    let second = Uuid::now_v7().to_string();
    core.seed_offline_storage(
        second.clone(),
        "Other account".into(),
        "https://other.example.test".into(),
    )
    .expect("second");
    core.lock().expect("lock");
    let plan = core
        .prepare_local_recovery(RecoveryScope::Account(first.clone()))
        .expect("preview");
    assert_eq!(plan.accounts, 1);
    assert_eq!(plan.items, 1);
    assert!(plan.has_unsent());
    assert!(core.confirm_local_recovery(plan.id.clone(), false).is_err());
    let result = core.confirm_local_recovery(plan.id, true).expect("forget");
    assert!(!result.device_reset);
    assert!(core.app_status().expect("status").initialized);
    let rows = core.setup_accounts().expect("remaining");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].location.storage_id, second);
    assert!(rows[0].enrolled);
    core.unlock(password.clone()).expect("same device password");
    assert!(core
        .account_key_for_storage(Uuid::parse_str(&second).expect("uuid"))
        .is_ok());
    assert!(core
        .account_key_for_storage(Uuid::parse_str(&first).expect("uuid"))
        .is_err());
    core.snapshot_restore(result.snapshot_path)
        .expect("restore encrypted snapshot");
    core.unlock(password).expect("original password");
    core.set_current_storage(first).expect("original account");
    assert!(core.item_get(item).is_ok());
}

#[test]
fn same_cardinality_change_invalidates_preview_and_device_reset_invalidates_old_handles() {
    let _serial = super::super::MAINTENANCE_TEST_LOCK.lock().expect("serial");
    let (dir, core, _password) = fixture();
    let stale = open_vault_at_path(
        &dir.path()
            .canonicalize()
            .expect("root")
            .join("local.sqlite"),
        LocalVaultPorts::system_default(),
    )
    .expect("other handle");
    let plan = core
        .prepare_local_recovery(RecoveryScope::Device)
        .expect("preview");
    let pool = core.pool();
    let mut storage = core
        .runtime
        .block_on(LocalStorageRepo::new(&pool).list())
        .expect("storages")
        .remove(0);
    storage.name = "Changed".into();
    core.runtime
        .block_on(LocalStorageRepo::new(&pool).upsert(&storage))
        .expect("same count mutation");
    assert!(core.confirm_local_recovery(plan.id, true).is_err());
    assert_eq!(core.setup_accounts().expect("unchanged").len(), 1);
    let plan = core
        .prepare_local_recovery(RecoveryScope::Device)
        .expect("fresh preview");
    let outcome = core.confirm_local_recovery(plan.id, true).expect("reset");
    assert!(outcome.device_reset);
    assert!(!core.app_status().expect("status").initialized);
    assert!(!core.remembered_unlock().expect("remembered").armed);
    assert!(core.setup_accounts().expect("empty").is_empty());
    assert!(stale
        .initialize_master_password(Uuid::now_v7().to_string())
        .is_err());
    assert!(stale
        .runtime
        .block_on(zann_db::local::MetadataRepo::new(&stale.pool()).set_value("late", "write"))
        .is_err());
    core.initialize_master_password(Uuid::now_v7().to_string())
        .expect("fresh password");
}

#[test]
fn snapshot_failure_and_cancel_never_remove_local_data() {
    let _serial = super::super::MAINTENANCE_TEST_LOCK.lock().expect("serial");
    let (dir, core, password) = fixture();
    let plan = core
        .prepare_local_recovery(RecoveryScope::Device)
        .expect("preview");
    core.cancel_local_recovery(plan.id.clone()).expect("cancel");
    assert!(core.confirm_local_recovery(plan.id, true).is_err());
    let plan = core
        .prepare_local_recovery(RecoveryScope::Device)
        .expect("next preview");
    std::fs::write(dir.path().join("snapshots"), b"blocks snapshot directory")
        .expect("block snapshot");
    assert!(core.confirm_local_recovery(plan.id, true).is_err());
    assert!(core.app_status().expect("status").initialized);
    core.unlock(password)
        .expect("original password still works");
    assert_eq!(core.setup_accounts().expect("account preserved").len(), 1);
}
