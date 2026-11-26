use super::*;
use zann_client::browser_ipc::PasskeyOperation;
use zann_db::local::KeyWrapType;
fn fixture() -> (tempfile::TempDir, Arc<LocalVault>) {
    let dir = tempfile::tempdir().expect("passkey fixture operation");
    let core = open_vault_at_path(
        &dir.path().join("local.sqlite"),
        LocalVaultPorts::system_default(),
    )
    .expect("passkey fixture operation");
    core.seed_offline_fixture("synthetic password".into())
        .expect("passkey fixture operation");
    (dir, core)
}
fn request() -> PasskeyRequest {
    PasskeyRequest {
        context: BrowserContext {
            top_level_url: "https://example.com".into(),
            frame_url: "https://example.com".into(),
        },
        rp_id: "example.com".into(),
        challenge: B64.encode([7; 32]),
        require_verification: false,
        operation: PasskeyOperation::Create {
            rp_name: "Example".into(),
            user_id: B64.encode([1; 16]),
            user_name: "alice".into(),
            user_display_name: "Alice".into(),
            algorithms: vec![-7],
            exclude_credentials: vec![],
        },
    }
}
fn scope(core: &LocalVault) -> BrowserScope {
    let mut scope = None;
    core.passkey_query(request(), &mut |matches| {
        scope = Some(matches.scope);
        Ok(())
    })
    .expect("passkey fixture operation");
    scope.expect("passkey fixture operation")
}
fn counts(core: &LocalVault) -> (i64, i64, i64, i64) {
    core.runtime.block_on(async {
        use zann_db::local::{LocalItemHistoryRepo, LocalItemRepo, PendingChangeRepo};
        let pool = core.pool();
        let storage = core.storage_id().expect("passkey fixture operation");
        let vault = core.vault_id().expect("passkey fixture operation");
        let items = LocalItemRepo::new(&pool)
            .list_by_vault(storage, vault, false)
            .await
            .expect("passkey fixture operation");
        let mut history = 0;
        let mut pending = 0;
        let mut versions = 0;
        for item in &items {
            history += LocalItemHistoryRepo::new(&pool)
                .list_by_item_limit(storage, vault, item.id, 100)
                .await
                .expect("passkey fixture operation")
                .len() as i64;
            pending += PendingChangeRepo::new(&pool)
                .list_by_item(storage, item.id)
                .await
                .expect("passkey fixture operation")
                .len() as i64;
            versions += item.version;
        }
        (items.len() as i64, history, pending, versions)
    })
}
#[test]
fn assertions_leave_item_history_pending_and_version_unchanged_and_hold_delivery_lease() {
    let (_dir, core) = fixture();
    let scope = scope(&core);
    core.passkey_ceremony(request(), scope.clone(), None, &mut |_| Ok(()))
        .expect("passkey fixture operation");
    assert_eq!(counts(&core), (1, 1, 1, 1));
    let mut get = request();
    get.operation = PasskeyOperation::Get {
        allow_credentials: vec![],
    };
    let mut selected = None;
    core.passkey_query(get.clone(), &mut |mut matches| {
        selected = Some(matches.items.remove(0).item_id);
        Ok(())
    })
    .expect("passkey fixture operation");
    let (send, recv) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let worker = core.clone();
    let ceremony = std::thread::spawn(move || {
        worker.passkey_ceremony(get, scope, selected, &mut |_| {
            send.send(()).expect("passkey fixture operation");
            wait.recv().expect("passkey fixture operation");
            Ok(())
        })
    });
    recv.recv_timeout(std::time::Duration::from_secs(5))
        .expect("passkey fixture operation");
    let worker = core.clone();
    let (done, locked) = std::sync::mpsc::channel();
    let lock = std::thread::spawn(move || {
        worker.lock().expect("passkey fixture operation");
        done.send(()).expect("passkey fixture operation");
    });
    assert!(locked
        .recv_timeout(std::time::Duration::from_millis(50))
        .is_err());
    release.send(()).expect("passkey fixture operation");
    ceremony
        .join()
        .expect("passkey fixture operation")
        .expect("passkey fixture operation");
    lock.join().expect("passkey fixture operation");
    core.unlock("synthetic password".into())
        .expect("passkey fixture operation");
    assert_eq!(counts(&core), (1, 1, 1, 1));
}
#[test]
fn failed_delivery_keeps_one_atomic_create_and_shared_vaults_are_refused() {
    let (_dir, core) = fixture();
    let scope = scope(&core);
    let error = core.passkey_ceremony(request(), scope, None, &mut |_| {
        Err(LocalError::BrowserDelivery(
            "synthetic dropped response".into(),
        ))
    });
    assert!(matches!(error, Err(LocalError::BrowserDelivery(_))));
    assert_eq!(counts(&core), (1, 1, 1, 1));
    let pool = core.pool();
    let mut vault = core
        .runtime
        .block_on(LocalVaultRepo::new(&pool).get_by_id(
            core.storage_id().expect("passkey fixture operation"),
            core.vault_id().expect("passkey fixture operation"),
        ))
        .expect("passkey fixture operation")
        .expect("passkey fixture operation");
    vault.id = Uuid::now_v7();
    vault.slug = "shared-test".into();
    vault.kind = zann_core::VaultKind::Shared;
    vault.key_wrap_type = KeyWrapType::RemoteServer;
    core.runtime
        .block_on(LocalVaultRepo::new(&pool).create(&vault))
        .expect("passkey fixture operation");
    core.set_current_vault(vault.id.to_string())
        .expect("passkey fixture operation");
    assert!(core
        .passkey_query(request(), &mut |_| panic!(
            "shared chooser must not be delivered"
        ))
        .is_err());
}
