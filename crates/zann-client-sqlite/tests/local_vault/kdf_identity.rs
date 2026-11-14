//! The device password and account encryption key have independent lifetimes.
use crate::support::CanonicalTempDir;
use zann_client_sqlite::local_vault::open_vault;

fn open(root: &std::path::Path) -> std::sync::Arc<zann_client_sqlite::local_vault::LocalVault> {
    open_vault(format!("sqlite://{}", root.join("local.sqlite").display())).expect("open")
}

#[test]
fn local_unlock_password_needs_no_server_account() {
    let root = CanonicalTempDir::new();
    let core = open(&root);
    assert!(!core.app_status().expect("status").initialized);
    core.initialize_master_password("device only password".into())
        .expect("initialize locally");
    assert!(core.list_storages().expect("storages").is_empty());
    core.lock().expect("lock");
    drop(core);
    let core = open(&root);
    assert!(
        core.unlock("device only password".into())
            .expect("offline unlock")
            .unlocked
    );
    let page = core
        .items_list(
            zann_client::app::local::ItemsFilter {
                query: None,
                include_deleted: false,
            },
            zann_client::app::local::Page {
                limit: 10,
                cursor: None,
            },
        )
        .expect("unlocked empty workspace");
    assert!(page.items.is_empty());
    assert_eq!(page.total_count, 0);
}

#[test]
fn failed_password_changes_preserve_the_existing_password_after_restart() {
    let root = CanonicalTempDir::new();
    let core = open(&root);
    core.seed_offline_fixture("original device password".into())
        .expect("fixture");
    assert!(core
        .change_unlock_password("wrong password".into(), "new device password".into())
        .is_err());
    assert!(core
        .change_unlock_password(
            "original device password".into(),
            " accidental space".into()
        )
        .is_err());
    drop(core);
    let core = open(&root);
    core.unlock("original device password".into())
        .expect("original still works");
}

#[test]
fn replacement_survives_restart_and_rejects_old_password() {
    let root = CanonicalTempDir::new();
    let core = open(&root);
    core.seed_offline_fixture("original device password".into())
        .expect("fixture");
    core.change_unlock_password(
        "original device password".into(),
        "new device password".into(),
    )
    .expect("change");
    drop(core);
    let core = open(&root);
    assert!(core.unlock("original device password".into()).is_err());
    assert!(!core.vault_status().expect("locked").unlocked);
    assert!(
        core.unlock("new device password".into())
            .expect("unlock")
            .unlocked
    );
    assert_eq!(core.list_vaults().expect("vaults").len(), 1);
}
