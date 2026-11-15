//! Two native accounts, one real HTTP endpoint, independent offline keys.
use super::*;
use std::time::{Duration, Instant};
use zann_client::app::local::RecoveryScope;
use zann_client::app::{
    AppClient, ClientId, ClientPaths, LoginPassword, PasswordLoginRequest,
    PrepareConnectionOutcome, SessionClient, SessionOperation,
};
use zann_client::config::ConfigRepository;
use zann_client_sqlite::SqliteSyncStoreFactory;

pub(super) fn operation() -> SessionOperation {
    SessionOperation::new(Instant::now() + Duration::from_secs(60)).0
}
pub(super) fn client(root: &Path, credentials: Arc<Credentials>) -> AppClient {
    let app = AppClient::new(
        ClientPaths::new(root),
        credentials.clone(),
        SessionClient::new(ClientId::new("desktop").unwrap()),
        Arc::new(SqliteSyncStoreFactory::new(&root.join("local.sqlite")).unwrap()),
    );
    app.initialize(credentials.as_ref()).unwrap();
    app
}
fn add_account(
    runtime: &tokio::runtime::Runtime,
    app: &AppClient,
    core: &LocalVault,
    url: &str,
    email: &str,
    encryption_password: &str,
) -> String {
    let prepared = runtime
        .block_on(app.prepare_account_connection(url, "Accounts test", None))
        .unwrap();
    let PrepareConnectionOutcome::Ready(prepared) = prepared else {
        panic!("unexpected trust change")
    };
    let request = PasswordLoginRequest::new(
        prepared.target().clone(),
        email,
        LoginPassword::new("Test password 123!").unwrap(),
    )
    .unwrap();
    runtime
        .block_on(app.password_login(request, operation()))
        .unwrap_or_else(|error| {
            use std::error::Error;
            panic!(
                "test authentication: {error}; diagnostic: {:?}",
                error.source()
            );
        });
    core.enroll_account_key(encryption_password.into()).unwrap();
    let storage = core.current_storage_id().unwrap();
    assert_eq!(storage, prepared.storage_id());
    core.remote_sync(Some(storage.clone()), None).unwrap();
    storage
}
pub(super) fn create_note(core: &LocalVault, marker: &str) {
    core.item_create(ItemCreate {
        title: marker.into(),
        path: format!("accounts/{marker}"),
        type_id: "note".into(),
        payload_json:
            json!({"v":1,"typeId":"note","fields":{"notes":{"kind":"text","value":marker}}})
                .to_string(),
    })
    .unwrap();
}
pub(super) fn export(core: &LocalVault, root: &Path, name: &str) -> Vec<Value> {
    let path = root.join(name);
    core.backup_export_file(path.display().to_string()).unwrap();
    normalized(&path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_accounts_one_endpoint_enroll_sync_restart_export_logout_and_remove_independently() {
    let app = server_app::TestApp::new_with_smk().await;
    app.register("first@example.test", "Test password 123!")
        .await;
    app.register("second@example.test", "Test password 123!")
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let router = app.router();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::task::spawn_blocking(move || {
        let root = tempdir();
        let credentials = Arc::new(Credentials::default());
        let core = open_with_credentials(root.path(), credentials.clone());
        core.initialize_master_password("test device unlock password".into())
            .unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let app = client(root.path(), credentials.clone());
        let first = add_account(
            &runtime,
            &app,
            &core,
            &url,
            "first@example.test",
            "first account encryption password",
        );
        create_note(&core, "first-only");
        core.remote_sync(Some(first.clone()), None).unwrap();
        let second = add_account(
            &runtime,
            &app,
            &core,
            &url,
            "second@example.test",
            "second account encryption password",
        );
        assert_ne!(first, second);
        create_note(&core, "second-only");
        core.remote_sync(Some(second.clone()), None).unwrap();
        let labels: std::collections::BTreeMap<_, _> = core
            .list_storages()
            .unwrap()
            .into_iter()
            .map(|storage| (storage.id, storage.account_name))
            .collect();
        assert_eq!(labels[&first].as_deref(), Some("first@example.test"));
        assert_eq!(labels[&second].as_deref(), Some("second@example.test"));
        let repository = ConfigRepository::new(ClientPaths::new(root.path()));
        let snapshot = repository.snapshot().unwrap();
        assert_eq!(snapshot.config().connections.len(), 1);
        let first_target = app.configured_target(Some(&first)).unwrap();
        let second_target = app.configured_target(Some(&second)).unwrap();
        assert_eq!(first_target.connection_id(), second_target.connection_id());
        assert_ne!(first_target.profile_name(), second_target.profile_name());
        let second_anchor = repository
            .resolve_credential_profile_anchor(
                second_target.connection_id(),
                second_target.profile_name(),
            )
            .unwrap();
        let first_anchor = repository
            .resolve_credential_profile_anchor(
                first_target.connection_id(),
                first_target.profile_name(),
            )
            .unwrap();
        assert_ne!(
            first_anchor.expected_master_key_fp(),
            second_anchor.expected_master_key_fp()
        );
        let expected = export(&core, root.path(), "before.json");
        assert_eq!(expected.len(), 2);
        core.lock().unwrap();
        drop(core);
        drop(app);
        let core = open_with_credentials(root.path(), credentials.clone());
        core.unlock("test device unlock password".into()).unwrap();
        assert_eq!(export(&core, root.path(), "after.json"), expected);
        for storage in [&first, &second] {
            core.set_current_storage(storage.clone()).unwrap();
            core.remote_sync(Some(storage.clone()), None).unwrap();
        }
        let app = client(root.path(), credentials);
        runtime
            .block_on(app.logout(&first_target, operation()))
            .unwrap();
        let after_logout = repository
            .resolve_credential_profile_anchor(
                second_target.connection_id(),
                second_target.profile_name(),
            )
            .unwrap();
        assert_eq!(after_logout.credentials(), second_anchor.credentials());
        assert_eq!(
            after_logout.server_fingerprint(),
            second_anchor.server_fingerprint()
        );
        core.set_current_storage(second.clone()).unwrap();
        core.remote_sync(Some(second.clone()), None).unwrap();
        let recovery = core
            .prepare_local_recovery(RecoveryScope::Account(first.clone()))
            .unwrap();
        assert!(
            core.confirm_local_recovery(recovery.id.clone(), false)
                .is_err(),
            "local history requires explicit discard acknowledgement"
        );
        core.confirm_local_recovery(recovery.id, true).unwrap();
        core.unlock("test device unlock password".into()).unwrap();
        core.set_current_storage(second.clone()).unwrap();
        core.remote_sync(Some(second), None).unwrap();
        let remaining = export(&core, root.path(), "remaining.json");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0]["path"], "accounts/second-only");
        assert!(core.verify().unwrap().problems.is_empty());
        assert!(core.set_current_storage(first).is_err());
    })
    .await
    .unwrap();
    server.abort();
}
