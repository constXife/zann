//! Passwordless shared cache enrollment, crash retry and policy-change refusal.
use super::account_replicas::{client, create_note, export, operation};
use super::*;
use tower::ServiceExt;
use zann_client::app::unlock::DeviceUnlock;
use zann_client::app::AccountKeyOrigin;

fn connect_shared(core: &LocalVault, url: &str, login: &Value) -> String {
    let storage = uuid::Uuid::now_v7().to_string();
    core.import_legacy_account(
        url.into(),
        "Shared test".into(),
        storage.clone(),
        Some(storage.clone()),
        login["access_token"].as_str().unwrap().into(),
        login["refresh_token"].as_str().unwrap().into(),
        Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()),
    )
    .unwrap();
    storage
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_accounts_need_one_device_password_and_keep_cache_on_personal_policy_change() {
    let app = server_app::TestApp::new_shared_only_with_smk().await;
    let first = app
        .register("shared-first@example.test", "Test password 123!")
        .await;
    let second = app
        .register("shared-second@example.test", "Test password 123!")
        .await;
    app.create_shared_vault(first["access_token"].as_str().unwrap(), "first")
        .await;
    app.create_shared_vault(second["access_token"].as_str().unwrap(), "second")
        .await;
    let current = Arc::new(tokio::sync::RwLock::new(app.router()));
    let enabled = app.router_with_personal_policy(true);
    let router = axum::Router::new().fallback({
        let current = current.clone();
        move |request: axum::extract::Request| {
            let current = current.clone();
            async move { current.read().await.clone().oneshot(request).await.unwrap() }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::task::spawn_blocking(move || {
        let root = tempdir();
        let credentials = Arc::new(Credentials::default());
        let keystore = Arc::new(MemoryKeystore::default());
        let core = open_shared(root.path(), credentials.clone(), keystore.clone());
        let storage_a = connect_shared(&core, &url, &first);
        assert!(
            core.activate_connected_account().is_err(),
            "device password must be chosen explicitly"
        );
        core.initialize_master_password("test device unlock password".into())
            .unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let account_client = client(root.path(), credentials.clone());
        let target = account_client.configured_target(Some(&storage_a)).unwrap();
        assert!(
            account_client.account_identity(&target).is_err(),
            "no account KDF required"
        );
        // Crash/failed keyring CAS before publication must not pin a lost random key.
        let unfinished = runtime
            .block_on(account_client.prepare_account_key(
                &target,
                Arc::new(zann_crypto::SecretKey::generate()),
                AccountKeyOrigin::LocalCacheKey,
                None,
                operation(),
            ))
            .unwrap();
        drop(unfinished);
        assert!(
            zann_client::config::ConfigRepository::new(core.client_paths())
                .resolve_credential_profile_anchor(target.connection_id(), target.profile_name())
                .unwrap()
                .expected_master_key_fp()
                .is_none()
        );
        assert!(core.activate_connected_account().unwrap());
        core.remote_sync(Some(storage_a.clone()), None).unwrap();
        create_note(&core, "shared-first");
        core.remote_sync(Some(storage_a.clone()), None).unwrap();
        let storage_b = connect_shared(&core, &url, &second);
        assert!(
            core.activate_connected_account().unwrap(),
            "no second account password"
        );
        core.remote_sync(Some(storage_b.clone()), None).unwrap();
        create_note(&core, "shared-second");
        core.remote_sync(Some(storage_b.clone()), None).unwrap();
        let expected = export(&core, root.path(), "before.json");
        assert_eq!(expected.len(), 2);
        let names: Vec<_> = core
            .list_storages()
            .unwrap()
            .into_iter()
            .map(|s| s.account_name.unwrap())
            .collect();
        assert!(names.contains(&"shared-first@example.test".into()));
        assert!(names.contains(&"shared-second@example.test".into()));
        core.remember_with_keystore().unwrap();
        core.lock().unwrap();
        drop(core);
        let core = open_shared(root.path(), credentials, keystore);
        core.unlock_remembered().unwrap();
        assert_eq!(export(&core, root.path(), "restarted.json"), expected);
        // Capture the durable envelopes. Neither a mismatched binding nor enabled
        // personal policy may replace them or initialize a personal remote key.
        let pool = runtime
            .block_on(zann_db::open_existing_sqlite(
                &root.path().join("local.sqlite"),
            ))
            .unwrap();
        let repo = zann_db::local::MetadataRepo::new(pool.pool());
        let original = runtime
            .block_on(repo.get_value_bounded("device_keyring", 1024 * 1024))
            .unwrap()
            .unwrap();
        let keyring = DeviceUnlock::decode(&original).unwrap();
        assert!(keyring
            .accounts
            .values()
            .all(|e| e.origin == AccountKeyOrigin::LocalCacheKey));
        let device_root = keyring.open("test device unlock password").unwrap();
        let keys = keyring.account_keys(&device_root).unwrap();
        assert_ne!(keys[&storage_a].as_bytes(), keys[&storage_b].as_bytes());
        let mut missing = keyring.clone();
        missing.accounts.remove(&storage_b);
        let missing = serde_json::to_string(&missing).unwrap();
        assert!(runtime
            .block_on(repo.compare_exchange_value("device_keyring", Some(&original), &missing))
            .unwrap());
        assert!(
            core.activate_connected_account().is_err(),
            "new random key cannot take over a fingerprint"
        );
        assert_eq!(
            runtime
                .block_on(repo.get_value("device_keyring"))
                .unwrap()
                .as_deref(),
            Some(missing.as_str())
        );
        assert!(runtime
            .block_on(repo.compare_exchange_value("device_keyring", Some(&missing), &original))
            .unwrap());
        let mut forged = keyring.clone();
        forged.accounts.get_mut(&storage_b).unwrap().origin = AccountKeyOrigin::AccountPassword;
        let forged = serde_json::to_string(&forged).unwrap();
        assert!(runtime
            .block_on(repo.compare_exchange_value("device_keyring", Some(&original), &forged))
            .unwrap());
        assert!(
            core.remote_sync(Some(storage_b.clone()), None).is_err(),
            "unlocked process must authenticate the reread purpose"
        );
        assert!(runtime
            .block_on(repo.compare_exchange_value("device_keyring", Some(&forged), &original))
            .unwrap());
        core.set_current_storage(storage_b.clone()).unwrap();
        create_note(&core, "pending-before-policy-change");
        let pending = core.pending_change_count(storage_b.clone()).unwrap();
        assert!(pending > 0);
        let before_transition = export(&core, root.path(), "with-pending.json");
        runtime.block_on(async {
            *current.write().await = enabled;
        });
        let error = core.remote_sync(Some(storage_b.clone()), None).unwrap_err();
        let zann_client::app::local::LocalError::Sync { kind, .. } = error else {
            panic!("typed sync error");
        };
        assert_eq!(kind, "account_key_enrollment_required");
        let import = core
            .backup_import_file(
                root.path().join("with-pending.json").display().to_string(),
                storage_b.clone(),
                BackupImportOptions {
                    target_storage_id: Some(storage_b.clone()),
                },
            )
            .unwrap_err();
        let zann_client::app::local::LocalError::Backup { kind, .. } = import else {
            panic!("typed import error");
        };
        assert_eq!(kind, "account_key_enrollment_required");
        assert_eq!(
            core.pending_change_count(storage_b.clone()).unwrap(),
            pending
        );
        assert_eq!(
            runtime
                .block_on(repo.get_value("device_keyring"))
                .unwrap()
                .as_deref(),
            Some(original.as_str())
        );
        assert_eq!(
            export(&core, root.path(), "after-policy-change.json"),
            before_transition
        );
        assert!(core.verify().unwrap().problems.is_empty());
        // Complete the explicit policy transition in a fresh root. The full
        // device backup contains A+B, but only B may be restored into new B.
        let destination = tempdir();
        let destination_credentials = Arc::new(Credentials::default());
        let next = open_with_credentials(destination.path(), destination_credentials.clone());
        let next_client = client(destination.path(), destination_credentials);
        let zann_client::app::PrepareConnectionOutcome::Ready(prepared) = runtime
            .block_on(next_client.prepare_account_connection(&url, "Personal enabled", None))
            .unwrap()
        else {
            panic!("fresh trust");
        };
        runtime
            .block_on(
                next_client.password_login(
                    zann_client::app::PasswordLoginRequest::new(
                        prepared.target().clone(),
                        "shared-second@example.test",
                        zann_client::app::LoginPassword::new("Test password 123!").unwrap(),
                    )
                    .unwrap(),
                    operation(),
                ),
            )
            .unwrap();
        next.initialize_master_password("new device unlock password".into())
            .unwrap();
        assert!(
            !next.activate_connected_account().unwrap(),
            "explicit personal-key enrollment required"
        );
        next.enroll_account_key("explicit personal encryption password".into())
            .unwrap();
        next.remote_sync(None, None).unwrap();
        let new_storage = next.current_storage_id().unwrap();
        assert_ne!(new_storage, storage_b);
        let backup = root.path().join("with-pending.json").display().to_string();
        let options = || BackupImportOptions {
            target_storage_id: Some(new_storage.clone()),
        };
        let export_next = |name: &str| {
            let path = destination.path().join(name);
            let authorization = next
                .authorize_export(
                    zann_client::app::local::ExportStepUp::device_password(
                        "new device unlock password".into(),
                    ),
                    operation(),
                )
                .unwrap();
            next.backup_export_file(path.display().to_string(), authorization)
                .unwrap();
            normalized(&path)
        };
        let before_invalid_source = export_next("before-invalid-source.json");
        assert!(next
            .backup_import_file(backup.clone(), uuid::Uuid::now_v7().to_string(), options())
            .is_err());
        assert_eq!(
            export_next("after-invalid-source.json"),
            before_invalid_source
        );
        next.backup_import_file(backup, storage_b.clone(), options())
            .unwrap();
        let transferred = export_next("transferred.json");
        let expected_b: Vec<_> = before_transition
            .into_iter()
            .filter(|item| item["path"] != "accounts/shared-first")
            .collect();
        assert_eq!(
            transferred, expected_b,
            "account A must never be copied into B"
        );
        assert!(next.verify().unwrap().problems.is_empty());
        runtime.block_on(pool.pool().close());
    })
    .await
    .unwrap();
    server.abort();
}

#[derive(Default)]
struct MemoryKeystore(Mutex<Option<Vec<u8>>>);
impl zann_keystore::Keystore for MemoryKeystore {
    fn status(&self) -> zann_keystore::KeystoreStatus {
        zann_keystore::KeystoreStatus {
            supported: true,
            biometrics_available: false,
            reason: None,
            message: None,
        }
    }
    fn store_dwk(&self, key: &[u8]) -> Result<(), zann_keystore::KeystoreError> {
        *self.0.lock().unwrap() = Some(key.to_vec());
        Ok(())
    }
    fn load_dwk(&self) -> Result<Option<Vec<u8>>, zann_keystore::KeystoreError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn delete_dwk(&self) -> Result<(), zann_keystore::KeystoreError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}
fn open_shared(
    root: &Path,
    credentials: Arc<Credentials>,
    keystore: Arc<MemoryKeystore>,
) -> Arc<LocalVault> {
    LocalVault::open(
        zann_db::SqliteFileLocation::from_path(&root.join("local.sqlite")).unwrap(),
        LocalVaultPorts {
            backup_keys: Arc::new(zann_keystore::UnsupportedBiometricKeys),
            keystore,
            authenticator: Arc::new(zann_keystore::UnsupportedAuthenticator),
            credentials: credentials.clone(),
            legacy_credentials: credentials,
        },
    )
    .unwrap()
}
