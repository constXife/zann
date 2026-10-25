use super::*;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use tempfile::TempDir;

type PutCallback = Box<dyn FnOnce() + Send>;

#[derive(Default)]
struct TestCredentialStore {
    values: Mutex<BTreeMap<String, String>>,
    validations: AtomicUsize,
    reads: AtomicUsize,
    puts: AtomicUsize,
    deletes: AtomicUsize,
    deleted_ids: Mutex<Vec<CredentialId>>,
    fail_deletes: AtomicBool,
    after_put: Mutex<Option<PutCallback>>,
}

impl TestCredentialStore {
    fn calls(&self) -> (usize, usize, usize, usize) {
        (
            self.validations.load(Ordering::SeqCst),
            self.reads.load(Ordering::SeqCst),
            self.puts.load(Ordering::SeqCst),
            self.deletes.load(Ordering::SeqCst),
        )
    }

    fn set_after_put(&self, callback: impl FnOnce() + Send + 'static) {
        *self.after_put.lock().expect("callback lock") = Some(Box::new(callback));
    }

    fn value(&self, credential_id: &CredentialId) -> Option<String> {
        self.values
            .lock()
            .expect("credential map lock")
            .get(credential_id.as_str())
            .cloned()
    }

    fn deleted_ids(&self) -> Vec<CredentialId> {
        self.deleted_ids.lock().expect("deleted ids lock").clone()
    }

    fn set_fail_deletes(&self, fail: bool) {
        self.fail_deletes.store(fail, Ordering::SeqCst);
    }
}

impl CredentialStore for TestCredentialStore {
    fn validate(
        &self,
        _credential_id: &CredentialId,
        _secret: &CredentialSecret,
    ) -> Result<(), CredentialPortError> {
        self.validations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn put(
        &self,
        credential_id: &CredentialId,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialPortError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        self.values.lock().expect("credential map lock").insert(
            credential_id.as_str().to_string(),
            secret.expose_secret().to_string(),
        );
        let callback = self.after_put.lock().expect("callback lock").take();
        if let Some(callback) = callback {
            callback();
        }
        Ok(())
    }

    fn get(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.values
            .lock()
            .expect("credential map lock")
            .get(credential_id.as_str())
            .cloned()
            .map(CredentialSecret::new)
            .transpose()
            .map_err(|error| CredentialPortError::new(error.to_string()))
    }

    fn delete(&self, credential_id: &CredentialId) -> Result<(), CredentialPortError> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        self.deleted_ids
            .lock()
            .expect("deleted ids lock")
            .push(credential_id.clone());
        if self.fail_deletes.load(Ordering::SeqCst) {
            return Err(CredentialPortError::new("injected delete failure"));
        }
        self.values
            .lock()
            .expect("credential map lock")
            .remove(credential_id.as_str());
        Ok(())
    }
}

struct EmptyLegacyCredentials;

impl LegacyCredentialSource for EmptyLegacyCredentials {
    fn get(
        &self,
        _locator: &LegacyCredentialLocator,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        Ok(None)
    }
}

fn repository(temp: &TempDir) -> ConfigRepository {
    ConfigRepository::new(ClientPaths::new(temp.path()))
}

fn client_id(value: &str) -> ClientId {
    ClientId::new(value).expect("client id")
}

fn initialize(repo: &ConfigRepository) {
    repo.initialize(
        &client_id("test"),
        &TestCredentialStore::default(),
        &EmptyLegacyCredentials,
    )
    .expect("initialize empty config");
}

fn identity(label: &str) -> ConfigIdentity {
    ConfigIdentity {
        kdf_salt: format!("salt-{label}"),
        kdf_params: ConfigKdfParams {
            algorithm: "argon2id".to_string(),
            iterations: 3,
            memory_kb: 64 * 1024,
            parallelism: 1,
        },
        salt_fingerprint: None,
        first_seen_at: None,
        email: None,
    }
}

fn endpoint(address: &str, server_id: &str, fingerprint: &str) -> VerifiedEndpointBinding {
    VerifiedEndpointBinding::new_for_test(address, server_id, fingerprint)
        .expect("verified endpoint")
}

fn stored_binding(
    address: &str,
    server_id: Option<&str>,
    fingerprint: Option<&str>,
    storage_id: Option<&str>,
) -> StoredConnectionBinding {
    StoredConnectionBinding::new(
        address,
        server_id.map(str::to_string),
        fingerprint.map(str::to_string),
        storage_id.map(str::to_string),
    )
}

fn bundle(value: &str) -> CredentialBundle {
    CredentialBundle::new(
        Some(CredentialSecret::new(value).expect("credential secret")),
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn commit(
    repo: &ConfigRepository,
    revision: u64,
    endpoint: VerifiedEndpointBinding,
    storage_id: Option<&str>,
    target: AuthenticatedConnectionTarget,
    identity: IdentityCommit,
    client: &str,
    profile: &str,
    secret: &str,
    store: &TestCredentialStore,
) -> Result<AuthenticatedSessionOutcome, ConfigError> {
    repo.commit_authenticated_session(
        revision,
        AuthenticatedSessionCommit::new(
            endpoint,
            storage_id.map(str::to_string),
            target,
            identity,
            client_id(client),
            profile,
            bundle(secret),
        ),
        store,
    )
}

#[test]
fn authenticated_targets_publish_complete_generations_and_preserve_metadata() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let callback_repo = repo.clone();
    store.set_after_put(move || {
        assert!(matches!(
            callback_repo.snapshot(),
            Err(ConfigError::CredentialRecoveryRequired { .. })
        ));
    });
    let config_identity = identity("targets");
    let created = commit(
        &repo,
        0,
        endpoint("https://AUTH.test:443/", "server-a", "pin-a"),
        Some("storage-a"),
        AuthenticatedConnectionTarget::Create {
            connection_name: "primary".to_string(),
        },
        IdentityCommit::InitializeOrMatch(config_identity.clone()),
        "desktop",
        "first",
        "first-secret",
        &store,
    )
    .expect("create authenticated connection");
    let connection_id = created.connection_id().clone();
    assert_eq!(created.snapshot().revision(), 1);
    assert_eq!(created.storage_id(), Some("storage-a"));
    assert_eq!(created.profile_name(), "first");
    assert_eq!(
        created.snapshot().config().identity,
        Some(config_identity.clone())
    );
    let connection = &created.snapshot().config().connections[&connection_id];
    assert_eq!(connection.metadata.address, "https://auth.test");
    assert_eq!(connection.metadata.server_id.as_deref(), Some("server-a"));
    assert_eq!(
        connection.metadata.server_fingerprint.as_deref(),
        Some("pin-a")
    );
    assert_eq!(connection.metadata.storage_id.as_deref(), Some("storage-a"));
    assert_eq!(connection.active_credential(), Some("first"));
    assert_eq!(
        created.snapshot().config().clients[&client_id("desktop")].active_connection(),
        Some(&connection_id)
    );
    let first_id =
        &connection.credential_profiles()["first"].credentials()[&CredentialKind::Access];
    assert_eq!(store.value(first_id).as_deref(), Some("first-secret"));

    let exact = stored_binding(
        "https://auth.test",
        Some("server-a"),
        Some("pin-a"),
        Some("storage-a"),
    );
    commit(
        &repo,
        1,
        endpoint("https://auth.test", "server-a", "pin-a"),
        Some("storage-a"),
        AuthenticatedConnectionTarget::UseExisting {
            connection_id: connection_id.clone(),
            expected: exact,
        },
        IdentityCommit::InitializeOrMatch(config_identity.clone()),
        "cli",
        "second",
        "second-secret",
        &store,
    )
    .expect("use exact authenticated binding");

    let unpinned_id = ConnectionId::deterministic("unpinned", "https://unpinned.test");
    let mut unpinned = ConnectionMetadata::new("unpinned", "https://unpinned.test");
    unpinned.needs_salt_update = true;
    unpinned.expected_master_key_fp = Some("master-key-fp".to_string());
    repo.upsert_connection(unpinned_id.clone(), unpinned)
        .expect("insert unpinned metadata");
    let pinned = commit(
        &repo,
        3,
        endpoint("https://unpinned.test", "server-b", "pin-b"),
        Some("storage-b"),
        AuthenticatedConnectionTarget::PinExisting {
            connection_id: unpinned_id.clone(),
            expected: stored_binding("https://unpinned.test", None, None, None),
        },
        IdentityCommit::InitializeOrMatch(config_identity.clone()),
        "cli",
        "pinned",
        "pinned-secret",
        &store,
    )
    .expect("pin previously unpinned connection");
    let pinned_metadata = pinned.snapshot().config().connections[&unpinned_id].metadata();
    assert!(pinned_metadata.needs_salt_update);
    assert_eq!(
        pinned_metadata.expected_master_key_fp.as_deref(),
        Some("master-key-fp")
    );

    commit(
        &repo,
        4,
        endpoint("https://auth.test", "server-a", "pin-a-2"),
        Some("storage-a"),
        AuthenticatedConnectionTarget::ReplaceFingerprint {
            connection_id: connection_id.clone(),
            expected: stored_binding(
                "https://auth.test",
                Some("server-a"),
                Some("pin-a"),
                Some("storage-a"),
            ),
        },
        IdentityCommit::InitializeOrMatch(config_identity.clone()),
        "desktop",
        "third",
        "third-secret",
        &store,
    )
    .expect("replace fingerprint under exact trust CAS");
    let relocated = commit(
        &repo,
        5,
        endpoint("https://new.test/base/", "server-a", "pin-a-3"),
        Some("storage-a"),
        AuthenticatedConnectionTarget::RelocateEndpoint {
            connection_id: connection_id.clone(),
            expected: stored_binding(
                "https://auth.test",
                Some("server-a"),
                Some("pin-a-2"),
                Some("storage-a"),
            ),
        },
        IdentityCommit::InitializeOrMatch(config_identity),
        "desktop",
        "fourth",
        "fourth-secret",
        &store,
    )
    .expect("relocate endpoint with the same signed server id");
    let relocated_connection = &relocated.snapshot().config().connections[&connection_id];
    assert_eq!(
        relocated_connection.metadata.address,
        "https://new.test/base"
    );
    assert_eq!(
        relocated_connection.metadata.server_fingerprint.as_deref(),
        Some("pin-a-3")
    );
    assert_eq!(relocated_connection.credential_profiles().len(), 4);
}

#[test]
fn authenticated_storage_is_optional_and_outcome_reports_the_effective_binding() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let config_identity = identity("optional-storage");
    let calls = store.calls();
    assert!(matches!(
        commit(
            &repo,
            0,
            endpoint("https://remote-only.test", "server-remote", "pin-remote"),
            Some(""),
            AuthenticatedConnectionTarget::Create {
                connection_name: "remote-only".to_string(),
            },
            IdentityCommit::InitializeOrMatch(config_identity.clone()),
            "cli",
            "invalid",
            "invalid-secret",
            &store,
        )
        .expect_err("Some storage id still requires validation"),
        ConfigError::InvalidConfig { .. }
    ));
    assert_eq!(store.calls(), calls);
    let created = commit(
        &repo,
        0,
        endpoint("https://remote-only.test", "server-remote", "pin-remote"),
        None,
        AuthenticatedConnectionTarget::Create {
            connection_name: "remote-only".to_string(),
        },
        IdentityCommit::InitializeOrMatch(config_identity.clone()),
        "cli",
        "first",
        "first-secret",
        &store,
    )
    .expect("DB-free create without storage");
    let connection_id = created.connection_id().clone();
    assert_eq!(created.storage_id(), None);
    assert_eq!(
        created.snapshot().config().connections[&connection_id]
            .metadata()
            .storage_id,
        None
    );

    let without_storage = stored_binding(
        "https://remote-only.test",
        Some("server-remote"),
        Some("pin-remote"),
        None,
    );
    let still_without_storage = commit(
        &repo,
        1,
        endpoint("https://remote-only.test", "server-remote", "pin-remote"),
        None,
        AuthenticatedConnectionTarget::UseExisting {
            connection_id: connection_id.clone(),
            expected: without_storage.clone(),
        },
        IdentityCommit::InitializeOrMatch(config_identity.clone()),
        "cli",
        "second",
        "second-secret",
        &store,
    )
    .expect("None preserves an existing None binding");
    assert_eq!(still_without_storage.storage_id(), None);

    let filled = commit(
        &repo,
        2,
        endpoint("https://remote-only.test", "server-remote", "pin-remote"),
        Some("storage-local"),
        AuthenticatedConnectionTarget::UseExisting {
            connection_id: connection_id.clone(),
            expected: without_storage,
        },
        IdentityCommit::InitializeOrMatch(config_identity.clone()),
        "desktop",
        "third",
        "third-secret",
        &store,
    )
    .expect("Some fills a previously absent storage binding");
    assert_eq!(filled.storage_id(), Some("storage-local"));

    let with_storage = stored_binding(
        "https://remote-only.test",
        Some("server-remote"),
        Some("pin-remote"),
        Some("storage-local"),
    );
    let preserved = commit(
        &repo,
        3,
        endpoint("https://remote-only.test", "server-remote", "pin-remote"),
        None,
        AuthenticatedConnectionTarget::UseExisting {
            connection_id: connection_id.clone(),
            expected: with_storage.clone(),
        },
        IdentityCommit::InitializeOrMatch(config_identity.clone()),
        "cli",
        "fourth",
        "fourth-secret",
        &store,
    )
    .expect("None preserves an existing Some binding");
    assert_eq!(preserved.storage_id(), Some("storage-local"));
    assert_eq!(
        preserved.snapshot().config().connections[&connection_id]
            .metadata()
            .storage_id
            .as_deref(),
        Some("storage-local")
    );

    let calls = store.calls();
    assert!(matches!(
        commit(
            &repo,
            4,
            endpoint("https://remote-only.test", "server-remote", "pin-remote"),
            Some("storage-replacement"),
            AuthenticatedConnectionTarget::UseExisting {
                connection_id,
                expected: with_storage,
            },
            IdentityCommit::InitializeOrMatch(config_identity),
            "cli",
            "replacement",
            "replacement-secret",
            &store,
        )
        .expect_err("Some cannot replace an existing storage binding"),
        ConfigError::AuthenticatedBindingConflict { .. }
    ));
    assert_eq!(store.calls(), calls);
}

#[test]
fn authenticated_conflicts_fail_before_ports_and_leave_primary_unchanged() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let config_identity = identity("conflicts");
    let created = commit(
        &repo,
        0,
        endpoint("https://one.test", "server-one", "pin-one"),
        Some("storage-one"),
        AuthenticatedConnectionTarget::Create {
            connection_name: "one".to_string(),
        },
        IdentityCommit::InitializeOrMatch(config_identity.clone()),
        "cli",
        "first",
        "first-secret",
        &store,
    )
    .expect("first connection");
    let before = fs::read(repo.paths().config()).expect("primary before conflict");
    let calls = store.calls();
    for (verified, target) in [
        (
            endpoint("https://ONE.test:443/", "other-server", "other-pin"),
            AuthenticatedConnectionTarget::Create {
                connection_name: "address-alias".to_string(),
            },
        ),
        (
            endpoint("https://two.test", "server-one", "other-pin"),
            AuthenticatedConnectionTarget::Create {
                connection_name: "server-alias".to_string(),
            },
        ),
    ] {
        assert!(matches!(
            commit(
                &repo,
                1,
                verified,
                Some("storage-two"),
                target,
                IdentityCommit::InitializeOrMatch(config_identity.clone()),
                "cli",
                "other",
                "other-secret",
                &store,
            )
            .expect_err("endpoint alias must fail"),
            ConfigError::AuthenticatedEndpointAlias { .. }
        ));
    }
    assert!(matches!(
        commit(
            &repo,
            1,
            endpoint("https://one.test", "server-one", "pin-one"),
            Some("storage-one"),
            AuthenticatedConnectionTarget::UseExisting {
                connection_id: created.connection_id().clone(),
                expected: stored_binding(
                    "https://wrong.test",
                    Some("server-one"),
                    Some("pin-one"),
                    Some("storage-one"),
                ),
            },
            IdentityCommit::InitializeOrMatch(config_identity),
            "cli",
            "other",
            "other-secret",
            &store,
        )
        .expect_err("stale stored binding must fail"),
        ConfigError::AuthenticatedBindingConflict { .. }
    ));
    assert_eq!(store.calls(), calls);
    assert_eq!(
        fs::read(repo.paths().config()).expect("unchanged primary"),
        before
    );
}

#[test]
fn authenticated_known_host_identity_and_storage_are_exact_cas() {
    let temp = TempDir::new().expect("tempdir");
    fs::write(
        temp.path().join(LEGACY_KNOWN_HOSTS_FILENAME),
        r#"{"https://KNOWN.test:443/":"pin-one"}"#,
    )
    .expect("known hosts");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let base_identity = identity("identity");
    let created = commit(
        &repo,
        0,
        endpoint("https://known.test", "server-one", "pin-one"),
        Some("storage-one"),
        AuthenticatedConnectionTarget::Create {
            connection_name: "known".to_string(),
        },
        IdentityCommit::InitializeOrMatch(base_identity.clone()),
        "desktop",
        "first",
        "first-secret",
        &store,
    )
    .expect("matching retained pin is consumed");
    assert!(created.snapshot().config().legacy_known_hosts.is_empty());
    let connection_id = created.connection_id().clone();
    commit(
        &repo,
        1,
        endpoint("https://known.test", "server-one", "pin-two"),
        Some("storage-one"),
        AuthenticatedConnectionTarget::ReplaceFingerprint {
            connection_id: connection_id.clone(),
            expected: stored_binding(
                "https://known.test",
                Some("server-one"),
                Some("pin-one"),
                Some("storage-one"),
            ),
        },
        IdentityCommit::InitializeOrMatch(base_identity.clone()),
        "desktop",
        "second",
        "second-secret",
        &store,
    )
    .expect("consumed legacy pin does not block explicit replacement");

    let mut enriched = base_identity.clone();
    enriched.email = Some("user@example.test".to_string());
    enriched.salt_fingerprint = Some("salt-fingerprint".to_string());
    commit(
        &repo,
        2,
        endpoint("https://known.test", "server-one", "pin-two"),
        Some("storage-one"),
        AuthenticatedConnectionTarget::UseExisting {
            connection_id: connection_id.clone(),
            expected: stored_binding(
                "https://known.test",
                Some("server-one"),
                Some("pin-two"),
                Some("storage-one"),
            ),
        },
        IdentityCommit::InitializeOrMatch(enriched.clone()),
        "desktop",
        "third",
        "third-secret",
        &store,
    )
    .expect("optional missing identity fields may enrich");
    let calls = store.calls();
    let mut conflict = enriched.clone();
    conflict.email = Some("other@example.test".to_string());
    assert!(matches!(
        commit(
            &repo,
            3,
            endpoint("https://known.test", "server-one", "pin-two"),
            Some("storage-one"),
            AuthenticatedConnectionTarget::UseExisting {
                connection_id: connection_id.clone(),
                expected: stored_binding(
                    "https://known.test",
                    Some("server-one"),
                    Some("pin-two"),
                    Some("storage-one"),
                ),
            },
            IdentityCommit::InitializeOrMatch(conflict),
            "desktop",
            "conflict",
            "conflict-secret",
            &store,
        )
        .expect_err("identity Some/Some mismatch"),
        ConfigError::AuthenticatedIdentityConflict { .. }
    ));
    assert_eq!(store.calls(), calls);

    let replacement = identity("replacement");
    commit(
        &repo,
        3,
        endpoint("https://known.test", "server-one", "pin-two"),
        Some("storage-one"),
        AuthenticatedConnectionTarget::UseExisting {
            connection_id: connection_id.clone(),
            expected: stored_binding(
                "https://known.test",
                Some("server-one"),
                Some("pin-two"),
                Some("storage-one"),
            ),
        },
        IdentityCommit::ReplaceExact {
            expected: enriched,
            replacement: replacement.clone(),
        },
        "desktop",
        "replacement",
        "replacement-secret",
        &store,
    )
    .expect("explicit exact identity replacement");
    assert_eq!(
        repo.snapshot().expect("snapshot").config().identity,
        Some(replacement.clone())
    );

    let other_id = ConnectionId::deterministic("other", "https://other.test");
    repo.upsert_connection(
        other_id.clone(),
        ConnectionMetadata::new("other", "https://other.test"),
    )
    .expect("insert second connection");
    let calls = store.calls();
    assert!(matches!(
        commit(
            &repo,
            5,
            endpoint("https://other.test", "server-two", "pin-other"),
            Some("storage-one"),
            AuthenticatedConnectionTarget::PinExisting {
                connection_id: other_id,
                expected: stored_binding("https://other.test", None, None, None),
            },
            IdentityCommit::InitializeOrMatch(replacement),
            "desktop",
            "other",
            "other-secret",
            &store,
        )
        .expect_err("storage id may not be reused"),
        ConfigError::StorageBindingConflict { .. }
    ));
    assert_eq!(store.calls(), calls);
}

#[test]
fn candidate_marker_without_credential_journal_recovers_by_revoking_only_source_ids() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = ConnectionId::deterministic("intent", "https://intent.test");
    let committed = repo
        .commit_authenticated_session(
            0,
            AuthenticatedSessionCommit::new(
                endpoint("https://intent.test", "server-intent", "pin-intent"),
                Some("storage-intent".to_string()),
                AuthenticatedConnectionTarget::Create {
                    connection_name: "intent".to_string(),
                },
                IdentityCommit::InitializeOrMatch(identity("intent")),
                client_id("test"),
                "default",
                CredentialBundle::new(
                    Some(CredentialSecret::new("old-access").expect("access")),
                    Some(CredentialSecret::new("old-refresh").expect("refresh")),
                    Some(CredentialSecret::new("service-secret").expect("service")),
                )
                .with_access_expires_at(Some("2026-08-16T11:00:00Z".to_string())),
            ),
            &store,
        )
        .expect("seed authenticated profile");
    assert_eq!(committed.connection_id(), &connection_id);
    repo.reconcile_credentials_with_operation_lock(&store)
        .expect("settle seed credential journal");
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "default")
        .expect("source anchor");
    let source_ids: BTreeSet<_> = anchor.credentials().values().cloned().collect();
    let mut permit = repo
        .prepare_auth_operation_intent_with_operation_locks(
            &anchor,
            AuthOperationKind::Refresh,
            "operation-marker-cut",
        )
        .expect("arm intent");
    let candidate_plan = repo
        .install_auth_rotation_candidate_without_credential_journal_for_test(
            &mut permit,
            CredentialSecret::new("new-access").expect("new access"),
            CredentialSecret::new("new-refresh").expect("new refresh"),
            "2026-08-16T13:00:00Z".to_string(),
            &store,
        )
        .expect("install candidate marker only");
    let candidate_ids = candidate_plan.credential_ids.clone();
    assert!(repo.paths().auth_operation_intent().exists());
    assert!(!repo.paths().credential_transaction_journal().exists());
    drop(permit);

    let (recovered, disposition) = repo
        .reconcile_auth_operation_with_operation_locks(&store)
        .expect("restart recovery");
    assert_eq!(disposition, AuthOperationRecoveryDisposition::SourceRevoked);
    let profiles = recovered.snapshot().config().connections[&connection_id].credential_profiles();
    assert!(
        profiles.get("default").is_none(),
        "profiles after recovery: {:?}",
        profiles.keys().collect::<Vec<_>>()
    );
    assert!(!repo.paths().auth_operation_intent().exists());
    // The normal credential journal may remain as the durable authority
    // for source ids still referenced by the backup generation.
    assert!(repo.paths().credential_transaction_journal().exists());
    assert!(matches!(
        repo.restore_backup(),
        Err(ConfigError::CredentialRecoveryRequired { .. })
    ));
    let deleted: BTreeSet<_> = store.deleted_ids().into_iter().collect();
    assert!(deleted.is_subset(&source_ids));
    assert!(candidate_ids
        .values()
        .all(|candidate| !deleted.contains(candidate)));
}

fn seed_auth_intent_profile(repo: &ConfigRepository, store: &TestCredentialStore) -> ConnectionId {
    let connection_id = ConnectionId::deterministic("intent", "https://intent.test");
    repo.commit_authenticated_session(
        0,
        AuthenticatedSessionCommit::new(
            endpoint("https://intent.test", "server-intent", "pin-intent"),
            Some("storage-intent".to_string()),
            AuthenticatedConnectionTarget::Create {
                connection_name: "intent".to_string(),
            },
            IdentityCommit::InitializeOrMatch(identity("intent")),
            client_id("test"),
            "default",
            CredentialBundle::new(
                Some(CredentialSecret::new("old-access").expect("access")),
                Some(CredentialSecret::new("old-refresh").expect("refresh")),
                Some(CredentialSecret::new("service-secret").expect("service")),
            )
            .with_access_expires_at(Some("2026-08-16T11:00:00Z".to_string())),
        ),
        store,
    )
    .expect("seed authenticated profile");
    connection_id
}

#[test]
fn authorized_generation_proves_the_temporary_single_target_topology() {
    let profile_temp = TempDir::new().expect("profile tempdir");
    let profile_repo = repository(&profile_temp);
    initialize(&profile_repo);
    let profile_store = TestCredentialStore::default();
    let profile_connection = seed_auth_intent_profile(&profile_repo, &profile_store);
    let exact_anchor = profile_repo
        .resolve_credential_profile_anchor(&profile_connection, "default")
        .expect("exact topology anchor");
    let exact = profile_repo
        .authorized_target_generation_from_anchor(&exact_anchor)
        .expect("exact topology generation");
    assert!(exact.single_target_topology());

    let revision = profile_repo
        .snapshot()
        .expect("profile snapshot")
        .revision();
    profile_repo
        .replace_credential_bundle(
            revision,
            &profile_connection,
            "secondary",
            bundle("secondary-secret"),
            CredentialActivation::Preserve,
            &profile_store,
        )
        .expect("add second profile");
    let multi_profile_anchor = profile_repo
        .resolve_credential_profile_anchor(&profile_connection, "default")
        .expect("multi-profile anchor");
    let multi_profile = profile_repo
        .authorized_target_generation_from_anchor(&multi_profile_anchor)
        .expect("multi-profile generation");
    assert!(!multi_profile.single_target_topology());
    assert_ne!(
        exact.stable_target_fingerprint(),
        multi_profile.stable_target_fingerprint(),
        "the stable proof must bind the topology decision"
    );

    let connection_temp = TempDir::new().expect("connection tempdir");
    let connection_repo = repository(&connection_temp);
    initialize(&connection_repo);
    let connection_store = TestCredentialStore::default();
    let selected_connection = seed_auth_intent_profile(&connection_repo, &connection_store);
    let selected_anchor = connection_repo
        .resolve_credential_profile_anchor(&selected_connection, "default")
        .expect("selected anchor");
    let selected = connection_repo
        .authorized_target_generation_from_anchor(&selected_anchor)
        .expect("selected exact generation");
    assert!(selected.single_target_topology());

    let other = ConnectionId::deterministic("other", "https://other-topology.test");
    connection_repo
        .upsert_connection(
            other,
            ConnectionMetadata::new("Other", "https://other-topology.test"),
        )
        .expect("add second connection");
    let multi_connection_anchor = connection_repo
        .resolve_credential_profile_anchor(&selected_connection, "default")
        .expect("multi-connection anchor");
    let multi_connection = connection_repo
        .authorized_target_generation_from_anchor(&multi_connection_anchor)
        .expect("multi-connection generation");
    assert!(!multi_connection.single_target_topology());
    assert_ne!(
        selected.stable_target_fingerprint(),
        multi_connection.stable_target_fingerprint(),
        "adding a connection must change the stable topology proof"
    );
}

#[cfg(feature = "session")]
#[tokio::test(flavor = "current_thread")]
async fn sync_generation_rejects_same_revision_raw_rewrite() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = seed_auth_intent_profile(&repo, &store);
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "default")
        .expect("source anchor");
    let generation = repo
        .authorized_target_generation_from_anchor(&anchor)
        .expect("authorized generation");

    let mut raw = fs::read(repo.paths().config()).expect("read raw config");
    raw.push(b'\n');
    fs::write(repo.paths().config(), raw).expect("rewrite same revision with new bytes");

    assert!(matches!(
        repo.acquire_sync_commit_lease(&generation).await,
        Err(ConfigError::ConfigContentConflict { revision })
            if revision == anchor.source_revision()
    ));
}

#[cfg(feature = "session")]
#[tokio::test(flavor = "current_thread")]
async fn sync_lease_releases_config_but_blocks_config_writer_at_shared_gate() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = seed_auth_intent_profile(&repo, &store);
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "default")
        .expect("source anchor");
    let generation = repo
        .authorized_target_generation_from_anchor(&anchor)
        .expect("authorized generation");
    let lease = repo
        .acquire_sync_commit_lease(&generation)
        .await
        .expect("exact sync lease");

    let config = LockKind::Config
        .pending_at(repo.paths().root())
        .expect("open config lock while lease is held")
        .acquire_blocking(Duration::from_millis(100))
        .expect("lease releases config after exact validation");
    drop(config);

    let error = repo
        .snapshot()
        .expect_err("config repository writer/read must enter through shared sync gate");
    assert!(matches!(
        error,
        ConfigError::Busy { path, .. } if path == repo.paths().sync_commit_lock()
    ));
    drop(lease);
    repo.snapshot().expect("writer proceeds after lease drop");
}

#[cfg(feature = "session")]
#[tokio::test(flavor = "current_thread")]
async fn sync_lease_is_repository_bound_and_refuses_every_recovery_barrier() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = seed_auth_intent_profile(&repo, &store);
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "default")
        .expect("source anchor");
    let generation = repo
        .authorized_target_generation_from_anchor(&anchor)
        .expect("authorized generation");

    let other_temp = TempDir::new().expect("other tempdir");
    let other = repository(&other_temp);
    initialize(&other);
    assert!(matches!(
        other.acquire_sync_commit_lease(&generation).await,
        Err(ConfigError::CredentialProfileAnchorRepositoryMismatch)
    ));

    fs::write(repo.paths().auth_operation_intent(), b"{}").expect("arm auth barrier");
    assert!(matches!(
        repo.acquire_sync_commit_lease(&generation).await,
        Err(ConfigError::AuthOperationRecoveryRequired { .. })
    ));
    fs::remove_file(repo.paths().auth_operation_intent()).expect("clear auth barrier");

    fs::write(repo.paths().credential_transaction_journal(), b"{}")
        .expect("arm credential barrier");
    assert!(repo.acquire_sync_commit_lease(&generation).await.is_err());
    fs::remove_file(repo.paths().credential_transaction_journal())
        .expect("clear credential barrier");

    fs::write(repo.paths().restore_journal(), b"{}").expect("arm restore barrier");
    assert!(matches!(
        repo.acquire_sync_commit_lease(&generation).await,
        Err(ConfigError::RestoreJournalConflict { .. })
    ));
}

#[test]
fn committed_candidate_restart_preserves_rotation_and_service_slot() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = seed_auth_intent_profile(&repo, &store);
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "default")
        .expect("source anchor");
    let service_id = anchor.credentials()[&CredentialKind::ServiceAccount].clone();
    let mut permit = repo
        .prepare_auth_operation_intent_with_operation_locks(
            &anchor,
            AuthOperationKind::Refresh,
            "operation-committed-cut",
        )
        .expect("arm intent");
    let plan = repo
        .install_auth_rotation_candidate_without_credential_journal_for_test(
            &mut permit,
            CredentialSecret::new("new-access").expect("new access"),
            CredentialSecret::new("new-refresh").expect("new refresh"),
            "2026-08-16T13:00:00Z".to_string(),
            &store,
        )
        .expect("candidate marker");
    let expected_revision = plan.journal.source_primary.revision;
    let bundle = CredentialBundle::new(
        Some(CredentialSecret::new("new-access").expect("new access")),
        Some(CredentialSecret::new("new-refresh").expect("new refresh")),
        None,
    )
    .with_access_expires_at(Some("2026-08-16T13:00:00Z".to_string()));
    {
        let _lock = repo.exclusive_lock().expect("config lock");
        repo.install_credential_transaction_intent_locked(expected_revision, &plan)
            .expect("install credential journal");
    }
    repo.execute_installed_credential_transaction_plan(
        expected_revision,
        Some(&bundle),
        plan,
        &store,
    )
    .expect("publish candidate without clearing auth intent");
    assert!(repo.paths().auth_operation_intent().exists());
    drop(permit);

    let (_outcome, disposition) = repo
        .reconcile_auth_operation_with_operation_locks(&store)
        .expect("restart candidate recovery");
    assert_eq!(
        disposition,
        AuthOperationRecoveryDisposition::CandidatePreserved
    );
    let current = repo
        .resolve_credential_profile_anchor(&connection_id, "default")
        .expect("candidate anchor");
    assert_eq!(
        current.credentials()[&CredentialKind::ServiceAccount],
        service_id
    );
    assert_eq!(current.access_expires_at(), Some("2026-08-16T13:00:00Z"));
    assert!(!repo.paths().auth_operation_intent().exists());
}

#[test]
fn removed_target_restart_accepts_revoke_and_clears_auth_intent() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = seed_auth_intent_profile(&repo, &store);
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "default")
        .expect("source anchor");
    let permit = repo
        .prepare_auth_operation_intent_with_operation_locks(
            &anchor,
            AuthOperationKind::Logout,
            "operation-removed-cut",
        )
        .expect("arm logout intent");
    repo.remove_credential_profile_if_matches_with_operation_lock(
        &anchor,
        ActiveCredentialAfterRemoval::Clear,
        &store,
    )
    .expect("publish revoke without clearing auth intent");
    assert!(repo.paths().auth_operation_intent().exists());
    drop(permit);

    let (_outcome, disposition) = repo
        .reconcile_auth_operation_with_operation_locks(&store)
        .expect("restart removed-target recovery");
    assert_eq!(disposition, AuthOperationRecoveryDisposition::TargetRemoved);
    assert!(!repo.paths().auth_operation_intent().exists());
    assert!(matches!(
        repo.restore_backup(),
        Err(ConfigError::CredentialRecoveryRequired { .. })
    ));
}

fn password_login_identity() -> ConfigIdentity {
    let mut value = identity("intent");
    value.email = Some("person@example.test".to_string());
    value
}

#[test]
fn armed_password_login_with_absent_profile_abandons_without_credential_deletes() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = seed_auth_intent_profile(&repo, &store);
    repo.reconcile_credentials_with_operation_lock(&store)
        .expect("settle seed journal");
    let anchor = repo
        .resolve_password_login_anchor(&connection_id, "password", &client_id("test"))
        .expect("absent-profile login anchor");
    let permit = repo
        .prepare_password_login_intent_with_operation_locks(
            &anchor,
            &endpoint("https://intent.test", "server-intent", "pin-intent"),
            password_login_identity(),
            "operation-password-armed",
            &store,
        )
        .expect("arm password login");
    let calls_after_arm = store.calls();
    let deleted_before = store.deleted_ids();
    drop(permit);

    let (outcome, disposition) = repo
        .reconcile_auth_operation_with_operation_locks(&store)
        .expect("restart abandons armed login");
    assert_eq!(
        disposition,
        AuthOperationRecoveryDisposition::LoginAbandoned
    );
    assert_eq!(store.calls(), calls_after_arm);
    assert_eq!(store.deleted_ids(), deleted_before);
    assert!(!repo.paths().auth_operation_intent().exists());
    assert!(outcome.snapshot().config().connections[&connection_id]
        .credential_profiles()
        .get("password")
        .is_none());
}

#[test]
fn absent_password_login_target_in_descendant_clears_without_credential_io() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = seed_auth_intent_profile(&repo, &store);
    repo.reconcile_credentials_with_operation_lock(&store)
        .expect("settle seed journal");
    let anchor = repo
        .resolve_password_login_anchor(&connection_id, "password", &client_id("test"))
        .expect("absent-profile login anchor");
    let permit = repo
        .prepare_password_login_intent_with_operation_locks(
            &anchor,
            &endpoint("https://intent.test", "server-intent", "pin-intent"),
            password_login_identity(),
            "operation-password-removed",
            &store,
        )
        .expect("arm password login");
    let calls_after_arm = store.calls();
    let deleted_before = store.deleted_ids();

    // Simulate a separately durable, later config generation in which the login target is
    // still absent. Recovery may accept that absence, but must never infer ownership of the
    // reserved IDs from the auth intent alone.
    let mut descendant = repo.snapshot().expect("source snapshot").config().clone();
    descendant.revision = descendant
        .revision
        .checked_add(1)
        .expect("revision advance");
    descendant.legacy_known_hosts.insert(
        "https://descendant.test".to_string(),
        "descendant-pin".to_string(),
    );
    atomic_write(
        &repo.paths().config(),
        &serialize_config(&descendant).expect("serialize descendant"),
    )
    .expect("publish descendant");
    drop(permit);

    let (_outcome, disposition) = repo
        .reconcile_auth_operation_with_operation_locks(&store)
        .expect("restart accepts absent target");
    assert_eq!(disposition, AuthOperationRecoveryDisposition::TargetRemoved);
    assert_eq!(store.calls(), calls_after_arm);
    assert_eq!(store.deleted_ids(), deleted_before);
    assert!(!repo.paths().auth_operation_intent().exists());
}

#[test]
fn password_login_candidate_marker_without_credential_journal_abandons_source() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = seed_auth_intent_profile(&repo, &store);
    repo.reconcile_credentials_with_operation_lock(&store)
        .expect("settle seed journal");
    let anchor = repo
        .resolve_password_login_anchor(&connection_id, "password", &client_id("test"))
        .expect("absent-profile login anchor");
    let mut permit = repo
        .prepare_password_login_intent_with_operation_locks(
            &anchor,
            &endpoint("https://intent.test", "server-intent", "pin-intent"),
            password_login_identity(),
            "operation-password-marker",
            &store,
        )
        .expect("arm password login");
    let bundle = CredentialBundle::new(
        Some(CredentialSecret::new("new-access").expect("access")),
        Some(CredentialSecret::new("new-refresh").expect("refresh")),
        None,
    )
    .with_access_expires_at(Some("2026-08-16T13:00:00Z".to_string()));
    let plan = repo
        .install_password_login_candidate_without_credential_journal_for_test(
            &mut permit,
            "018f4f08-7f1d-7d57-bd43-bb4b7c520001",
            &bundle,
            &store,
        )
        .expect("candidate marker only");
    let reserved: BTreeSet<_> = plan.credential_ids.values().cloned().collect();
    assert!(!repo.paths().credential_transaction_journal().exists());
    let deletes_before = store.deleted_ids();
    drop(permit);

    let (_outcome, disposition) = repo
        .reconcile_auth_operation_with_operation_locks(&store)
        .expect("restart abandons marker-only login");
    assert_eq!(
        disposition,
        AuthOperationRecoveryDisposition::LoginAbandoned
    );
    let deleted: BTreeSet<_> = store.deleted_ids().into_iter().collect();
    assert_eq!(deleted, deletes_before.into_iter().collect());
    assert!(reserved.iter().all(|id| !deleted.contains(id)));
    assert!(!repo.paths().auth_operation_intent().exists());
}

#[test]
fn committed_password_login_candidate_is_preserved_with_exact_binding_and_service_slot() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = seed_auth_intent_profile(&repo, &store);
    repo.reconcile_credentials_with_operation_lock(&store)
        .expect("settle seed journal");
    let source = repo
        .resolve_credential_profile_anchor(&connection_id, "default")
        .expect("source profile");
    let service_id = source.credentials()[&CredentialKind::ServiceAccount].clone();
    let anchor = repo
        .resolve_password_login_anchor(&connection_id, "default", &client_id("test"))
        .expect("present-profile login anchor");
    let mut permit = repo
        .prepare_password_login_intent_with_operation_locks(
            &anchor,
            &endpoint("https://intent.test", "server-intent", "pin-intent"),
            password_login_identity(),
            "operation-password-committed",
            &store,
        )
        .expect("arm password login");
    let bundle = CredentialBundle::new(
        Some(CredentialSecret::new("new-access").expect("access")),
        Some(CredentialSecret::new("new-refresh").expect("refresh")),
        None,
    )
    .with_access_expires_at(Some("2026-08-16T13:00:00Z".to_string()));
    let plan = repo
        .install_password_login_candidate_without_credential_journal_for_test(
            &mut permit,
            "018f4f08-7f1d-7d57-bd43-bb4b7c520001",
            &bundle,
            &store,
        )
        .expect("candidate marker");
    let expected_revision = plan.journal.source_primary.revision;
    {
        let _lock = repo.exclusive_lock().expect("config lock");
        repo.install_credential_transaction_intent_locked(expected_revision, &plan)
            .expect("install credential journal");
    }
    repo.execute_installed_credential_transaction_plan(
        expected_revision,
        Some(&bundle),
        plan,
        &store,
    )
    .expect("publish candidate while retaining auth intent");
    drop(permit);

    let (_outcome, disposition) = repo
        .reconcile_auth_operation_with_operation_locks(&store)
        .expect("restart preserves candidate");
    assert_eq!(
        disposition,
        AuthOperationRecoveryDisposition::CandidatePreserved
    );
    let candidate_snapshot = repo.snapshot().expect("candidate snapshot");
    let profile =
        &candidate_snapshot.config().connections[&connection_id].credential_profiles()["default"];
    assert_eq!(
        profile.account_subject(),
        Some("018f4f08-7f1d-7d57-bd43-bb4b7c520001")
    );
    assert_eq!(profile.auth_method(), Some(AuthMethod::Password));
    assert_eq!(
        profile.credentials()[&CredentialKind::ServiceAccount],
        service_id
    );
    assert!(!repo.paths().auth_operation_intent().exists());
}

#[test]
fn password_login_rebases_unrelated_revision_but_rejects_same_revision_aba() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = seed_auth_intent_profile(&repo, &store);
    repo.reconcile_credentials_with_operation_lock(&store)
        .expect("settle seed journal");
    let anchor = repo
        .resolve_password_login_anchor(&connection_id, "password", &client_id("test"))
        .expect("login anchor");
    repo.mutate(None, |config| {
        config.legacy_known_hosts.insert(
            "https://unrelated.test".to_string(),
            "unrelated-pin".to_string(),
        );
        Ok(())
    })
    .expect("unrelated revision advance");
    let permit = repo
        .prepare_password_login_intent_with_operation_locks(
            &anchor,
            &endpoint("https://intent.test", "server-intent", "pin-intent"),
            password_login_identity(),
            "operation-password-rebase",
            &store,
        )
        .expect("unrelated revision rebases");
    drop(permit);
    repo.reconcile_auth_operation_with_operation_locks(&store)
        .expect("clear rebased intent");

    let aba_anchor = repo
        .resolve_password_login_anchor(&connection_id, "password", &client_id("test"))
        .expect("ABA anchor");
    let mut tampered = repo.snapshot().expect("ABA source").config().clone();
    tampered
        .legacy_known_hosts
        .insert("https://aba.test".to_string(), "aba-pin".to_string());
    atomic_write(
        &repo.paths().config(),
        &serialize_config(&tampered).expect("serialize ABA config"),
    )
    .expect("publish same-revision ABA");
    let error = match repo.prepare_password_login_intent_with_operation_locks(
        &aba_anchor,
        &endpoint("https://intent.test", "server-intent", "pin-intent"),
        password_login_identity(),
        "operation-password-aba",
        &store,
    ) {
        Ok(_) => panic!("same-revision content change must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, ConfigError::ConfigContentConflict { .. }));
    assert!(!repo.paths().auth_operation_intent().exists());
}

#[test]
fn published_password_candidate_proof_normalizes_legacy_endpoint_address() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = seed_auth_intent_profile(&repo, &store);
    repo.reconcile_credentials_with_operation_lock(&store)
        .expect("settle seed journal");
    repo.mutate(None, |config| {
        config
            .connections
            .get_mut(&connection_id)
            .expect("connection")
            .metadata
            .address = "https://intent.test/".to_string();
        Ok(())
    })
    .expect("retain legacy noncanonical address");
    let anchor = repo
        .resolve_password_login_anchor(&connection_id, "password", &client_id("test"))
        .expect("normalized login anchor");
    let mut permit = repo
        .prepare_password_login_intent_with_operation_locks(
            &anchor,
            &endpoint("https://intent.test", "server-intent", "pin-intent"),
            password_login_identity(),
            "operation-password-visible-unlink",
            &store,
        )
        .expect("arm login");
    let bundle = CredentialBundle::new(
        Some(CredentialSecret::new("new-access").expect("access")),
        Some(CredentialSecret::new("new-refresh").expect("refresh")),
        None,
    )
    .with_access_expires_at(Some("2026-08-16T13:00:00Z".to_string()));
    let plan = repo
        .install_password_login_candidate_without_credential_journal_for_test(
            &mut permit,
            "018f4f08-7f1d-7d57-bd43-bb4b7c520001",
            &bundle,
            &store,
        )
        .expect("candidate marker");
    let expected_revision = plan.journal.source_primary.revision;
    {
        let _lock = repo.exclusive_lock().expect("config lock");
        repo.install_credential_transaction_intent_locked(expected_revision, &plan)
            .expect("credential journal");
    }
    repo.execute_installed_credential_transaction_plan(
        expected_revision,
        Some(&bundle),
        plan,
        &store,
    )
    .expect("publish candidate");
    fs::remove_file(repo.paths().auth_operation_intent()).expect("simulate visible unlink");
    sync_parent(repo.paths().root()).expect("sync visible unlink");

    assert!(repo
        .password_login_candidate_is_published_with_operation_locks(&permit)
        .expect("candidate proof")
        .is_some());
}

fn valid_auth_intent(root: &Path) -> AuthOperationIntent {
    AuthOperationIntent {
        journal_version: AUTH_OPERATION_INTENT_V1,
        operation_id: "operation-parser".to_string(),
        operation: AuthOperationKind::Logout,
        state: AuthOperationIntentState::Armed,
        repository_binding_digest: credential_profile_anchor_repository_binding(root)
            .expect("repository binding"),
        connection_id: ConnectionId::deterministic("intent", "https://intent.test"),
        profile_name: "default".to_string(),
        endpoint: AuthIntentEndpoint {
            address: normalize_address("https://intent.test", "$.test.address")
                .expect("canonical address"),
            server_id: "server-intent".to_string(),
            server_fingerprint: "pin-intent".to_string(),
            storage_id: Some("storage-intent".to_string()),
        },
        source: AuthIntentSource {
            revision: 7,
            raw_digest: format!("sha256:{}", "a".repeat(64)),
            account_subject: Some("user@example.test".to_string()),
            auth_method: None,
            access_expires_at: Some("2026-08-16T12:00:00Z".to_string()),
            credentials: BTreeMap::from([(
                CredentialKind::Refresh,
                CredentialId::from_serialized(format!("cred_{}", "b".repeat(64)))
                    .expect("credential id"),
            )]),
            profile_present: None,
            client_present: None,
            active_profile: None,
            client_active_connection: None,
        },
        candidate_rotation: None,
        client_id: None,
        reserved_login: None,
        candidate_login: None,
    }
}

#[test]
fn credential_anchor_and_auth_intent_protect_stable_profile_binding() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let mut protected_identity = identity("subject");
    protected_identity.email = Some("user@example.test".to_string());
    let committed = repo
        .commit_authenticated_session(
            0,
            AuthenticatedSessionCommit::new(
                endpoint("https://subject.test", "server-subject", "pin-subject"),
                Some("storage-subject".to_string()),
                AuthenticatedConnectionTarget::Create {
                    connection_name: "subject".to_string(),
                },
                IdentityCommit::InitializeOrMatch(protected_identity),
                client_id("test"),
                "default",
                CredentialBundle::new(
                    Some(CredentialSecret::new("access").expect("access")),
                    Some(CredentialSecret::new("refresh").expect("refresh")),
                    None,
                )
                .with_access_expires_at(Some("2026-08-16T12:00:00Z".to_string())),
            ),
            &store,
        )
        .expect("seed subject-bound session");
    repo.reconcile_credentials_with_operation_lock(&store)
        .expect("settle credential journal");
    let subject = "018f4f08-7f1d-7d57-bd43-bb4b7c520001";
    let mut bound = repo.snapshot().expect("bound snapshot").config().clone();
    let bound_connection = bound
        .connections
        .get_mut(committed.connection_id())
        .expect("bound connection");
    bound_connection.metadata.expected_master_key_fp = Some("0123456789ab".to_string());
    let bound_profile = bound_connection
        .credential_profiles
        .get_mut("default")
        .expect("bound profile");
    bound_profile.account_subject = Some(subject.to_string());
    bound_profile.auth_method = Some(AuthMethod::Password);
    bound.revision += 1;
    atomic_write(
        &repo.paths().config(),
        &serialize_config(&bound).expect("serialize bound config"),
    )
    .expect("publish bound config");
    let anchor = repo
        .resolve_credential_profile_anchor(committed.connection_id(), "default")
        .expect("subject-bound anchor");
    assert_eq!(anchor.expected_master_key_fp(), Some("0123456789ab"));
    assert_eq!(anchor.account_subject(), Some(subject));
    assert_eq!(anchor.auth_method(), Some(AuthMethod::Password));

    let permit = repo
        .prepare_auth_operation_intent_with_operation_locks(
            &anchor,
            AuthOperationKind::Refresh,
            "operation-subject",
        )
        .expect("arm subject-bound intent");
    let bytes = fs::read(repo.paths().auth_operation_intent()).expect("read auth intent");
    let intent = parse_auth_operation_intent(&repo.paths().auth_operation_intent(), &bytes)
        .expect("parse auth intent");
    assert_eq!(intent.source.account_subject.as_deref(), Some(subject));
    {
        let _lock = repo
            .exclusive_lock_allow_credential_journal()
            .expect("config lock");
        repo.ensure_owned_auth_operation_intent_locked(&permit)
            .expect("auth permit reconstructs without changing the v1/v2 wire document");
    }
    drop(permit);

    let mut changed = repo.snapshot().expect("snapshot").config().clone();
    changed.revision = anchor.source_revision + 1;
    changed
        .connections
        .get_mut(committed.connection_id())
        .expect("changed connection")
        .credential_profiles
        .get_mut("default")
        .expect("changed profile")
        .account_subject = Some("018f4f08-7f1d-7d57-bd43-bb4b7c520002".to_string());
    let error = ensure_credential_profile_anchor_matches(
        &anchor,
        &anchor.repository_binding_digest,
        &changed,
        &anchor.source_digest,
    )
    .expect_err("subject change invalidates the anchor");
    assert!(matches!(
        error,
        ConfigError::CredentialProfileAnchorConflict {
            field: "account_subject",
            ..
        }
    ));
}

#[test]
fn credential_profile_account_binding_is_an_exact_canonical_pair() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = seed_auth_intent_profile(&repo, &store);
    let source = repo.snapshot().expect("source snapshot").config().clone();

    let mutate_profile =
        |config: &mut ConfigV2, subject: Option<&str>, method: Option<AuthMethod>| {
            let profile = config
                .connections
                .get_mut(&connection_id)
                .expect("connection")
                .credential_profiles
                .get_mut("default")
                .expect("profile");
            profile.account_subject = subject.map(str::to_string);
            profile.auth_method = method;
        };

    let mut subject_only = source.clone();
    mutate_profile(
        &mut subject_only,
        Some("018f4f08-7f1d-7d57-bd43-bb4b7c520001"),
        None,
    );
    assert!(matches!(
        serialize_config(&subject_only),
        Err(ConfigError::InvalidConfig { .. })
    ));

    let mut method_only = source.clone();
    mutate_profile(&mut method_only, None, Some(AuthMethod::Password));
    assert!(matches!(
        serialize_config(&method_only),
        Err(ConfigError::InvalidConfig { .. })
    ));

    let mut noncanonical = source.clone();
    mutate_profile(
        &mut noncanonical,
        Some("018F4F08-7F1D-7D57-BD43-BB4B7C520001"),
        Some(AuthMethod::Password),
    );
    assert!(matches!(
        serialize_config(&noncanonical),
        Err(ConfigError::InvalidConfig { .. })
    ));

    let mut canonical = source;
    mutate_profile(
        &mut canonical,
        Some("018f4f08-7f1d-7d57-bd43-bb4b7c520001"),
        Some(AuthMethod::Password),
    );
    serialize_config(&canonical).expect("canonical binding pair");
}

#[test]
fn auth_intent_without_account_subject_remains_source_compatible() {
    let temp = TempDir::new().expect("tempdir");
    let intent = valid_auth_intent(temp.path());
    let bytes = serialize_auth_operation_intent(&intent, temp.path()).expect("serialize");
    let encoded = String::from_utf8(bytes).expect("intent JSON is UTF-8");
    let legacy_bytes = encoded
        .lines()
        .filter(|line| !line.contains("\"account_subject\""))
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let parsed = parse_auth_operation_intent(
        &temp.path().join(AUTH_OPERATION_INTENT_FILENAME),
        &legacy_bytes,
    )
    .expect("pre-binding v1 intent remains readable");
    assert!(parsed.source.account_subject.is_none());
}

#[test]
fn auth_intent_parser_is_bounded_duplicate_free_future_strict_and_root_bound() {
    let first = TempDir::new().expect("first tempdir");
    let second = TempDir::new().expect("second tempdir");
    let intent = valid_auth_intent(first.path());
    let bytes = serialize_auth_operation_intent(&intent, first.path()).expect("serialize");
    let encoded = String::from_utf8(bytes.clone()).expect("intent json is utf8");
    parse_auth_operation_intent(&first.path().join(AUTH_OPERATION_INTENT_FILENAME), &bytes)
        .expect("parse valid intent");

    let duplicate = encoded
        .clone()
        .replacen(
            "\"journal_version\": 1,",
            "\"journal_version\": 1,\n  \"journal_version\": 1,",
            1,
        )
        .into_bytes();
    assert!(matches!(
        parse_auth_operation_intent(
            &first.path().join(AUTH_OPERATION_INTENT_FILENAME),
            &duplicate,
        ),
        Err(ConfigError::MalformedAuthOperationIntent { .. })
    ));

    let future = encoded
        .replacen("\"journal_version\": 1", "\"journal_version\": 3", 1)
        .into_bytes();
    assert!(matches!(
        parse_auth_operation_intent(&first.path().join(AUTH_OPERATION_INTENT_FILENAME), &future,),
        Err(ConfigError::FutureAuthOperationIntent { .. })
    ));

    let unknown = encoded
        .replacen('{', "{\n  \"unexpected\": true,", 1)
        .into_bytes();
    assert!(matches!(
        parse_auth_operation_intent(&first.path().join(AUTH_OPERATION_INTENT_FILENAME), &unknown,),
        Err(ConfigError::MalformedAuthOperationIntent { .. })
    ));

    let excessive_nodes = encoded
        .replacen(
            '{',
            &format!("{{\n  \"unexpected\": [{}],", vec!["null"; 256].join(",")),
            1,
        )
        .into_bytes();
    assert!(matches!(
        parse_auth_operation_intent(
            &first.path().join(AUTH_OPERATION_INTENT_FILENAME),
            &excessive_nodes,
        ),
        Err(ConfigError::MalformedAuthOperationIntent { .. })
    ));

    assert!(matches!(
        parse_auth_operation_intent(&second.path().join(AUTH_OPERATION_INTENT_FILENAME), &bytes,),
        Err(ConfigError::AuthOperationIntentRepositoryMismatch)
    ));

    let oversized_path = first.path().join(AUTH_OPERATION_INTENT_FILENAME);
    fs::write(
        &oversized_path,
        vec![b' '; AUTH_OPERATION_INTENT_MAX_BYTES as usize + 1],
    )
    .expect("oversized intent");
    assert!(matches!(
        read_file(&oversized_path, "read oversized auth intent"),
        Err(ConfigError::ConfigTooLarge { max_bytes, .. })
            if max_bytes == AUTH_OPERATION_INTENT_MAX_BYTES
    ));
}

#[test]
fn invalid_auth_intent_preflight_blocks_pending_credential_cleanup_port_calls() {
    let temp = TempDir::new().expect("tempdir");
    let repo = repository(&temp);
    initialize(&repo);
    let store = TestCredentialStore::default();
    let connection_id = seed_auth_intent_profile(&repo, &store);
    let anchor = repo
        .resolve_credential_profile_anchor(&connection_id, "default")
        .expect("source anchor");
    repo.remove_credential_profile_if_matches_with_operation_lock(
        &anchor,
        ActiveCredentialAfterRemoval::Clear,
        &store,
    )
    .expect("publish source revoke");
    repo.upsert_connection(
        ConnectionId::deterministic("other", "https://other.intent.test"),
        ConnectionMetadata::new("other", "https://other.intent.test"),
    )
    .expect("rotate backup beyond removed source");
    store.set_fail_deletes(true);
    repo.reconcile_credentials_with_operation_lock(&store)
        .expect("leave failed cleanup journal");
    store.set_fail_deletes(false);
    assert!(repo.paths().credential_transaction_journal().exists());

    let other = TempDir::new().expect("other root");
    let cross_root =
        serialize_auth_operation_intent(&valid_auth_intent(other.path()), other.path())
            .expect("cross-root intent");
    let cases = [
        b"{broken".to_vec(),
        br#"{"journal_version":2}"#.to_vec(),
        cross_root,
    ];
    for bytes in cases {
        fs::write(repo.paths().auth_operation_intent(), bytes).expect("write invalid auth intent");
        let calls = store.calls();
        assert!(repo
            .reconcile_auth_operation_with_operation_locks(&store)
            .is_err());
        assert_eq!(store.calls(), calls, "invalid auth intent touched store");
        assert!(repo.paths().auth_operation_intent().exists());
        assert!(repo.paths().credential_transaction_journal().exists());
    }
}
