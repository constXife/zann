//! Several configured connections sync into one database. Every remote
//! storage and a disconnected server replica reuse the same vault and item identifiers to
//! prove that projections are isolated by `(storage_id, id)`.

use super::*;

struct SecondConnection {
    target: SessionTarget,
    storage: LocalStorage,
}

/// Adds a second fully bound connection to the fixture's config, owning its
/// own storage and account.
fn add_second_connection(fixture: &ConfigFixture) -> SecondConnection {
    let repository = ConfigRepository::new(fixture.paths.clone());
    let credentials = MemoryCredentials::default();
    let storage_id = Uuid::now_v7();
    let account_subject = Uuid::now_v7();
    let connection_id = ConnectionId::deterministic("second", "https://second.test/");
    let mut metadata = ConnectionMetadata::new("Second", "https://second.test");
    metadata.server_id = Some("second-server-identity".to_string());
    metadata.server_fingerprint = Some("second-server-fingerprint".to_string());
    metadata.storage_id = Some(storage_id.to_string());
    metadata.expected_master_key_fp = Some(zann_crypto::cache_key_fingerprint(&fixture.master_key));
    repository
        .upsert_connection(connection_id.clone(), metadata)
        .expect("insert second connection");
    let revision = repository
        .snapshot()
        .expect("snapshot second connection")
        .revision();
    repository
        .replace_credential_bundle(
            revision,
            &connection_id,
            "profile",
            CredentialBundle::new(
                Some(CredentialSecret::new("second-access").expect("access secret")),
                None,
                None,
            ),
            CredentialActivation::Preserve,
            &credentials,
        )
        .expect("insert second profile credentials");

    let config_path = fixture.paths.config();
    let mut raw: serde_json::Value =
        serde_json::from_slice(&fs::read(&config_path).expect("read config"))
            .expect("parse config");
    raw["connections"][connection_id.as_str()]["credential_profiles"]["profile"]
        ["account_subject"] = json!(account_subject.to_string());
    raw["connections"][connection_id.as_str()]["credential_profiles"]["profile"]["auth_method"] =
        json!(AuthMethod::Password.as_i32());
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&raw).expect("serialize config"),
    )
    .expect("write config");

    SecondConnection {
        target: SessionTarget::new(connection_id, "profile").expect("second target"),
        storage: LocalStorage {
            id: storage_id,
            kind: StorageKind::Remote,
            name: "Second".to_string(),
            server_url: Some("https://second.test".to_string()),
            server_name: Some("Second Server".to_string()),
            server_fingerprint: Some("second-server-fingerprint".to_string()),
            account_subject: Some(account_subject.to_string()),
            personal_vaults_enabled: true,
            auth_method: Some(AuthMethod::Password),
        },
    }
}

const SHARED_ENVELOPE: [u8; 3] = [4, 5, 6];

/// Materializes, binds and pulls one shared vault holding one item. Both ids
/// are deliberately identical across every storage in these tests.
async fn sync_shared_vault(
    pool: &SqlitePool,
    storage: &LocalStorage,
    master_key: &SecretKey,
    vault_id: Uuid,
    item_id: Uuid,
    payload: &[u8],
) {
    LocalStorageRepo::new(pool)
        .upsert(storage)
        .await
        .expect("insert remote storage");
    LocalVaultRepo::new(pool)
        .insert_if_absent(&LocalVault {
            id: vault_id,
            storage_id: storage.id,
            slug: "shared".to_string(),
            name: "Shared".to_string(),
            kind: VaultKind::Shared,
            is_default: false,
            vault_key_enc: SHARED_ENVELOPE.to_vec(),
            key_wrap_type: KeyWrapType::RemoteServer,
            cache_key_fp: None,
            last_synced_at: None,
        })
        .await
        .expect("materialize the catalog vault");
    let catalog = [CatalogExpectation {
        id: vault_id,
        slug: "shared",
        name: "Shared",
        plane: VaultPlane::SharedServer,
        vault_key_envelope: &SHARED_ENVELOPE,
    }];
    reconcile_catalog_rows_for_test(pool, storage, master_key, &catalog)
        .await
        .expect("bind the catalog despite identical ids in other storages");

    let scope = LocalSyncScope {
        storage_id: storage.id,
        vault_id,
    };
    let fingerprint = zann_crypto::cache_key_fingerprint(master_key);
    let item = LocalItem {
        metadata: Some(Default::default()),
        id: item_id,
        storage_id: storage.id,
        vault_id,
        path: "accounts/shared".to_string(),
        name: "shared".to_string(),
        type_id: "login".to_string(),
        payload_enc: payload.to_vec(),
        checksum: zann_crypto::payload_checksum(payload),
        cache_key_fp: Some(fingerprint.clone()),
        version: 1,
        deleted_at: None,
        updated_at: chrono::Utc::now(),
        sync_status: SyncStatus::Synced,
    };
    let change = PullChange::new(scope, LocalItemExpectation::Absent, item, Vec::new())
        .expect("construct pull change");
    let page = PullPage::new(
        scope,
        fingerprint,
        None,
        None,
        "eyJzZXEiOjF9".to_string(),
        Some(1),
        chrono::Utc::now(),
        vec![change],
    )
    .expect("construct pull page");
    commit_bound_pull_page_for_test(pool, storage, &page)
        .await
        .expect("pull into this storage despite identical ids elsewhere");
}

async fn seed_disconnected_replica(
    pool: &SqlitePool,
    vault_id: Uuid,
    item_id: Uuid,
    payload: &[u8],
) -> Uuid {
    let storage_id = Uuid::now_v7();
    LocalStorageRepo::new(pool)
        .upsert(&LocalStorage {
            id: storage_id,
            kind: StorageKind::Remote,
            name: "Disconnected".into(),
            server_url: Some("https://disconnected.test".into()),
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: true,
            auth_method: None,
        })
        .await
        .expect("disconnected server storage");
    LocalVaultRepo::new(pool)
        .create(&LocalVault {
            id: vault_id,
            storage_id,
            slug: LocalVault::local_slug(vault_id),
            name: "Local".to_string(),
            kind: VaultKind::Personal,
            is_default: false,
            vault_key_enc: vec![1, 2, 3],
            key_wrap_type: KeyWrapType::Master,
            cache_key_fp: None,
            last_synced_at: None,
        })
        .await
        .expect("insert local vault");
    LocalItemRepo::new(pool)
        .create(&LocalItem {
            metadata: Some(Default::default()),
            id: item_id,
            storage_id,
            vault_id,
            path: "accounts/shared".to_string(),
            name: "shared".to_string(),
            type_id: "login".to_string(),
            payload_enc: payload.to_vec(),
            checksum: zann_crypto::payload_checksum(payload),
            cache_key_fp: None,
            version: 1,
            deleted_at: None,
            updated_at: chrono::Utc::now(),
            sync_status: SyncStatus::Modified,
        })
        .await
        .expect("insert cached item");
    storage_id
}

async fn stored_payload(pool: &SqlitePool, storage_id: Uuid, item_id: Uuid) -> Option<Vec<u8>> {
    LocalItemRepo::new(pool)
        .get_by_id(storage_id, item_id)
        .await
        .expect("read item")
        .map(|item| item.payload_enc)
}

#[test]
fn two_connected_and_one_disconnected_server_replicas_isolate_identical_ids() {
    let _serial = TERMINAL_MUTATION_TEST_LOCK
        .lock()
        .expect("serialize process-global terminal admission test");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("multi-storage test runtime");
    runtime.block_on(async {
        let fixture = configured_fixture();
        let second = add_second_connection(&fixture);
        let first = matching_storage(&fixture);
        let (database_path, pool) = reset_test_database(&fixture, "multi-storage.sqlite").await;
        let vault_id = Uuid::now_v7();
        let item_id = Uuid::now_v7();

        sync_shared_vault(&pool, &first, &fixture.master_key, vault_id, item_id, &[1]).await;
        sync_shared_vault(
            &pool,
            &second.storage,
            &fixture.master_key,
            vault_id,
            item_id,
            &[2],
        )
        .await;
        let disconnected = seed_disconnected_replica(&pool, vault_id, item_id, &[3]).await;

        assert_eq!(
            stored_payload(&pool, first.id, item_id).await,
            Some(vec![1])
        );
        assert_eq!(
            stored_payload(&pool, second.storage.id, item_id).await,
            Some(vec![2])
        );
        assert_eq!(
            stored_payload(&pool, disconnected, item_id).await,
            Some(vec![3])
        );

        for target in [&fixture.target, &second.target] {
            let store = SqliteSyncStore::from_pool(
                bound_paths(&fixture, &database_path),
                file_location(&database_path),
                pool.clone(),
                fixture.master_key.clone(),
                target.clone(),
            )
            .expect("construct a store for one of several connections");
            store
                .resolve_exact_target_for_test(target)
                .await
                .expect("each connection resolves its own storage");
        }
        pool.close().await;

        let (database_path, paths) = canonical_reset_paths(&database_path);
        Arc::new(SqliteSyncStoreFactory::new(&database_path).expect("construct reset factory"))
            .reset_projection(paths, second.target.clone(), fixture.master_key.clone())
            .await
            .expect("reset the second connection's clean projection");

        let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
            .await
            .expect("reopen multi-storage database");
        assert_eq!(
            stored_payload(&pool, second.storage.id, item_id).await,
            None
        );
        assert!(!LocalVaultRepo::new(&pool)
            .exists(second.storage.id, vault_id)
            .await
            .expect("read reset vault"));
        assert_eq!(
            stored_payload(&pool, first.id, item_id).await,
            Some(vec![1])
        );
        assert_eq!(
            stored_payload(&pool, disconnected, item_id).await,
            Some(vec![3])
        );
        assert!(LocalVaultRepo::new(&pool)
            .exists(first.id, vault_id)
            .await
            .expect("read surviving remote vault"));
        pool.close().await;
    });
}
