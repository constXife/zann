//! A store opened for a connection that has not bound a master key yet may
//! help prove its key (generate and check the account's first vault key) but
//! never reads or keeps projection state, while a bound connection's store
//! still admits only the bound key.

use super::*;

struct Opened {
    fixture: ConfigFixture,
    pool: SqlitePool,
    store: Arc<SqliteSyncStore>,
    scope: SyncScope,
}

async fn open(master_key_bound: bool, name: &str) -> Opened {
    let fixture = configured_fixture_with_master_key_bound(master_key_bound);
    let database_path = fixture.temp.path().join(format!("{name}.sqlite"));
    let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
        .await
        .expect("open adapter database");
    zann_db::migrate_local(&pool)
        .await
        .expect("migrate adapter database");
    LocalStorageRepo::new(&pool)
        .upsert(&matching_storage(&fixture))
        .await
        .expect("insert matching local storage");
    let vault_id = Uuid::now_v7();
    LocalVaultRepo::new(&pool)
        .insert_if_absent(&LocalVault {
            id: vault_id,
            storage_id: fixture.storage_id,
            slug: "personal".to_string(),
            name: "Personal".to_string(),
            kind: VaultKind::Personal,
            is_default: false,
            vault_key_enc: zann_crypto::encrypt_vault_key(
                &fixture.master_key,
                vault_id,
                &SecretKey::generate(),
            )
            .expect("wrap the vault key"),
            key_wrap_type: KeyWrapType::RemoteStrict,
            cache_key_fp: None,
            last_synced_at: None,
        })
        .await
        .expect("insert the account's personal vault");
    let store = Arc::new(
        SqliteSyncStore::from_pool(
            bound_paths(&fixture, &database_path),
            file_location(&database_path),
            pool.clone(),
            Arc::clone(&fixture.master_key),
            fixture.target.clone(),
        )
        .expect("construct adapter"),
    );
    let scope = SyncScope::new(fixture.storage_id, vault_id).expect("scope");
    Opened {
        fixture,
        pool,
        store,
        scope,
    }
}

#[tokio::test]
async fn a_candidate_key_proves_itself_but_keeps_no_projection_state() {
    let opened = open(false, "candidate").await;
    let store = &opened.store;

    let refused =
        |error: SyncStoreError| assert_eq!(error.kind(), SyncStoreErrorKind::StaleKeyBinding);
    refused(
        store
            .load_checkpoint(opened.scope)
            .await
            .expect_err("no checkpoint for an unbound key"),
    );
    refused(
        store
            .load_item_states(opened.scope, &[])
            .await
            .expect_err("no item state for an unbound key"),
    );
    let publication = Arc::clone(store)
        .prepare_generated_key(opened.scope, Vec::new())
        .await
        .expect("the candidate wraps the account's first vault key");
    zann_crypto::decrypt_vault_key(
        &opened.fixture.master_key,
        opened.scope.vault_id(),
        publication.published_envelope(),
    )
    .expect("wrapped by the candidate key");
    Arc::clone(store)
        .commit_generated_key(publication)
        .await
        .expect("the published key checks against the candidate");
    opened.pool.close().await;
}

#[tokio::test]
async fn a_bound_connection_admits_only_its_bound_key() {
    let opened = open(true, "bound").await;
    let checkpoint = opened
        .store
        .load_checkpoint(opened.scope)
        .await
        .expect("the bound key reads its projection");
    assert!(checkpoint.pending().is_empty());

    let database_path = opened.fixture.temp.path().join("bound.sqlite");
    let error = SqliteSyncStore::from_pool(
        bound_paths(&opened.fixture, &database_path),
        file_location(&database_path),
        opened.pool.clone(),
        Arc::new(SecretKey::from_bytes([8_u8; 32])),
        opened.fixture.target.clone(),
    )
    .expect_err("another key than the bound one");
    assert_eq!(error.kind(), SyncStoreErrorKind::StaleKeyBinding);
    opened.pool.close().await;
}
