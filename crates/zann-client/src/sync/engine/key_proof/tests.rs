use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use uuid::Uuid;
use zann_core::AuthMethod;
use zann_crypto::{vault_crypto, SecretKey};

use crate::config::{AuthorizedTargetGeneration, ConnectionId};
use crate::session::{SessionAccess, SessionOperation, SessionTarget};
use crate::sync::engine::{AuthorizeFuture, SyncAuthorizer, SyncEngine};
use crate::sync::model::{
    CatalogSnapshot, CatalogVault, GeneratedVaultKeyCommit, ItemState, PendingProof,
    ProjectionReset, PullCommitReceipt, PullPageCommit, PushCommitPlan, PushCommitReceipt,
    ReconciledCatalog, ResolvedSyncTarget, ResolvedSyncVault, StorageBindingProof, SyncCheckpoint,
    SyncCursor, SyncError, SyncErrorKind, SyncLocalStore, SyncScope, SyncStage, SyncStoreError,
    SyncStoreErrorKind, SyncStoreFuture, VaultPayloadKey, VaultPlane,
};
use crate::sync::transport::{RemoteError, RemoteErrorKind, RemoteFuture, SyncRemote};
use crate::sync::wire::{PullPageWire, PushResponseWire};

const ENDPOINT: &str = "https://sync.example.test";
const FINGERPRINT: &str = "server-fingerprint";
const SUBJECT: &str = "018f4f08-7f1d-7d57-bd43-bb4b7c520001";

struct Authorizer {
    storage_id: Uuid,
    personal_vaults_enabled: bool,
}

impl SyncAuthorizer for Authorizer {
    fn authorize<'a>(
        &'a self,
        target: &'a SessionTarget,
        operation: SessionOperation,
    ) -> AuthorizeFuture<'a> {
        let access = SessionAccess::for_sync_test(
            operation.operation_id(),
            target.clone(),
            ENDPOINT,
            Some(self.storage_id.to_string()),
            FINGERPRINT,
            (Some(SUBJECT.to_string()), Some(AuthMethod::Password)),
            self.personal_vaults_enabled,
        );
        Box::pin(async move { Ok(access) })
    }
}

/// A server whose personal vault keys initialize at most once.
struct Remote {
    vaults: Mutex<Vec<(Uuid, VaultPlane, Vec<u8>)>>,
    /// Another device publishes this envelope just before ours arrives.
    racing_envelope: Option<Vec<u8>>,
    publishes: AtomicUsize,
}

impl Remote {
    fn new(vaults: Vec<(Uuid, VaultPlane, Vec<u8>)>) -> Self {
        Self {
            vaults: Mutex::new(vaults),
            racing_envelope: None,
            publishes: AtomicUsize::new(0),
        }
    }

    fn envelope(&self, vault_id: Uuid) -> Vec<u8> {
        self.vaults
            .lock()
            .expect("vaults")
            .iter()
            .find(|(id, _, _)| *id == vault_id)
            .map(|(_, _, envelope)| envelope.clone())
            .expect("known vault")
    }
}

impl SyncRemote for Remote {
    fn fetch_catalog<'a>(
        &'a self,
        _access: &'a SessionAccess,
        _timeout: Duration,
    ) -> RemoteFuture<'a, CatalogSnapshot> {
        let vaults = self
            .vaults
            .lock()
            .expect("vaults")
            .iter()
            .map(|(id, plane, envelope)| {
                CatalogVault::validated(
                    *id,
                    format!("vault-{id}"),
                    "Vault".to_string(),
                    *plane,
                    Vec::new(),
                    Utc::now(),
                    envelope.clone(),
                )
            })
            .collect();
        let catalog = CatalogSnapshot::validated(vaults);
        Box::pin(async move { Ok(catalog) })
    }

    fn pull_page<'a>(
        &'a self,
        _access: &'a SessionAccess,
        _vault_id: Uuid,
        _plane: VaultPlane,
        _cursor: Option<&'a SyncCursor>,
        _timeout: Duration,
    ) -> RemoteFuture<'a, PullPageWire> {
        unreachable!("a key proof never pulls")
    }

    fn push<'a>(
        &'a self,
        _access: &'a SessionAccess,
        _vault: &'a ResolvedSyncVault,
        _pending: &'a [PendingProof],
        _timeout: Duration,
    ) -> RemoteFuture<'a, PushResponseWire> {
        unreachable!("a key proof never pushes")
    }

    fn publish_personal_vault_key<'a>(
        &'a self,
        _access: &'a SessionAccess,
        vault_id: Uuid,
        envelope: &'a [u8],
        _timeout: Duration,
    ) -> RemoteFuture<'a, ()> {
        self.publishes.fetch_add(1, Ordering::SeqCst);
        let mut vaults = self.vaults.lock().expect("vaults");
        let (_, _, stored) = vaults
            .iter_mut()
            .find(|(id, _, _)| *id == vault_id)
            .expect("known vault");
        if let Some(racing) = &self.racing_envelope {
            *stored = racing.clone();
        }
        let result = if stored.is_empty() {
            *stored = envelope.to_vec();
            Ok(())
        } else {
            Err(RemoteError::new(RemoteErrorKind::Rejected))
        };
        Box::pin(async move { result })
    }
}

/// Holds the device's master key the way the adapter does, and counts every
/// call that would keep local state.
struct Store {
    storage_id: Uuid,
    master_key: SecretKey,
    persistent_calls: AtomicUsize,
}

impl Store {
    fn persistent(&self) -> SyncStoreError {
        self.persistent_calls.fetch_add(1, Ordering::SeqCst);
        SyncStoreError::new(SyncStoreErrorKind::StaleKeyBinding)
    }
}

impl SyncLocalStore for Store {
    fn resolve_target<'a>(
        &'a self,
        _target: &'a SessionTarget,
        _generation: Arc<AuthorizedTargetGeneration>,
        personal_vaults_enabled: bool,
    ) -> SyncStoreFuture<'a, ResolvedSyncTarget> {
        let binding = StorageBindingProof::new(
            self.storage_id,
            "Remote",
            ENDPOINT,
            None,
            FINGERPRINT,
            Some(SUBJECT.to_string()),
            personal_vaults_enabled,
            Some(AuthMethod::Password),
        )
        .map(ResolvedSyncTarget::new)
        .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::InvalidData));
        Box::pin(async move { binding })
    }

    fn reconcile_catalog(
        self: Arc<Self>,
        _target: Arc<ResolvedSyncTarget>,
        _catalog: Arc<CatalogSnapshot>,
    ) -> SyncStoreFuture<'static, ReconciledCatalog> {
        let error = self.persistent();
        Box::pin(async move { Err(error) })
    }

    fn load_checkpoint<'a>(&'a self, _scope: SyncScope) -> SyncStoreFuture<'a, SyncCheckpoint> {
        let error = self.persistent();
        Box::pin(async move { Err(error) })
    }

    fn load_item_states<'a>(
        &'a self,
        _scope: SyncScope,
        _item_ids: &'a [Uuid],
    ) -> SyncStoreFuture<'a, Vec<ItemState>> {
        let error = self.persistent();
        Box::pin(async move { Err(error) })
    }

    fn prepare_generated_key(
        self: Arc<Self>,
        scope: SyncScope,
        expected_remote_envelope: Vec<u8>,
    ) -> SyncStoreFuture<'static, GeneratedVaultKeyCommit> {
        Box::pin(async move {
            let generated = SecretKey::generate();
            let published =
                vault_crypto::encrypt_vault_key(&self.master_key, scope.vault_id(), &generated)
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?;
            GeneratedVaultKeyCommit::new(
                scope,
                expected_remote_envelope,
                published,
                VaultPayloadKey::from_secret_key(generated),
            )
            .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::InvalidData))
        })
    }

    fn commit_generated_key(
        self: Arc<Self>,
        commit: GeneratedVaultKeyCommit,
    ) -> SyncStoreFuture<'static, ()> {
        Box::pin(async move {
            vault_crypto::decrypt_vault_key(
                &self.master_key,
                commit.scope().vault_id(),
                commit.published_envelope(),
            )
            .map(|_| ())
            .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::StaleKeyBinding))
        })
    }

    fn commit_push(
        self: Arc<Self>,
        _commit: PushCommitPlan,
    ) -> SyncStoreFuture<'static, PushCommitReceipt> {
        let error = self.persistent();
        Box::pin(async move { Err(error) })
    }

    fn commit_pull_page(
        self: Arc<Self>,
        _commit: PullPageCommit,
    ) -> SyncStoreFuture<'static, PullCommitReceipt> {
        let error = self.persistent();
        Box::pin(async move { Err(error) })
    }

    fn reset_projection_if_clean(
        self: Arc<Self>,
        _reset: ProjectionReset,
    ) -> SyncStoreFuture<'static, ()> {
        let error = self.persistent();
        Box::pin(async move { Err(error) })
    }
}

/// One device about to sync a connection that has no master key bound.
struct Device {
    master_key: SecretKey,
    store: Arc<Store>,
    remote: Arc<Remote>,
    engine: SyncEngine,
    binds: AtomicUsize,
}

impl Device {
    fn new(master_key: [u8; 32], remote: Remote, personal_vaults_enabled: bool) -> Self {
        let storage_id = Uuid::now_v7();
        let store = Arc::new(Store {
            storage_id,
            master_key: SecretKey::from_bytes(master_key),
            persistent_calls: AtomicUsize::new(0),
        });
        let remote = Arc::new(remote);
        let engine = SyncEngine::with_components(
            Arc::new(Authorizer {
                storage_id,
                personal_vaults_enabled,
            }),
            store.clone(),
            remote.clone(),
        );
        Self {
            master_key: SecretKey::from_bytes(master_key),
            store,
            remote,
            engine,
            binds: AtomicUsize::new(0),
        }
    }

    async fn sync(&self) -> Result<(), SyncError> {
        let target = SessionTarget::new(ConnectionId::deterministic("key-proof", ENDPOINT), "p")
            .expect("target");
        let (operation, _cancel) = SessionOperation::new(Instant::now() + Duration::from_secs(30));
        self.engine
            .prove_and_bind_master_key(&target, &self.master_key, &operation, |_| {
                self.binds.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
    }

    fn bound(&self) -> bool {
        self.binds.load(Ordering::SeqCst) == 1
    }

    fn kept_nothing(&self) -> bool {
        self.store.persistent_calls.load(Ordering::SeqCst) == 0
    }
}

const ACCOUNT_KEY: [u8; 32] = [7; 32];
const MISTYPED_KEY: [u8; 32] = [9; 32];

fn personal_vault(wrapped_by: Option<[u8; 32]>) -> (Uuid, VaultPlane, Vec<u8>) {
    let id = Uuid::now_v7();
    let envelope = wrapped_by.map_or_else(Vec::new, |key| {
        vault_crypto::encrypt_vault_key(&SecretKey::from_bytes(key), id, &SecretKey::generate())
            .expect("wrap the vault key")
    });
    (id, VaultPlane::PersonalClient, envelope)
}

fn shared_vault() -> (Uuid, VaultPlane, Vec<u8>) {
    (Uuid::now_v7(), VaultPlane::SharedServer, vec![1, 2, 3])
}

#[tokio::test]
async fn a_mismatched_key_binds_nothing_and_keeps_nothing() {
    let device = Device::new(
        MISTYPED_KEY,
        Remote::new(vec![personal_vault(Some(ACCOUNT_KEY)), shared_vault()]),
        true,
    );
    let error = device.sync().await.expect_err("another master password");
    assert_eq!(error.kind(), SyncErrorKind::Crypto);
    assert_eq!(error.stage(), SyncStage::Catalog);
    assert!(!device.bound());
    assert!(device.kept_nothing());
    assert_eq!(device.remote.publishes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_key_that_opens_every_published_vault_key_binds() {
    let device = Device::new(
        ACCOUNT_KEY,
        Remote::new(vec![personal_vault(Some(ACCOUNT_KEY)), shared_vault()]),
        true,
    );
    device.sync().await.expect("the account's key");
    assert!(device.bound());
    assert!(device.kept_nothing());
    assert_eq!(device.remote.publishes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn one_vault_key_the_key_cannot_open_is_a_mismatch() {
    let device = Device::new(
        ACCOUNT_KEY,
        Remote::new(vec![
            personal_vault(Some(ACCOUNT_KEY)),
            personal_vault(Some(MISTYPED_KEY)),
        ]),
        true,
    );
    let error = device.sync().await.expect_err("one key does not open");
    assert_eq!(error.kind(), SyncErrorKind::Crypto);
    assert!(!device.bound());
}

#[tokio::test]
async fn publishing_the_first_vault_key_proves_and_binds() {
    let vault = personal_vault(None);
    let vault_id = vault.0;
    let device = Device::new(ACCOUNT_KEY, Remote::new(vec![vault]), true);
    device.sync().await.expect("first device publishes");
    assert!(device.bound());
    assert!(device.kept_nothing());
    assert_eq!(device.remote.publishes.load(Ordering::SeqCst), 1);
    vault_crypto::decrypt_vault_key(
        &SecretKey::from_bytes(ACCOUNT_KEY),
        vault_id,
        &device.remote.envelope(vault_id),
    )
    .expect("the published key is wrapped by the device's key");
}

#[tokio::test]
async fn the_loser_of_a_first_publish_race_binds_nothing() {
    let vault = personal_vault(None);
    let winner = vault_crypto::encrypt_vault_key(
        &SecretKey::from_bytes(ACCOUNT_KEY),
        vault.0,
        &SecretKey::generate(),
    )
    .expect("wrap the winner's key");
    let mut remote = Remote::new(vec![vault]);
    remote.racing_envelope = Some(winner);
    let device = Device::new(MISTYPED_KEY, remote, true);
    let error = device
        .sync()
        .await
        .expect_err("the other device published first");
    assert_eq!(error.kind(), SyncErrorKind::TransportRejected);
    assert!(!device.bound());
    assert!(device.kept_nothing());

    // Its next sync sees the winner's key and refuses its own.
    let published = device.remote.vaults.lock().expect("vaults").clone();
    let retry = Device::new(MISTYPED_KEY, Remote::new(published), true);
    let error = retry
        .sync()
        .await
        .expect_err("the account uses the winner's key");
    assert_eq!(error.kind(), SyncErrorKind::Crypto);
    assert!(!retry.bound());
}

#[tokio::test]
async fn a_personal_account_without_a_personal_vault_binds_nothing() {
    let device = Device::new(ACCOUNT_KEY, Remote::new(vec![shared_vault()]), true);
    let error = device.sync().await.expect_err("nothing proves the key");
    assert_eq!(error.kind(), SyncErrorKind::Protocol);
    assert!(!device.bound());
}

#[tokio::test]
async fn a_server_without_personal_vaults_binds_without_proof() {
    let device = Device::new(ACCOUNT_KEY, Remote::new(vec![shared_vault()]), false);
    device
        .sync()
        .await
        .expect("the key wraps nothing on the server");
    assert!(device.bound());
    assert!(device.kept_nothing());
}

#[tokio::test]
async fn a_failed_bind_fails_the_sync() {
    let device = Device::new(
        ACCOUNT_KEY,
        Remote::new(vec![personal_vault(Some(ACCOUNT_KEY))]),
        true,
    );
    let target = SessionTarget::new(ConnectionId::deterministic("key-proof", ENDPOINT), "p")
        .expect("target");
    let (operation, _cancel) = SessionOperation::new(Instant::now() + Duration::from_secs(30));
    let operation_id = operation.operation_id();
    let error = device
        .engine
        .prove_and_bind_master_key(&target, &device.master_key, &operation, |_| {
            Err(SyncError::new(
                operation_id,
                SyncErrorKind::Crypto,
                SyncStage::ResolveTarget,
            ))
        })
        .await
        .expect_err("the bind refused");
    assert_eq!(error.stage(), SyncStage::ResolveTarget);
}
