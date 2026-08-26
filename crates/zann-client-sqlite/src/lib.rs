//! Production SQLite adapter for the canonical `zann-client` sync owner.
//!
//! An instance is an operation-scoped lease over exactly one explicit session
//! target, config root, database pool and immutable master key. The current
//! SQLite schema uses global UUID primary keys for vaults and items, so this
//! adapter currently rejects multiple configured connections/profiles and
//! multiple remote storage rows. Missing exact remote projections may be
//! materialized, but existing storage and key bindings are never replaced.

#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use uuid::Uuid;
use zann_client::app::{
    spi::{
        AuthorizedTargetGeneration, CatalogSnapshot, CatalogVault, ContentChecksum,
        GeneratedVaultKeyCommit, HistoryAuthority, ItemProjection, ItemProof, ItemState,
        PendingExpectation, PendingProof, ProjectionReset, PullCommitReceipt, PullPageCommit,
        PushCommitPlan, PushCommitReceipt, ReconciledCatalog, ResolvedSyncTarget,
        ResolvedSyncVault, StorageBindingProof, SyncCheckpoint, SyncCursor, SyncLocalStore,
        SyncScope, SyncSeq, SyncStoreError, SyncStoreErrorKind, SyncStoreFuture, VaultPayloadKey,
        VaultPlane,
    },
    AppSyncStoreFactory, ClientPaths, SessionTarget,
};
use zann_client::config::{ConfigError, ConfigRepository, ConnectionId};
#[cfg(test)]
use zann_client::config::{CredentialId, CredentialKind, CredentialProfileAnchor};
use zann_core::{AuthMethod, StorageKind, SyncStatus, VaultKind};
use zann_crypto::SecretKey;
use zann_db::local::{
    CacheKeyFingerprintBinding, HistorySource, HistorySyncStatus, KeyWrapType, LocalItem,
    LocalItemExpectation, LocalItemHistory, LocalItemProof, LocalItemRepo, LocalPendingChange,
    LocalProjectionReadError, LocalStorage, LocalStorageProof, LocalStorageRepo, LocalSyncError,
    LocalSyncGenerationProof, LocalSyncRepo, LocalSyncScope, LocalVault, LocalVaultKeyBindError,
    LocalVaultRepo, PendingChangeRepo, PullChange, PullPage, PushCommit, PushOutcome,
    ResetProjection,
};
use zann_db::{ExistingSqliteDatabase, SqliteFileLocation, SqlitePool};

const MAX_ITEM_STATE_IDS: usize = 64;
const MAX_PENDING_CHANGES: u32 = 64;
static TERMINAL_MUTATION_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
const CONFIG_CAPTURE_ATTEMPTS: usize = 3;

/// Existing-file factory for the DB-free [`zann_client::app::AppClient`].
#[derive(Clone)]
pub struct SqliteSyncStoreFactory {
    location: SqliteFileLocation,
}

impl SqliteSyncStoreFactory {
    /// Resolves one already-existing native SQLite file. Missing databases,
    /// URI semantics, symlinks and non-regular files fail before an operation
    /// can be constructed.
    pub fn new(database_path: &Path) -> Result<Self, SyncStoreError> {
        let location = SqliteFileLocation::from_existing_path(database_path)
            .map_err(|_| store_error(SyncStoreErrorKind::Unavailable))?;
        Ok(Self { location })
    }
}

impl std::fmt::Debug for SqliteSyncStoreFactory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteSyncStoreFactory")
            .finish_non_exhaustive()
    }
}

impl AppSyncStoreFactory for SqliteSyncStoreFactory {
    fn open_existing(
        self: Arc<Self>,
        paths: ClientPaths,
        _target: SessionTarget,
        master_key: Arc<SecretKey>,
    ) -> SyncStoreFuture<'static, Arc<dyn SyncLocalStore>> {
        let database_path = self.location.path().to_path_buf();
        Box::pin(async move {
            let store = SqliteSyncStore::open(paths, &database_path, master_key).await?;
            Ok(Arc::new(store) as Arc<dyn SyncLocalStore>)
        })
    }

    fn reset_projection(
        self: Arc<Self>,
        paths: ClientPaths,
        _target: SessionTarget,
        master_key: Arc<SecretKey>,
    ) -> SyncStoreFuture<'static, ()> {
        let database_path = self.location.path().to_path_buf();
        Box::pin(async move {
            let store = Arc::new(SqliteSyncStore::open(paths, &database_path, master_key).await?);
            store.reset_single_remote_projection().await
        })
    }
}

/// An operation-scoped, bidirectional persistence adapter.
///
/// Create a fresh value for each sync operation. Keeping the master key in an
/// `Arc` makes ownership explicit and immutable; no target/key side map exists.
pub struct SqliteSyncStore {
    config: ConfigRepository,
    database: AdapterDatabase,
    master_key: Arc<SecretKey>,
    authorization: OnceLock<InstalledAuthorization>,
}

impl std::fmt::Debug for SqliteSyncStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteSyncStore")
            .field("database_path", &self.database.location().path())
            .field("authorized", &self.authorization.get().is_some())
            .field("master_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

enum AdapterDatabase {
    Existing(ExistingSqliteDatabase),
    #[cfg(test)]
    Injected {
        pool: SqlitePool,
        location: SqliteFileLocation,
    },
}

impl AdapterDatabase {
    fn pool(&self) -> &SqlitePool {
        match self {
            Self::Existing(database) => database.pool(),
            #[cfg(test)]
            Self::Injected { pool, .. } => pool,
        }
    }

    fn location(&self) -> &SqliteFileLocation {
        match self {
            Self::Existing(database) => database.location(),
            #[cfg(test)]
            Self::Injected { location, .. } => location,
        }
    }

    async fn verify_identity(&self) -> Result<(), SyncStoreError> {
        match self {
            Self::Existing(database) => database
                .verify_identity()
                .await
                .map_err(|_| store_error(SyncStoreErrorKind::Unavailable)),
            #[cfg(test)]
            Self::Injected { .. } => Ok(()),
        }
    }
}

struct InstalledAuthorization {
    target: SessionTarget,
    generation: Option<Arc<AuthorizedTargetGeneration>>,
    expected: TargetBinding,
}

impl std::fmt::Debug for InstalledAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledAuthorization")
            .field("target", &self.target)
            .field("storage_id", &self.expected.storage_id)
            .field("generation", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct TargetBinding {
    connection_id: ConnectionId,
    profile_name: String,
    display_name: String,
    address: String,
    server_id: String,
    server_fingerprint: String,
    storage_id: Uuid,
    master_key_fingerprint: String,
    account_subject: String,
    auth_method: AuthMethod,
}

#[derive(Clone, Copy)]
struct CatalogExpectation<'a> {
    id: Uuid,
    slug: &'a str,
    name: &'a str,
    plane: VaultPlane,
    vault_key_envelope: &'a [u8],
}

impl<'a> From<&'a CatalogVault> for CatalogExpectation<'a> {
    fn from(vault: &'a CatalogVault) -> Self {
        Self {
            id: vault.id(),
            slug: vault.slug(),
            name: vault.name(),
            plane: vault.plane(),
            vault_key_envelope: vault.vault_key_envelope(),
        }
    }
}

impl std::fmt::Debug for TargetBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TargetBinding")
            .field("connection_id", &self.connection_id)
            .field("profile_name", &self.profile_name)
            .field("storage_id", &self.storage_id)
            .field("binding", &"<redacted>")
            .finish()
    }
}

impl SqliteSyncStore {
    /// Opens an existing, already migrated database without reading config or
    /// authorizing a target. Missing databases are never created. The exact
    /// target generation is installed once by [`SyncLocalStore::resolve_target`].
    pub async fn open(
        paths: ClientPaths,
        database_path: &Path,
        master_key: Arc<SecretKey>,
    ) -> Result<Self, SyncStoreError> {
        ensure_requested_paths_match(&paths, database_path)?;
        let database = zann_db::open_existing_sqlite(database_path)
            .await
            .map_err(|_| store_error(SyncStoreErrorKind::Unavailable))?;
        ensure_paths_match_location(&paths, database.location())?;
        let config = ConfigRepository::new(paths);
        Ok(Self {
            config,
            database: AdapterDatabase::Existing(database),
            master_key,
            authorization: OnceLock::new(),
        })
    }

    /// Removes the single remote storage's complete projection in one terminal
    /// transaction. This is the local recovery path used when a server has been
    /// rebuilt or re-trusted: it must fail closed while any pending, dirty-item
    /// or non-server history state would be discarded, and it never requires a
    /// previously authorized target generation.
    async fn reset_single_remote_projection(self: Arc<Self>) -> Result<(), SyncStoreError> {
        let worker = Arc::clone(&self);
        self.dispatch_terminal_mutation(async move {
            worker.database.verify_identity().await?;
            let remotes: Vec<LocalStorage> = LocalStorageRepo::new(worker.database.pool())
                .list()
                .await
                .map_err(|_| store_error(SyncStoreErrorKind::InvalidData))?
                .into_iter()
                .filter(|storage| storage.kind == StorageKind::Remote)
                .collect();
            let [storage] = remotes.as_slice() else {
                return Err(store_error(SyncStoreErrorKind::InvalidData));
            };
            let proof = LocalStorageProof::try_from(storage).map_err(map_local_sync_error)?;
            let reset = ResetProjection::new(proof, None).map_err(map_local_sync_error)?;
            LocalSyncRepo::new(worker.database.pool())
                .reset_projection(&reset)
                .await
                .map(|_| ())
                .map_err(map_local_sync_error)
        })
        .await
    }

    /// Test-only injected pool. Production always uses the pinned non-creating
    /// existing-file factory above.
    #[cfg(test)]
    fn from_pool(
        paths: ClientPaths,
        location: SqliteFileLocation,
        pool: SqlitePool,
        master_key: Arc<SecretKey>,
        target: SessionTarget,
    ) -> Result<Self, SyncStoreError> {
        ensure_paths_match_location(&paths, &location)?;
        let config = ConfigRepository::new(paths);
        let expected = capture_target_binding_for_test(&config, &target, &master_key)?;
        let authorization = OnceLock::new();
        authorization
            .set(InstalledAuthorization {
                target,
                generation: None,
                expected,
            })
            .map_err(|_| store_error(SyncStoreErrorKind::Internal))?;
        Ok(Self {
            config,
            database: AdapterDatabase::Injected { pool, location },
            master_key,
            authorization,
        })
    }

    #[cfg(test)]
    async fn resolve_exact_target_for_test(
        &self,
        target: &SessionTarget,
    ) -> Result<ResolvedSyncTarget, SyncStoreError> {
        let installed = self.installed()?;
        if target != &installed.target {
            return Err(store_error(SyncStoreErrorKind::InvalidData));
        }
        self.ensure_config_current_for_test()?;
        let storage = self.exact_local_storage(&installed.expected).await?;
        storage_binding_proof(&storage).map(ResolvedSyncTarget::new)
    }

    #[cfg(test)]
    fn ensure_config_current_for_test(&self) -> Result<(), SyncStoreError> {
        let installed = self.installed()?;
        let current =
            capture_target_binding_for_test(&self.config, &installed.target, &self.master_key)?;
        if current != installed.expected {
            return Err(store_error(SyncStoreErrorKind::StaleCheckpoint));
        }
        Ok(())
    }

    fn installed(&self) -> Result<&InstalledAuthorization, SyncStoreError> {
        self.authorization
            .get()
            .ok_or_else(|| store_error(SyncStoreErrorKind::StaleCheckpoint))
    }

    fn try_acquire_terminal_mutation(&self) -> Result<MutationPermit, SyncStoreError> {
        MutationPermit::try_acquire()
    }

    fn dispatch_terminal_mutation<T, F>(&self, mutation: F) -> SyncStoreFuture<'static, T>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, SyncStoreError>> + Send + 'static,
    {
        let permit = match self.try_acquire_terminal_mutation() {
            Ok(permit) => permit,
            Err(error) => {
                drop(mutation);
                return Box::pin(async move { Err(error) });
            }
        };
        terminal_mutation(async move {
            let _permit = permit;
            mutation.await
        })
    }

    async fn exact_local_storage(
        &self,
        expected: &TargetBinding,
    ) -> Result<LocalStorage, SyncStoreError> {
        let repository = LocalStorageRepo::new(self.database.pool());
        let storage = repository
            .get_bounded(expected.storage_id)
            .await
            .map_err(map_projection_read)?
            .ok_or_else(|| store_error(SyncStoreErrorKind::NotFound))?;
        let remote_count = repository
            .remote_count_up_to_two()
            .await
            .map_err(|_| store_error(SyncStoreErrorKind::InvalidData))?;
        if remote_count != 1 {
            return Err(store_error(SyncStoreErrorKind::InvalidData));
        }
        ensure_storage_matches_target(&storage, expected)?;
        Ok(storage)
    }

    async fn ensure_scope(&self, scope: SyncScope) -> Result<LocalStorage, SyncStoreError> {
        let installed = self.installed()?;
        if scope.storage_id() != installed.expected.storage_id {
            return Err(store_error(SyncStoreErrorKind::InvalidData));
        }
        self.database.verify_identity().await?;
        let storage = self.exact_local_storage(&installed.expected).await?;
        let vault_exists = LocalVaultRepo::new(self.database.pool())
            .exists_bounded(scope.storage_id(), scope.vault_id())
            .await
            .map_err(map_projection_read)?;
        if !vault_exists {
            return Err(store_error(SyncStoreErrorKind::NotFound));
        }
        Ok(storage)
    }

    async fn resolve_exact_target(
        &self,
        target: &SessionTarget,
        generation: Arc<AuthorizedTargetGeneration>,
        personal_vaults_enabled: bool,
    ) -> Result<ResolvedSyncTarget, SyncStoreError> {
        let expected = target_binding_from_generation(target, &generation, &self.master_key)?;
        self.database.verify_identity().await?;
        let storage_repository = LocalStorageRepo::new(self.database.pool());
        if storage_repository
            .get_bounded(expected.storage_id)
            .await
            .map_err(map_projection_read)?
            .is_none()
        {
            if storage_repository
                .remote_count_up_to_two()
                .await
                .map_err(|_| store_error(SyncStoreErrorKind::InvalidData))?
                != 0
            {
                return Err(store_error(SyncStoreErrorKind::InvalidData));
            }
            let candidate = LocalStorage {
                id: expected.storage_id,
                kind: StorageKind::Remote,
                name: expected.display_name.clone(),
                server_url: Some(expected.address.clone()),
                server_name: None,
                server_fingerprint: Some(expected.server_fingerprint.clone()),
                account_subject: Some(expected.account_subject.clone()),
                personal_vaults_enabled,
                auth_method: Some(expected.auth_method),
            };
            storage_repository
                .insert_if_absent(&candidate)
                .await
                .map_err(|_| store_error(SyncStoreErrorKind::Unavailable))?;
        }
        let storage = self.exact_local_storage(&expected).await?;
        if storage.personal_vaults_enabled != personal_vaults_enabled {
            return Err(store_error(SyncStoreErrorKind::InvalidData));
        }
        let candidate = InstalledAuthorization {
            target: target.clone(),
            generation: Some(generation),
            expected,
        };
        if let Some(installed) = self.authorization.get() {
            ensure_same_authorization(installed, &candidate)?;
        } else if let Err(candidate) = self.authorization.set(candidate) {
            let installed = self.installed()?;
            // A racing resolver installed first; it must be byte-for-byte the
            // same authorization or this store is permanently fail-closed.
            ensure_same_authorization(installed, &candidate)?;
        }
        self.database.verify_identity().await?;
        storage_binding_proof(&storage).map(ResolvedSyncTarget::new)
    }

    async fn reconcile_existing_catalog(
        self: &Arc<Self>,
        target: &ResolvedSyncTarget,
        catalog: &CatalogSnapshot,
    ) -> Result<ReconciledCatalog, SyncStoreError> {
        let installed = self.installed()?;
        let generation = installed
            .generation
            .as_ref()
            .ok_or_else(|| store_error(SyncStoreErrorKind::StaleCheckpoint))?;
        self.database.verify_identity().await?;
        let storage = self.exact_local_storage(&installed.expected).await?;
        ensure_resolved_target_matches(target, &storage)?;
        let expectations = catalog
            .vaults()
            .iter()
            .map(CatalogExpectation::from)
            .collect::<Vec<_>>();
        let resolved = reconcile_catalog_rows(
            &self.database,
            &self.config,
            generation,
            &storage,
            &self.master_key,
            expectations.as_slice(),
        )
        .await?;

        let current_storage = self.exact_local_storage(&installed.expected).await?;
        ensure_same_storage(&storage, &current_storage)?;
        ReconciledCatalog::new(resolved).map_err(map_model_error)
    }

    async fn checkpoint(&self, scope: SyncScope) -> Result<SyncCheckpoint, SyncStoreError> {
        self.ensure_scope(scope).await?;
        let (checkpoint, pending) = PendingChangeRepo::new(self.database.pool())
            .load_checkpoint_with_pending_max(
                scope.storage_id(),
                scope.vault_id(),
                MAX_PENDING_CHANGES,
            )
            .await
            .map_err(map_projection_read)?;
        let cursor = checkpoint
            .as_ref()
            .and_then(|value| value.cursor.as_ref())
            .map(|value| SyncCursor::new(value.clone()))
            .transpose()
            .map_err(map_model_error)?;
        let last_seq = checkpoint
            .and_then(|value| value.last_seq)
            .map(SyncSeq::new)
            .transpose()
            .map_err(map_model_error)?;
        let pending = pending
            .iter()
            .map(|change| pending_proof(scope, change))
            .collect::<Result<Vec<_>, _>>()?;
        SyncCheckpoint::new(cursor, last_seq, pending).map_err(map_model_error)
    }

    async fn item_states(
        &self,
        scope: SyncScope,
        item_ids: &[Uuid],
    ) -> Result<Vec<ItemState>, SyncStoreError> {
        if item_ids.len() > MAX_ITEM_STATE_IDS
            || item_ids.iter().any(Uuid::is_nil)
            || item_ids.iter().copied().collect::<HashSet<_>>().len() != item_ids.len()
        {
            return Err(store_error(SyncStoreErrorKind::InvalidData));
        }
        self.ensure_scope(scope).await?;
        let item_repository = LocalItemRepo::new(self.database.pool());
        let pending_repository = PendingChangeRepo::new(self.database.pool());
        let mut states = Vec::with_capacity(item_ids.len());
        for item_id in item_ids {
            let item = item_repository
                .get_by_id_bounded(scope.storage_id(), *item_id)
                .await
                .map_err(map_projection_read)?;
            let pending = pending_repository
                .get_by_item_bounded(scope.storage_id(), *item_id)
                .await
                .map_err(map_projection_read)?;
            let mut state = match item {
                Some(item) => {
                    if item.vault_id != scope.vault_id() {
                        return Err(store_error(SyncStoreErrorKind::InvalidData));
                    }
                    ItemState::exact(item_proof(scope, &item)?)
                }
                None => ItemState::absent(*item_id).map_err(map_model_error)?,
            };
            if let Some(pending) = pending {
                state = state.with_pending(pending_proof(scope, &pending)?);
            }
            states.push(state);
        }
        Ok(states)
    }

    async fn apply_pull_page(
        self: &Arc<Self>,
        commit: PullPageCommit,
    ) -> Result<PullCommitReceipt, SyncStoreError> {
        let installed = self.installed()?;
        let generation = installed
            .generation
            .as_ref()
            .ok_or_else(|| store_error(SyncStoreErrorKind::StaleCheckpoint))?;
        let storage = self.ensure_scope(commit.scope()).await?;
        let local_scope = local_scope(commit.scope());
        let mut changes = Vec::with_capacity(commit.changes().len());
        for change in commit.changes() {
            if !matches!(change.expected().pending(), PendingExpectation::Absent) {
                return Err(store_error(SyncStoreErrorKind::PendingChanged));
            }
            let expected = match change.expected().exact_proof() {
                None => LocalItemExpectation::Absent,
                Some(proof) => {
                    let item = local_item_from_projection(proof.projection(), proof.sync_status())?;
                    LocalItemExpectation::Exact(Box::new(
                        LocalItemProof::try_from(&item).map_err(map_local_sync_error)?,
                    ))
                }
            };
            let item = local_item_from_projection(change.item(), change.item().sync_status())?;
            let history = change
                .history()
                .iter()
                .map(|entry| {
                    if entry.authority() != HistoryAuthority::ServerConfirmed {
                        return Err(store_error(SyncStoreErrorKind::InvalidData));
                    }
                    Ok(LocalItemHistory {
                        id: entry.history_id(),
                        storage_id: entry.scope().storage_id(),
                        vault_id: entry.scope().vault_id(),
                        item_id: entry.item_id(),
                        payload_enc: entry.payload_enc().to_vec(),
                        checksum: entry.checksum().to_hex(),
                        version: entry.version().get(),
                        change_type: entry.change_type(),
                        changed_by_email: entry.changed_by_email().to_string(),
                        changed_by_name: entry.changed_by_name().map(str::to_string),
                        changed_by_device_id: None,
                        changed_by_device_name: None,
                        source: HistorySource::Server,
                        sync_status: HistorySyncStatus::Confirmed,
                        created_at: entry.created_at(),
                    })
                })
                .collect::<Result<Vec<_>, SyncStoreError>>()?;
            changes.push(
                PullChange::new(local_scope, expected, item, history)
                    .map_err(map_local_sync_error)?,
            );
        }
        let page = PullPage::new(
            local_scope,
            commit.cache_key_fingerprint().to_string(),
            commit
                .expected_cursor()
                .map(|value| value.as_str().to_string()),
            commit.expected_last_seq().map(SyncSeq::get),
            commit.next_cursor().as_str().to_string(),
            commit.next_last_seq().map(SyncSeq::get),
            commit.committed_at(),
            changes,
        )
        .map_err(map_local_sync_error)?;
        let current_storage = self.exact_local_storage(&installed.expected).await?;
        ensure_same_storage(&storage, &current_storage)?;
        commit_leased_pull_page(&self.database, &self.config, generation, &storage, &page).await
    }

    async fn apply_push(
        self: &Arc<Self>,
        commit: PushCommitPlan,
    ) -> Result<PushCommitReceipt, SyncStoreError> {
        let installed = self.installed()?;
        let generation = installed
            .generation
            .as_ref()
            .ok_or_else(|| store_error(SyncStoreErrorKind::StaleCheckpoint))?;
        let storage = self.ensure_scope(commit.scope()).await?;
        let mut outcomes = Vec::with_capacity(commit.changes().len());
        for change in commit.changes() {
            let expected = change
                .expected()
                .exact_proof()
                .ok_or_else(|| store_error(SyncStoreErrorKind::StaleItem))?;
            let pending = change.pending();
            let local_pending = LocalPendingChange {
                id: pending.pending_id(),
                storage_id: pending.scope().storage_id(),
                vault_id: pending.scope().vault_id(),
                item_id: pending.item_id(),
                operation: pending.operation(),
                payload_enc: pending.payload_enc().map(<[u8]>::to_vec),
                checksum: pending.checksum().map(ContentChecksum::to_hex),
                path: pending.path().map(str::to_string),
                name: pending.name().map(str::to_string),
                type_id: pending.type_id().map(str::to_string),
                base_seq: pending.base_seq().map(SyncSeq::get),
                created_at: pending.created_at(),
            };
            let local_pending = zann_db::local::LocalPendingProof::try_from(&local_pending)
                .map_err(map_local_sync_error)?;
            let expected_item =
                local_item_from_projection(expected.projection(), expected.sync_status())?;
            let expected_item = LocalItemExpectation::Exact(Box::new(
                LocalItemProof::try_from(&expected_item).map_err(map_local_sync_error)?,
            ));
            let applied = local_item_from_projection(change.item(), SyncStatus::Synced)?;
            outcomes.push(
                PushOutcome::applied(
                    local_scope(commit.scope()),
                    local_pending,
                    expected_item,
                    applied,
                )
                .map_err(map_local_sync_error)?,
            );
        }
        let local = PushCommit::new(
            local_scope(commit.scope()),
            commit
                .expected_cursor()
                .map(|value| value.as_str().to_string()),
            commit.expected_last_seq().map(SyncSeq::get),
            commit.server_head_hint().as_str().to_string(),
            outcomes,
        )
        .map_err(map_local_sync_error)?;
        self.database.verify_identity().await?;
        let lease = self
            .config
            .acquire_sync_commit_lease(generation)
            .await
            .map_err(map_config_lease_error)?;
        self.database.verify_identity().await?;
        let storage_proof = LocalStorageProof::try_from(&storage).map_err(map_local_sync_error)?;
        let generation_proof = local_generation_proof(lease.generation());
        let receipt = LocalSyncRepo::new(self.database.pool())
            .commit_push_leased(&local, &storage_proof, &generation_proof)
            .await
            .map_err(map_local_sync_error)?;
        self.database
            .verify_identity()
            .await
            .map_err(|_| store_error(SyncStoreErrorKind::CommitOutcomeUnknown))?;
        let server_head =
            SyncCursor::new(receipt.server_head_hint().to_string()).map_err(map_model_error)?;
        Ok(PushCommitReceipt::new(
            receipt.pending_deleted(),
            server_head,
        ))
    }
}

async fn commit_leased_pull_page(
    database: &AdapterDatabase,
    config: &ConfigRepository,
    generation: &Arc<AuthorizedTargetGeneration>,
    storage: &LocalStorage,
    page: &PullPage,
) -> Result<PullCommitReceipt, SyncStoreError> {
    database.verify_identity().await?;
    let lease = config
        .acquire_sync_commit_lease(generation)
        .await
        .map_err(map_config_lease_error)?;
    // Revalidate the pinned file and logical database identity while the
    // exact config generation is leased.  This closes the gap between the
    // advisory preflight check and the SQLite writer transaction.
    database.verify_identity().await?;
    let storage_proof = LocalStorageProof::try_from(storage).map_err(map_local_sync_error)?;
    let generation_proof = local_generation_proof(lease.generation());
    let receipt = LocalSyncRepo::new(database.pool())
        .commit_pull_page_leased(page, &storage_proof, &generation_proof)
        .await
        .map_err(map_local_sync_error)?;
    database
        .verify_identity()
        .await
        .map_err(|_| store_error(SyncStoreErrorKind::CommitOutcomeUnknown))?;
    let cursor = SyncCursor::new(receipt.cursor().to_string()).map_err(map_model_error)?;
    let last_seq = receipt
        .last_seq()
        .map(SyncSeq::new)
        .transpose()
        .map_err(map_model_error)?;
    PullCommitReceipt::new(receipt.items(), receipt.history_entries(), cursor, last_seq)
        .map_err(map_model_error)
}

fn resolve_catalog_key(
    master_key: &SecretKey,
    vault_id: Uuid,
    plane: VaultPlane,
    vault_key_envelope: &[u8],
) -> Result<(VaultKind, KeyWrapType, VaultPayloadKey), SyncStoreError> {
    match plane {
        VaultPlane::PersonalClient => {
            let key = zann_crypto::decrypt_vault_key(master_key, vault_id, vault_key_envelope)
                .map_err(|_| store_error(SyncStoreErrorKind::StaleKeyBinding))?;
            Ok((
                VaultKind::Personal,
                KeyWrapType::RemoteStrict,
                VaultPayloadKey::from_secret_key(key),
            ))
        }
        VaultPlane::SharedServer => Ok((
            VaultKind::Shared,
            KeyWrapType::RemoteServer,
            VaultPayloadKey::copy_from_secret_key(master_key),
        )),
    }
}

async fn reconcile_catalog_rows(
    database: &AdapterDatabase,
    config: &ConfigRepository,
    generation: &Arc<AuthorizedTargetGeneration>,
    storage: &LocalStorage,
    master_key: &SecretKey,
    catalog: &[CatalogExpectation<'_>],
) -> Result<Vec<ResolvedSyncVault>, SyncStoreError> {
    let storage_proof = LocalStorageProof::try_from(storage).map_err(map_local_sync_error)?;
    let vault_repository = LocalVaultRepo::new(database.pool());
    if catalog.is_empty() {
        database.verify_identity().await?;
        let lease = config
            .acquire_sync_commit_lease(generation)
            .await
            .map_err(map_config_lease_error)?;
        database.verify_identity().await?;
        let generation_proof = local_generation_proof(lease.generation());
        vault_repository
            .bind_cache_key_fingerprints_leased(&storage_proof, &generation_proof, &[])
            .await
            .map_err(map_key_bind_error)?;
        database
            .verify_identity()
            .await
            .map_err(|_| store_error(SyncStoreErrorKind::CommitOutcomeUnknown))?;
        return Ok(Vec::new());
    }
    if !storage.personal_vaults_enabled
        && catalog
            .iter()
            .any(|vault| vault.plane == VaultPlane::PersonalClient)
    {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }

    let mut local_vaults = vault_repository
        .list_by_storage_bounded(storage.id)
        .await
        .map_err(map_projection_read)?;
    if local_vaults.len() > catalog.len() {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    let existing_ids = local_vaults
        .iter()
        .map(|vault| vault.id)
        .collect::<HashSet<_>>();
    for remote in catalog {
        if existing_ids.contains(&remote.id) {
            continue;
        }
        let (kind, key_wrap_type) = match remote.plane {
            VaultPlane::PersonalClient => (VaultKind::Personal, KeyWrapType::RemoteStrict),
            VaultPlane::SharedServer => (VaultKind::Shared, KeyWrapType::RemoteServer),
        };
        vault_repository
            .insert_if_absent(&LocalVault {
                id: remote.id,
                storage_id: storage.id,
                slug: remote.slug.to_string(),
                name: remote.name.to_string(),
                kind,
                is_default: false,
                vault_key_enc: remote.vault_key_envelope.to_vec(),
                key_wrap_type,
                cache_key_fp: None,
                last_synced_at: None,
            })
            .await
            .map_err(|_| store_error(SyncStoreErrorKind::Unavailable))?;
    }
    local_vaults = vault_repository
        .list_by_storage_bounded(storage.id)
        .await
        .map_err(map_projection_read)?;
    if local_vaults.len() != catalog.len() {
        return Err(store_error(SyncStoreErrorKind::NotFound));
    }
    let local_by_id: HashMap<_, _> = local_vaults.iter().map(|vault| (vault.id, vault)).collect();
    if local_by_id.len() != local_vaults.len() {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }

    let mut resolved = Vec::with_capacity(catalog.len());
    let mut fingerprints = Vec::with_capacity(catalog.len());
    for remote in catalog {
        let local = local_by_id
            .get(&remote.id)
            .copied()
            .ok_or_else(|| store_error(SyncStoreErrorKind::NotFound))?;
        let (kind, wrap_type, payload_key) = resolve_catalog_key(
            master_key,
            remote.id,
            remote.plane,
            remote.vault_key_envelope,
        )?;
        if local.storage_id != storage.id
            || local.slug != remote.slug
            || local.name != remote.name
            || local.kind != kind
            || local.is_default
            || local.vault_key_enc != remote.vault_key_envelope
            || local.key_wrap_type != wrap_type
        {
            return Err(store_error(SyncStoreErrorKind::InvalidData));
        }
        let fingerprint = payload_key.cache_key_fingerprint();
        match local.cache_key_fp.as_deref() {
            Some(stored) if stored == fingerprint => {}
            Some(_) => return Err(store_error(SyncStoreErrorKind::StaleKeyBinding)),
            None => {}
        }
        fingerprints.push(fingerprint.to_string());
        let scope = SyncScope::new(storage.id, remote.id).map_err(map_model_error)?;
        resolved.push(ResolvedSyncVault::new(scope, remote.plane, payload_key));
    }

    // The database repeats every envelope/wrap/fingerprint proof and all
    // NULL-binding emptiness proofs in one writer-serialized transaction
    // before the first monotonic transition.
    let bindings = catalog
        .iter()
        .zip(&fingerprints)
        .map(|(remote, fingerprint)| CacheKeyFingerprintBinding {
            storage_id: storage.id,
            vault_id: remote.id,
            expected_slug: remote.slug,
            expected_name: remote.name,
            expected_kind: match remote.plane {
                VaultPlane::PersonalClient => VaultKind::Personal,
                VaultPlane::SharedServer => VaultKind::Shared,
            },
            expected_is_default: false,
            expected_vault_key_enc: remote.vault_key_envelope,
            expected_key_wrap_type: match remote.plane {
                VaultPlane::PersonalClient => KeyWrapType::RemoteStrict,
                VaultPlane::SharedServer => KeyWrapType::RemoteServer,
            },
            target_cache_key_fp: fingerprint,
        })
        .collect::<Vec<_>>();
    database.verify_identity().await?;
    let lease = config
        .acquire_sync_commit_lease(generation)
        .await
        .map_err(map_config_lease_error)?;
    database.verify_identity().await?;
    let generation_proof = local_generation_proof(lease.generation());
    vault_repository
        .bind_cache_key_fingerprints_leased(&storage_proof, &generation_proof, &bindings)
        .await
        .map_err(map_key_bind_error)?;
    database
        .verify_identity()
        .await
        .map_err(|_| store_error(SyncStoreErrorKind::CommitOutcomeUnknown))?;

    let rebound = vault_repository
        .list_by_storage_bounded(storage.id)
        .await
        .map_err(map_projection_read)?;
    ensure_catalog_rows_match(storage.id, catalog, &rebound, &fingerprints)?;
    Ok(resolved)
}

#[cfg(test)]
async fn reconcile_catalog_rows_for_test(
    pool: &SqlitePool,
    storage: &LocalStorage,
    master_key: &SecretKey,
    catalog: &[CatalogExpectation<'_>],
) -> Result<Vec<ResolvedSyncVault>, SyncStoreError> {
    let storage_proof = LocalStorageProof::try_from(storage).map_err(map_local_sync_error)?;
    let vault_repository = LocalVaultRepo::new(pool);
    if catalog.is_empty() {
        vault_repository
            .bind_cache_key_fingerprints(&storage_proof, &[])
            .await
            .map_err(map_key_bind_error)?;
        return Ok(Vec::new());
    }
    if !storage.personal_vaults_enabled
        && catalog
            .iter()
            .any(|vault| vault.plane == VaultPlane::PersonalClient)
    {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    let local_vaults = vault_repository
        .list_by_storage_bounded(storage.id)
        .await
        .map_err(map_projection_read)?;
    if local_vaults.len() != catalog.len() {
        return Err(store_error(SyncStoreErrorKind::NotFound));
    }
    let local_by_id: HashMap<_, _> = local_vaults.iter().map(|vault| (vault.id, vault)).collect();
    if local_by_id.len() != local_vaults.len() {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }

    let mut resolved = Vec::with_capacity(catalog.len());
    let mut fingerprints = Vec::with_capacity(catalog.len());
    for remote in catalog {
        let local = local_by_id
            .get(&remote.id)
            .copied()
            .ok_or_else(|| store_error(SyncStoreErrorKind::NotFound))?;
        let (kind, wrap_type, payload_key) = resolve_catalog_key(
            master_key,
            remote.id,
            remote.plane,
            remote.vault_key_envelope,
        )?;
        if local.storage_id != storage.id
            || local.slug != remote.slug
            || local.name != remote.name
            || local.kind != kind
            || local.is_default
            || local.vault_key_enc != remote.vault_key_envelope
            || local.key_wrap_type != wrap_type
        {
            return Err(store_error(SyncStoreErrorKind::InvalidData));
        }
        let fingerprint = payload_key.cache_key_fingerprint();
        match local.cache_key_fp.as_deref() {
            Some(stored) if stored == fingerprint => {}
            Some(_) => return Err(store_error(SyncStoreErrorKind::StaleKeyBinding)),
            None => {}
        }
        fingerprints.push(fingerprint.to_string());
        let scope = SyncScope::new(storage.id, remote.id).map_err(map_model_error)?;
        resolved.push(ResolvedSyncVault::new(scope, remote.plane, payload_key));
    }
    let bindings = catalog
        .iter()
        .zip(&fingerprints)
        .map(|(remote, fingerprint)| CacheKeyFingerprintBinding {
            storage_id: storage.id,
            vault_id: remote.id,
            expected_slug: remote.slug,
            expected_name: remote.name,
            expected_kind: match remote.plane {
                VaultPlane::PersonalClient => VaultKind::Personal,
                VaultPlane::SharedServer => VaultKind::Shared,
            },
            expected_is_default: false,
            expected_vault_key_enc: remote.vault_key_envelope,
            expected_key_wrap_type: match remote.plane {
                VaultPlane::PersonalClient => KeyWrapType::RemoteStrict,
                VaultPlane::SharedServer => KeyWrapType::RemoteServer,
            },
            target_cache_key_fp: fingerprint,
        })
        .collect::<Vec<_>>();
    vault_repository
        .bind_cache_key_fingerprints(&storage_proof, &bindings)
        .await
        .map_err(map_key_bind_error)?;
    let rebound = vault_repository
        .list_by_storage_bounded(storage.id)
        .await
        .map_err(map_projection_read)?;
    ensure_catalog_rows_match(storage.id, catalog, &rebound, &fingerprints)?;
    Ok(resolved)
}

#[cfg(test)]
async fn commit_bound_pull_page_for_test(
    pool: &SqlitePool,
    storage: &LocalStorage,
    page: &PullPage,
) -> Result<PullCommitReceipt, SyncStoreError> {
    let storage_proof = LocalStorageProof::try_from(storage).map_err(map_local_sync_error)?;
    let receipt = LocalSyncRepo::new(pool)
        .commit_pull_page_bound(page, &storage_proof)
        .await
        .map_err(map_local_sync_error)?;
    let cursor = SyncCursor::new(receipt.cursor().to_string()).map_err(map_model_error)?;
    let last_seq = receipt
        .last_seq()
        .map(SyncSeq::new)
        .transpose()
        .map_err(map_model_error)?;
    PullCommitReceipt::new(receipt.items(), receipt.history_entries(), cursor, last_seq)
        .map_err(map_model_error)
}

fn ensure_catalog_rows_match(
    storage_id: Uuid,
    catalog: &[CatalogExpectation<'_>],
    local: &[zann_db::local::LocalVault],
    fingerprints: &[String],
) -> Result<(), SyncStoreError> {
    if local.len() != catalog.len() || fingerprints.len() != catalog.len() {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    let local_by_id: HashMap<_, _> = local.iter().map(|vault| (vault.id, vault)).collect();
    if local_by_id.len() != local.len() {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    for (remote, fingerprint) in catalog.iter().zip(fingerprints) {
        let local = local_by_id
            .get(&remote.id)
            .copied()
            .ok_or_else(|| store_error(SyncStoreErrorKind::NotFound))?;
        let (kind, wrap_type) = match remote.plane {
            VaultPlane::PersonalClient => (VaultKind::Personal, KeyWrapType::RemoteStrict),
            VaultPlane::SharedServer => (VaultKind::Shared, KeyWrapType::RemoteServer),
        };
        if local.storage_id != storage_id
            || local.slug != remote.slug
            || local.name != remote.name
            || local.kind != kind
            || local.is_default
            || local.vault_key_enc != remote.vault_key_envelope
            || local.key_wrap_type != wrap_type
            || local.cache_key_fp.as_deref() != Some(fingerprint)
        {
            return Err(store_error(SyncStoreErrorKind::StaleKeyBinding));
        }
    }
    Ok(())
}

impl SyncLocalStore for SqliteSyncStore {
    fn resolve_target<'a>(
        &'a self,
        target: &'a SessionTarget,
        generation: Arc<AuthorizedTargetGeneration>,
        personal_vaults_enabled: bool,
    ) -> SyncStoreFuture<'a, ResolvedSyncTarget> {
        Box::pin(async move {
            self.resolve_exact_target(target, generation, personal_vaults_enabled)
                .await
        })
    }

    fn reconcile_catalog(
        self: Arc<Self>,
        target: Arc<ResolvedSyncTarget>,
        catalog: Arc<CatalogSnapshot>,
    ) -> SyncStoreFuture<'static, ReconciledCatalog> {
        let worker = Arc::clone(&self);
        self.dispatch_terminal_mutation(async move {
            worker.reconcile_existing_catalog(&target, &catalog).await
        })
    }

    fn load_checkpoint<'a>(&'a self, scope: SyncScope) -> SyncStoreFuture<'a, SyncCheckpoint> {
        Box::pin(async move { self.checkpoint(scope).await })
    }

    fn load_item_states<'a>(
        &'a self,
        scope: SyncScope,
        item_ids: &'a [Uuid],
    ) -> SyncStoreFuture<'a, Vec<ItemState>> {
        Box::pin(async move { self.item_states(scope, item_ids).await })
    }

    fn prepare_generated_key(
        self: Arc<Self>,
        scope: SyncScope,
        expected_remote_envelope: Vec<u8>,
    ) -> SyncStoreFuture<'static, GeneratedVaultKeyCommit> {
        Box::pin(async move {
            if !expected_remote_envelope.is_empty() {
                return Err(store_error(SyncStoreErrorKind::StaleKeyBinding));
            }
            let installed = self.installed()?;
            if scope.storage_id() != installed.expected.storage_id {
                return Err(store_error(SyncStoreErrorKind::InvalidData));
            }
            self.database.verify_identity().await?;
            self.exact_local_storage(&installed.expected).await?;
            let generated = SecretKey::generate();
            let published =
                zann_crypto::encrypt_vault_key(&self.master_key, scope.vault_id(), &generated)
                    .map_err(|_| store_error(SyncStoreErrorKind::Internal))?;
            GeneratedVaultKeyCommit::new(
                scope,
                expected_remote_envelope,
                published,
                VaultPayloadKey::from_secret_key(generated),
            )
            .map_err(map_model_error)
        })
    }

    fn commit_generated_key(
        self: Arc<Self>,
        commit: GeneratedVaultKeyCommit,
    ) -> SyncStoreFuture<'static, ()> {
        Box::pin(async move {
            if !commit.expected_remote_envelope().is_empty() {
                return Err(store_error(SyncStoreErrorKind::StaleKeyBinding));
            }
            let installed = self.installed()?;
            if commit.scope().storage_id() != installed.expected.storage_id {
                return Err(store_error(SyncStoreErrorKind::InvalidData));
            }
            self.database.verify_identity().await?;
            self.exact_local_storage(&installed.expected).await?;
            let decrypted = zann_crypto::decrypt_vault_key(
                &self.master_key,
                commit.scope().vault_id(),
                commit.published_envelope(),
            )
            .map_err(|_| store_error(SyncStoreErrorKind::StaleKeyBinding))?;
            if zann_crypto::cache_key_fingerprint(&decrypted)
                != commit.generated_key().cache_key_fingerprint()
            {
                return Err(store_error(SyncStoreErrorKind::StaleKeyBinding));
            }
            Ok(())
        })
    }

    fn commit_push(
        self: Arc<Self>,
        commit: PushCommitPlan,
    ) -> SyncStoreFuture<'static, PushCommitReceipt> {
        let worker = Arc::clone(&self);
        self.dispatch_terminal_mutation(async move { worker.apply_push(commit).await })
    }

    fn commit_pull_page(
        self: Arc<Self>,
        commit: PullPageCommit,
    ) -> SyncStoreFuture<'static, PullCommitReceipt> {
        let worker = Arc::clone(&self);
        self.dispatch_terminal_mutation(async move { worker.apply_pull_page(commit).await })
    }

    fn reset_projection_if_clean(
        self: Arc<Self>,
        _reset: ProjectionReset,
    ) -> SyncStoreFuture<'static, ()> {
        Box::pin(async { Err(store_error(SyncStoreErrorKind::Unavailable)) })
    }
}

/// Owned, synchronous admission for the adapter's detached mutations.
///
/// At most one catalog or pull payload can be queued/running across all store
/// instances in this process. The permit is moved into the spawned terminal
/// task, so dropping the caller's outer future cannot release admission before
/// the mutation has finished.
struct MutationPermit {
    _private: (),
}

impl MutationPermit {
    fn try_acquire() -> Result<Self, SyncStoreError> {
        TERMINAL_MUTATION_IN_FLIGHT
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| store_error(SyncStoreErrorKind::Busy))?;
        Ok(Self { _private: () })
    }
}

impl Drop for MutationPermit {
    fn drop(&mut self) {
        TERMINAL_MUTATION_IN_FLIGHT.store(false, Ordering::Release);
    }
}

/// Dispatches a mutating adapter operation before returning its outer future.
///
/// Once a mutation is dispatched, dropping the returned future only detaches
/// the join handle: the owned task keeps the config lease alive through the
/// SQLite COMMIT and the post-commit identity check. A task failure is
/// conservatively ambiguous. If no Tokio runtime is active, no task and no
/// mutation is started.
fn terminal_mutation<T, F>(mutation: F) -> SyncStoreFuture<'static, T>
where
    T: Send + 'static,
    F: Future<Output = Result<T, SyncStoreError>> + Send + 'static,
{
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        drop(mutation);
        return Box::pin(async { Err(store_error(SyncStoreErrorKind::Unavailable)) });
    };
    // Spawning is intentionally synchronous in this ordinary function. If a
    // caller drops the returned future without polling it, the mutation has
    // already become an owned terminal task rather than an unstarted future.
    let task = runtime.spawn(mutation);
    Box::pin(async move {
        task.await
            .map_err(|_| store_error(SyncStoreErrorKind::CommitOutcomeUnknown))?
    })
}

#[cfg(test)]
fn capture_target_binding_for_test(
    repository: &ConfigRepository,
    target: &SessionTarget,
    master_key: &SecretKey,
) -> Result<TargetBinding, SyncStoreError> {
    for _ in 0..CONFIG_CAPTURE_ATTEMPTS {
        let anchor = repository
            .resolve_credential_profile_anchor(target.connection_id(), target.profile_name())
            .map_err(map_config_lease_error)?;
        let snapshot = repository.snapshot().map_err(map_config_lease_error)?;
        let confirmation = repository
            .resolve_credential_profile_anchor(target.connection_id(), target.profile_name())
            .map_err(map_config_lease_error)?;
        if snapshot.revision() != anchor.source_revision() || anchor != confirmation {
            continue;
        }
        let config = snapshot.config();
        if config.connections.len() != 1 {
            return Err(store_error(SyncStoreErrorKind::InvalidData));
        }
        let connection = config
            .connections
            .get(target.connection_id())
            .ok_or_else(|| store_error(SyncStoreErrorKind::NotFound))?;
        if connection.credential_profiles().len() != 1 {
            return Err(store_error(SyncStoreErrorKind::InvalidData));
        }
        let profile = connection
            .credential_profiles()
            .get(target.profile_name())
            .ok_or_else(|| store_error(SyncStoreErrorKind::NotFound))?;
        if profile.account_subject() != anchor.account_subject()
            || profile.auth_method() != anchor.auth_method()
            || profile.credentials() != anchor.credentials()
        {
            continue;
        }
        return target_binding_from_anchor_for_test(
            target,
            connection.metadata().name.as_str(),
            &anchor,
            master_key,
        );
    }
    Err(store_error(SyncStoreErrorKind::Busy))
}

#[cfg(test)]
fn target_binding_from_anchor_for_test(
    target: &SessionTarget,
    display_name: &str,
    anchor: &CredentialProfileAnchor,
    master_key: &SecretKey,
) -> Result<TargetBinding, SyncStoreError> {
    if anchor.connection_id() != target.connection_id()
        || anchor.profile_name() != target.profile_name()
        || display_name.is_empty()
    {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    let server_id = required(anchor.server_id())?;
    let server_fingerprint = required(anchor.server_fingerprint())?;
    let storage_id = canonical_uuid(required(anchor.storage_id())?)?;
    let account_subject = required(anchor.account_subject())?;
    canonical_uuid(account_subject)?;
    let auth_method = anchor
        .auth_method()
        .ok_or_else(|| store_error(SyncStoreErrorKind::InvalidData))?;
    if anchor.credentials().is_empty()
        || !anchor.credentials().contains_key(&CredentialKind::Access)
    {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    let expected_master = required(anchor.expected_master_key_fp())?;
    if !canonical_cache_fingerprint(expected_master) {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    if expected_master != zann_crypto::cache_key_fingerprint(master_key) {
        return Err(store_error(SyncStoreErrorKind::StaleKeyBinding));
    }
    Ok(TargetBinding {
        connection_id: target.connection_id().clone(),
        profile_name: target.profile_name().to_string(),
        display_name: display_name.to_string(),
        address: anchor.address().to_string(),
        server_id: server_id.to_string(),
        server_fingerprint: server_fingerprint.to_string(),
        storage_id,
        master_key_fingerprint: expected_master.to_string(),
        account_subject: account_subject.to_string(),
        auth_method,
    })
}

fn target_binding_from_generation(
    target: &SessionTarget,
    generation: &AuthorizedTargetGeneration,
    master_key: &SecretKey,
) -> Result<TargetBinding, SyncStoreError> {
    ensure_single_target_topology(generation.single_target_topology())?;
    if generation.connection_id() != target.connection_id()
        || generation.profile_name() != target.profile_name()
        || generation.display_name().is_empty()
        || generation.address().is_empty()
    {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    let server_id = required(generation.server_id())?;
    let server_fingerprint = required(generation.server_fingerprint())?;
    let storage_id_text = required(generation.storage_id())?;
    let storage_id = canonical_uuid(storage_id_text)?;
    let account_subject = required(generation.account_subject())?;
    canonical_uuid(account_subject)?;
    let auth_method = generation
        .auth_method()
        .ok_or_else(|| store_error(SyncStoreErrorKind::InvalidData))?;
    let expected_master = required(generation.expected_master_key_fingerprint())?;
    if !canonical_cache_fingerprint(expected_master) {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    if expected_master != zann_crypto::cache_key_fingerprint(master_key) {
        return Err(store_error(SyncStoreErrorKind::StaleKeyBinding));
    }
    Ok(TargetBinding {
        connection_id: target.connection_id().clone(),
        profile_name: target.profile_name().to_string(),
        display_name: generation.display_name().to_string(),
        address: generation.address().to_string(),
        server_id: server_id.to_string(),
        server_fingerprint: server_fingerprint.to_string(),
        storage_id,
        master_key_fingerprint: expected_master.to_string(),
        account_subject: account_subject.to_string(),
        auth_method,
    })
}

fn ensure_single_target_topology(proven: bool) -> Result<(), SyncStoreError> {
    if !proven {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    Ok(())
}

fn ensure_same_authorization(
    installed: &InstalledAuthorization,
    candidate: &InstalledAuthorization,
) -> Result<(), SyncStoreError> {
    if installed.target != candidate.target
        || installed.expected != candidate.expected
        || installed.generation.as_ref() != candidate.generation.as_ref()
    {
        return Err(store_error(SyncStoreErrorKind::StaleCheckpoint));
    }
    Ok(())
}

fn local_generation_proof(generation: &AuthorizedTargetGeneration) -> LocalSyncGenerationProof {
    LocalSyncGenerationProof::new(
        *generation.repository_fingerprint(),
        *generation.stable_target_fingerprint(),
        generation.revision(),
        *generation.content_fingerprint(),
    )
}

fn ensure_storage_matches_target(
    storage: &LocalStorage,
    target: &TargetBinding,
) -> Result<(), SyncStoreError> {
    if storage.id != target.storage_id
        || storage.kind != StorageKind::Remote
        || storage.name != target.display_name
        || storage.server_url.as_deref() != Some(target.address.as_str())
        || storage.server_fingerprint.as_deref() != Some(target.server_fingerprint.as_str())
        || storage.account_subject.as_deref() != Some(target.account_subject.as_str())
        || storage.auth_method != Some(target.auth_method)
    {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    Ok(())
}

fn storage_binding_proof(storage: &LocalStorage) -> Result<StorageBindingProof, SyncStoreError> {
    StorageBindingProof::new(
        storage.id,
        storage.name.clone(),
        storage.server_url.clone().unwrap_or_default(),
        storage.server_name.clone(),
        storage.server_fingerprint.clone().unwrap_or_default(),
        storage.account_subject.clone(),
        storage.personal_vaults_enabled,
        storage.auth_method,
    )
    .map_err(map_model_error)
}

fn ensure_resolved_target_matches(
    resolved: &ResolvedSyncTarget,
    storage: &LocalStorage,
) -> Result<(), SyncStoreError> {
    let binding = resolved.binding();
    if binding.storage_id() != storage.id
        || binding.display_name() != storage.name
        || Some(binding.server_url()) != storage.server_url.as_deref()
        || binding.server_name() != storage.server_name.as_deref()
        || Some(binding.server_fingerprint()) != storage.server_fingerprint.as_deref()
        || binding.account_subject() != storage.account_subject.as_deref()
        || binding.personal_vaults_enabled() != storage.personal_vaults_enabled
        || binding.auth_method() != storage.auth_method
    {
        return Err(store_error(SyncStoreErrorKind::StaleCheckpoint));
    }
    Ok(())
}

fn ensure_same_storage(
    expected: &LocalStorage,
    actual: &LocalStorage,
) -> Result<(), SyncStoreError> {
    if expected.id != actual.id
        || expected.kind != actual.kind
        || expected.name != actual.name
        || expected.server_url != actual.server_url
        || expected.server_name != actual.server_name
        || expected.server_fingerprint != actual.server_fingerprint
        || expected.account_subject != actual.account_subject
        || expected.personal_vaults_enabled != actual.personal_vaults_enabled
        || expected.auth_method != actual.auth_method
    {
        return Err(store_error(SyncStoreErrorKind::StaleCheckpoint));
    }
    Ok(())
}

fn item_proof(scope: SyncScope, item: &LocalItem) -> Result<ItemProof, SyncStoreError> {
    let projection = ItemProjection::new(
        scope,
        item.id,
        item.path.clone(),
        item.name.clone(),
        item.type_id.clone(),
        item.payload_enc.clone(),
        ContentChecksum::parse(&item.checksum).map_err(map_model_error)?,
        item.cache_key_fp
            .clone()
            .ok_or_else(|| store_error(SyncStoreErrorKind::StaleKeyBinding))?,
        SyncSeq::new(item.version).map_err(map_model_error)?,
        item.updated_at,
        item.deleted_at,
    )
    .map_err(map_model_error)?;
    Ok(ItemProof::new(projection, item.sync_status))
}

fn pending_proof(
    scope: SyncScope,
    pending: &LocalPendingChange,
) -> Result<PendingProof, SyncStoreError> {
    if pending.storage_id != scope.storage_id() || pending.vault_id != scope.vault_id() {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    let checksum = pending
        .checksum
        .as_deref()
        .map(ContentChecksum::parse)
        .transpose()
        .map_err(map_model_error)?;
    let base_seq = pending
        .base_seq
        .map(SyncSeq::new)
        .transpose()
        .map_err(map_model_error)?;
    PendingProof::new(
        pending.id,
        scope,
        pending.item_id,
        pending.operation,
        pending.payload_enc.clone(),
        checksum,
        pending.path.clone(),
        pending.name.clone(),
        pending.type_id.clone(),
        base_seq,
        pending.created_at,
    )
    .map_err(map_model_error)
}

fn local_item_from_projection(
    projection: &ItemProjection,
    sync_status: SyncStatus,
) -> Result<LocalItem, SyncStoreError> {
    Ok(LocalItem {
        id: projection.item_id(),
        storage_id: projection.scope().storage_id(),
        vault_id: projection.scope().vault_id(),
        path: projection.path().to_string(),
        name: projection.name().to_string(),
        type_id: projection.type_id().to_string(),
        payload_enc: projection.payload_enc().to_vec(),
        checksum: projection.checksum().to_hex(),
        cache_key_fp: Some(projection.cache_key_fingerprint().to_string()),
        version: projection.seq().get(),
        deleted_at: projection.deleted_at(),
        updated_at: projection.updated_at(),
        sync_status,
    })
}

fn local_scope(scope: SyncScope) -> LocalSyncScope {
    LocalSyncScope {
        storage_id: scope.storage_id(),
        vault_id: scope.vault_id(),
    }
}

fn ensure_paths_match_location(
    paths: &ClientPaths,
    location: &SqliteFileLocation,
) -> Result<(), SyncStoreError> {
    if !paths.root().is_absolute()
        || !paths.local_db().is_absolute()
        || paths.root() != location.root()
        || paths.local_db() != location.path()
    {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    Ok(())
}

fn ensure_requested_paths_match(
    paths: &ClientPaths,
    database_path: &Path,
) -> Result<(), SyncStoreError> {
    if !database_path.is_absolute()
        || paths.local_db() != database_path
        || database_path.parent() != Some(paths.root())
    {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    Ok(())
}

fn canonical_uuid(value: &str) -> Result<Uuid, SyncStoreError> {
    let parsed =
        Uuid::parse_str(value).map_err(|_| store_error(SyncStoreErrorKind::InvalidData))?;
    if parsed.to_string() != value {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    Ok(parsed)
}

fn canonical_cache_fingerprint(value: &str) -> bool {
    value.len() == 12
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn required(value: Option<&str>) -> Result<&str, SyncStoreError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| store_error(SyncStoreErrorKind::InvalidData))
}

fn map_config_lease_error(error: ConfigError) -> SyncStoreError {
    match error {
        ConfigError::Busy { .. } => store_error(SyncStoreErrorKind::Busy),
        ConfigError::MissingConfig { .. }
        | ConfigError::MissingConnection { .. }
        | ConfigError::MissingCredentialProfile { .. } => store_error(SyncStoreErrorKind::NotFound),
        ConfigError::RevisionConflict { .. }
        | ConfigError::ConfigContentConflict { .. }
        | ConfigError::CredentialProfileAnchorRepositoryMismatch
        | ConfigError::CredentialProfileAnchorConflict { .. } => {
            store_error(SyncStoreErrorKind::StaleCheckpoint)
        }
        _ => store_error(SyncStoreErrorKind::InvalidData),
    }
}

fn map_key_bind_error(error: LocalVaultKeyBindError) -> SyncStoreError {
    match error {
        LocalVaultKeyBindError::NotFound => store_error(SyncStoreErrorKind::NotFound),
        LocalVaultKeyBindError::KeyBindingChanged | LocalVaultKeyBindError::ProjectionNotEmpty => {
            store_error(SyncStoreErrorKind::StaleKeyBinding)
        }
        LocalVaultKeyBindError::GenerationChanged => {
            store_error(SyncStoreErrorKind::StaleCheckpoint)
        }
        LocalVaultKeyBindError::CommitOutcomeUnknown => {
            store_error(SyncStoreErrorKind::CommitOutcomeUnknown)
        }
        LocalVaultKeyBindError::InvalidInput => store_error(SyncStoreErrorKind::InvalidData),
        LocalVaultKeyBindError::Database(_) => store_error(SyncStoreErrorKind::Internal),
    }
}

fn map_local_sync_error(error: LocalSyncError) -> SyncStoreError {
    match error {
        LocalSyncError::StaleCursor { .. } => store_error(SyncStoreErrorKind::StaleCheckpoint),
        LocalSyncError::StaleItem { .. } => store_error(SyncStoreErrorKind::StaleItem),
        LocalSyncError::StalePending { .. } => store_error(SyncStoreErrorKind::PendingChanged),
        LocalSyncError::StaleVaultKey { .. } => store_error(SyncStoreErrorKind::StaleKeyBinding),
        LocalSyncError::PendingChangesPresent { .. } => {
            store_error(SyncStoreErrorKind::PendingPresent)
        }
        LocalSyncError::CommitOutcomeUnknown => {
            store_error(SyncStoreErrorKind::CommitOutcomeUnknown)
        }
        LocalSyncError::StorageBindingChanged { .. }
        | LocalSyncError::StorageGenerationChanged { .. } => {
            store_error(SyncStoreErrorKind::StaleCheckpoint)
        }
        LocalSyncError::ProjectionNotClean { .. }
        | LocalSyncError::CrossStorageVaultReference { .. }
        | LocalSyncError::InvalidPlan { .. } => store_error(SyncStoreErrorKind::InvalidData),
        LocalSyncError::Database(_) => store_error(SyncStoreErrorKind::Internal),
    }
}

fn map_projection_read(error: LocalProjectionReadError) -> SyncStoreError {
    match error {
        LocalProjectionReadError::InvalidInput
        | LocalProjectionReadError::CorruptProjection
        | LocalProjectionReadError::TooManyRows => store_error(SyncStoreErrorKind::InvalidData),
        LocalProjectionReadError::Database(_) => store_error(SyncStoreErrorKind::Internal),
    }
}

fn map_model_error(_: impl std::error::Error) -> SyncStoreError {
    store_error(SyncStoreErrorKind::InvalidData)
}

const fn store_error(kind: SyncStoreErrorKind) -> SyncStoreError {
    SyncStoreError::new(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use serde_json::json;
    use tempfile::TempDir;
    use zann_client::config::{
        ClientId, ConnectionMetadata, CredentialActivation, CredentialBundle, CredentialPortError,
        CredentialSecret, CredentialStore, LegacyCredentialLocator, LegacyCredentialSource,
    };
    use zann_db::local::{LocalSyncCheckpoint, SyncCursorRepo};

    #[derive(Default)]
    struct MemoryCredentials(Mutex<HashMap<String, String>>);

    impl CredentialStore for MemoryCredentials {
        fn put(
            &self,
            credential_id: &CredentialId,
            secret: &CredentialSecret,
        ) -> Result<(), CredentialPortError> {
            self.0
                .lock()
                .map_err(|_| CredentialPortError::new("credential lock poisoned"))?
                .insert(
                    credential_id.as_str().to_string(),
                    secret.expose_secret().to_string(),
                );
            Ok(())
        }

        fn get(
            &self,
            credential_id: &CredentialId,
        ) -> Result<Option<CredentialSecret>, CredentialPortError> {
            self.0
                .lock()
                .map_err(|_| CredentialPortError::new("credential lock poisoned"))?
                .get(credential_id.as_str())
                .cloned()
                .map(CredentialSecret::new)
                .transpose()
                .map_err(|error| CredentialPortError::new(error.to_string()))
        }

        fn delete(&self, credential_id: &CredentialId) -> Result<(), CredentialPortError> {
            self.0
                .lock()
                .map_err(|_| CredentialPortError::new("credential lock poisoned"))?
                .remove(credential_id.as_str());
            Ok(())
        }
    }

    struct EmptyLegacyCredentials;

    static CWD_LOCK: Mutex<()> = Mutex::new(());
    static TERMINAL_MUTATION_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct CurrentDirGuard(PathBuf);

    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.0).expect("restore adapter test working directory");
        }
    }

    impl LegacyCredentialSource for EmptyLegacyCredentials {
        fn get(
            &self,
            _locator: &LegacyCredentialLocator,
        ) -> Result<Option<CredentialSecret>, CredentialPortError> {
            Ok(None)
        }
    }

    struct ConfigFixture {
        temp: TempDir,
        paths: ClientPaths,
        target: SessionTarget,
        master_key: Arc<SecretKey>,
        storage_id: Uuid,
        account_subject: Uuid,
    }

    fn matching_storage(fixture: &ConfigFixture) -> LocalStorage {
        LocalStorage {
            id: fixture.storage_id,
            kind: StorageKind::Remote,
            name: "Adapter".to_string(),
            server_url: Some("https://adapter.test".to_string()),
            server_name: Some("Adapter Server".to_string()),
            server_fingerprint: Some("server-fingerprint-binding".to_string()),
            account_subject: Some(fixture.account_subject.to_string()),
            personal_vaults_enabled: true,
            auth_method: Some(AuthMethod::Password),
        }
    }

    fn bound_paths(fixture: &ConfigFixture, database_path: &Path) -> ClientPaths {
        ClientPaths::with_local_db(fixture.paths.root(), database_path)
    }

    fn file_location(database_path: &Path) -> SqliteFileLocation {
        SqliteFileLocation::from_path(database_path).expect("resolve adapter database location")
    }

    fn configured_fixture() -> ConfigFixture {
        let temp = TempDir::new().expect("temporary adapter root");
        let paths = ClientPaths::new(temp.path());
        let repository = ConfigRepository::new(paths.clone());
        let credentials = MemoryCredentials::default();
        repository
            .initialize(
                &ClientId::new("adapter-test").expect("client id"),
                &credentials,
                &EmptyLegacyCredentials,
            )
            .expect("initialize config");

        let master_key = Arc::new(SecretKey::from_bytes([7_u8; 32]));
        let storage_id = Uuid::now_v7();
        let account_subject = Uuid::now_v7();
        let connection_id = ConnectionId::deterministic("adapter", "https://adapter.test/");
        let mut metadata = ConnectionMetadata::new("Adapter", "HTTPS://ADAPTER.TEST:443/");
        metadata.server_id = Some("server-identity-binding".to_string());
        metadata.server_fingerprint = Some("server-fingerprint-binding".to_string());
        metadata.storage_id = Some(storage_id.to_string());
        metadata.expected_master_key_fp = Some(zann_crypto::cache_key_fingerprint(&master_key));
        repository
            .upsert_connection(connection_id.clone(), metadata)
            .expect("insert pinned connection");
        repository
            .replace_credential_bundle(
                1,
                &connection_id,
                "profile",
                CredentialBundle::new(
                    Some(CredentialSecret::new("access-token").expect("access secret")),
                    None,
                    None,
                ),
                CredentialActivation::MakeActive,
                &credentials,
            )
            .expect("insert profile credentials");

        // Account/auth binding is normally installed by AppSession's
        // authenticated commit. This test fixture edits only those two fields
        // after the public credential transaction has produced repository-
        // bound credential ids.
        let config_path = paths.config();
        let mut raw: serde_json::Value =
            serde_json::from_slice(&fs::read(&config_path).expect("read adapter config"))
                .expect("parse adapter config");
        raw["connections"][connection_id.as_str()]["credential_profiles"]["profile"]
            ["account_subject"] = json!(account_subject.to_string());
        raw["connections"][connection_id.as_str()]["credential_profiles"]["profile"]
            ["auth_method"] = json!(AuthMethod::Password.as_i32());
        fs::write(
            &config_path,
            serde_json::to_vec_pretty(&raw).expect("serialize adapter config"),
        )
        .expect("write adapter config");

        ConfigFixture {
            temp,
            paths,
            target: SessionTarget::new(connection_id, "profile").expect("session target"),
            master_key,
            storage_id,
            account_subject,
        }
    }

    #[test]
    fn cache_fingerprint_format_is_exact() {
        assert!(canonical_cache_fingerprint("012345abcdef"));
        assert!(!canonical_cache_fingerprint("012345ABCDEf"));
        assert!(!canonical_cache_fingerprint("012345abcdef0"));
        assert!(!canonical_cache_fingerprint(""));
    }

    #[test]
    fn adapter_rejects_an_unproven_single_target_topology_before_binding_conversion() {
        let error = ensure_single_target_topology(false)
            .expect_err("global-UUID adapter requires an exact single-target proof");
        assert_eq!(error.kind(), SyncStoreErrorKind::InvalidData);
        ensure_single_target_topology(true).expect("exact topology is supported");
    }

    #[test]
    fn terminal_mutations_are_process_single_flight_and_release_every_exit() {
        let _serial = TERMINAL_MUTATION_TEST_LOCK
            .lock()
            .expect("serialize process-global terminal admission test");

        let no_runtime_ran = Arc::new(AtomicBool::new(false));
        let no_runtime_ran_in_task = Arc::clone(&no_runtime_ran);
        let no_runtime_permit = MutationPermit::try_acquire().expect("initial terminal permit");
        let no_runtime = terminal_mutation(async move {
            let _permit = no_runtime_permit;
            no_runtime_ran_in_task.store(true, Ordering::Release);
            Ok(())
        });
        assert!(
            !TERMINAL_MUTATION_IN_FLIGHT.load(Ordering::Acquire),
            "missing runtime must synchronously drop and release admission"
        );
        assert!(!no_runtime_ran.load(Ordering::Acquire));

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()
            .expect("terminal mutation test runtime");
        runtime.block_on(async move {
            let no_runtime_error = no_runtime
                .await
                .expect_err("missing runtime must reject before polling mutation");
            assert_eq!(no_runtime_error.kind(), SyncStoreErrorKind::Unavailable);

            let first_fixture = configured_fixture();
            let first_database = first_fixture.temp.path().join("terminal-first.sqlite");
            let first_pool = zann_db::connect_sqlite_path_with_max(&first_database, 1)
                .await
                .expect("open first terminal database");
            let first_store = Arc::new(
                SqliteSyncStore::from_pool(
                    bound_paths(&first_fixture, &first_database),
                    file_location(&first_database),
                    first_pool.clone(),
                    Arc::clone(&first_fixture.master_key),
                    first_fixture.target.clone(),
                )
                .expect("construct first terminal store"),
            );

            let second_fixture = configured_fixture();
            let second_database = second_fixture.temp.path().join("terminal-second.sqlite");
            let second_pool = zann_db::connect_sqlite_path_with_max(&second_database, 1)
                .await
                .expect("open second terminal database");
            let second_store = Arc::new(
                SqliteSyncStore::from_pool(
                    bound_paths(&second_fixture, &second_database),
                    file_location(&second_database),
                    second_pool.clone(),
                    Arc::clone(&second_fixture.master_key),
                    second_fixture.target.clone(),
                )
                .expect("construct second terminal store"),
            );

            let entered = Arc::new(AtomicBool::new(false));
            let release = Arc::new(AtomicBool::new(false));
            let entered_in_task = Arc::clone(&entered);
            let release_in_task = Arc::clone(&release);
            let detached = first_store.dispatch_terminal_mutation(async move {
                entered_in_task.store(true, Ordering::Release);
                while !release_in_task.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
                Ok(())
            });
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while !entered.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("first detached terminal task enters");
            drop(detached);

            for _ in 0..2_048 {
                let rejected_was_polled = Arc::new(AtomicBool::new(false));
                let rejected_was_polled_in_task = Arc::clone(&rejected_was_polled);
                let rejected = second_store.dispatch_terminal_mutation(async move {
                    rejected_was_polled_in_task.store(true, Ordering::Release);
                    Ok(())
                });
                drop(rejected);
                assert!(
                    !rejected_was_polled.load(Ordering::Acquire),
                    "busy payload must be dropped without being spawned or polled"
                );
            }
            let busy = second_store
                .dispatch_terminal_mutation(async { Ok(()) })
                .await
                .expect_err("a second store cannot bypass process-global admission");
            assert_eq!(busy.kind(), SyncStoreErrorKind::Busy);

            release.store(true, Ordering::Release);
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while TERMINAL_MUTATION_IN_FLIGHT.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("detached mutation releases admission after completion");

            let ordinary_error = second_store
                .dispatch_terminal_mutation(async {
                    Err::<(), _>(store_error(SyncStoreErrorKind::InvalidData))
                })
                .await
                .expect_err("terminal task returns its ordinary store error");
            assert_eq!(ordinary_error.kind(), SyncStoreErrorKind::InvalidData);
            assert!(!TERMINAL_MUTATION_IN_FLIGHT.load(Ordering::Acquire));

            let panic_error = first_store
                .dispatch_terminal_mutation::<(), _>(async {
                    panic!("terminal mutation panic fixture");
                })
                .await
                .expect_err("task panic is an ambiguous terminal outcome");
            assert_eq!(panic_error.kind(), SyncStoreErrorKind::CommitOutcomeUnknown);
            assert!(
                !TERMINAL_MUTATION_IN_FLIGHT.load(Ordering::Acquire),
                "task panic must release process-global admission"
            );

            first_pool.close().await;
            second_pool.close().await;
        });
    }

    #[test]
    fn dropped_catalog_outer_keeps_the_sync_gate_until_the_db_claim_finishes() {
        let _serial = TERMINAL_MUTATION_TEST_LOCK
            .lock()
            .expect("serialize process-global terminal admission test");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()
            .expect("catalog cancellation test runtime");
        runtime.block_on(async {
            let fixture = configured_fixture();
            let database_path = fixture.temp.path().join("terminal-catalog.sqlite");
            let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
                .await
                .expect("open catalog terminal database");
            zann_db::migrate_local(&pool)
                .await
                .expect("migrate catalog terminal database");
            let storage = matching_storage(&fixture);
            LocalStorageRepo::new(&pool)
                .upsert(&storage)
                .await
                .expect("insert catalog terminal storage");
            let store = Arc::new(
                SqliteSyncStore::from_pool(
                    bound_paths(&fixture, &database_path),
                    file_location(&database_path),
                    pool.clone(),
                    Arc::clone(&fixture.master_key),
                    fixture.target.clone(),
                )
                .expect("construct catalog terminal store"),
            );

            let config = ConfigRepository::new(fixture.paths.clone());
            let source_revision = config
                .snapshot()
                .expect("prime exact sync gate file")
                .revision();
            let sync_gate = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(fixture.paths.sync_commit_lock())
                .expect("open real Config v2 sync gate");
            let expected_storage =
                LocalStorageProof::try_from(&storage).expect("valid catalog storage proof");
            let generation = LocalSyncGenerationProof::new([1_u8; 32], [2_u8; 32], 7, [3; 32]);
            let worker_pool = pool.clone();
            let entered = Arc::new(AtomicBool::new(false));
            let release = Arc::new(AtomicBool::new(false));
            let committed = Arc::new(AtomicBool::new(false));
            let entered_in_task = Arc::clone(&entered);
            let release_in_task = Arc::clone(&release);
            let committed_in_task = Arc::clone(&committed);
            let outer = store.dispatch_terminal_mutation(async move {
                sync_gate
                    .lock()
                    .map_err(|_| store_error(SyncStoreErrorKind::Unavailable))?;
                entered_in_task.store(true, Ordering::Release);
                while !release_in_task.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
                let result = LocalVaultRepo::new(&worker_pool)
                    .bind_cache_key_fingerprints_leased(&expected_storage, &generation, &[])
                    .await
                    .map_err(map_key_bind_error)
                    .map(|_| ());
                committed_in_task.store(result.is_ok(), Ordering::Release);
                drop(sync_gate);
                result
            });
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while !entered.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("detached catalog task owns the sync gate");
            drop(outer);

            let writer_started = Arc::new(AtomicBool::new(false));
            let writer_started_in_task = Arc::clone(&writer_started);
            let writer_config = config.clone();
            let mut writer = tokio::task::spawn_blocking(move || {
                writer_started_in_task.store(true, Ordering::Release);
                writer_config.upsert_connection(
                    ConnectionId::deterministic("terminal-catalog-writer", "https://writer.test/"),
                    ConnectionMetadata::new("Terminal writer", "https://writer.test/"),
                )
            });
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while !writer_started.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("catalog config writer starts");
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(100), &mut writer)
                    .await
                    .is_err(),
                "config writer must remain behind the detached sync gate"
            );

            release.store(true, Ordering::Release);
            let snapshot = tokio::time::timeout(std::time::Duration::from_secs(2), writer)
                .await
                .expect("catalog writer completes after DB claim")
                .expect("catalog writer task joins")
                .expect("catalog writer advances config");
            assert!(snapshot.revision() > source_revision);
            assert!(
                committed.load(Ordering::Acquire),
                "catalog claim must finish before the sync gate is released"
            );

            LocalVaultRepo::new(&pool)
                .bind_cache_key_fingerprints_leased(
                    &LocalStorageProof::try_from(&storage).expect("repeat catalog storage proof"),
                    &LocalSyncGenerationProof::new([1_u8; 32], [2_u8; 32], 7, [3; 32]),
                    &[],
                )
                .await
                .expect("detached catalog claim is durably idempotent");
            pool.close().await;
        });
    }

    #[test]
    fn dropped_pull_outer_keeps_the_sync_gate_until_the_db_commit_finishes() {
        let _serial = TERMINAL_MUTATION_TEST_LOCK
            .lock()
            .expect("serialize process-global terminal admission test");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()
            .expect("pull cancellation test runtime");
        runtime.block_on(async {
            let fixture = configured_fixture();
            let database_path = fixture.temp.path().join("terminal-pull.sqlite");
            let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
                .await
                .expect("open pull terminal database");
            zann_db::migrate_local(&pool)
                .await
                .expect("migrate pull terminal database");
            let storage = matching_storage(&fixture);
            LocalStorageRepo::new(&pool)
                .upsert(&storage)
                .await
                .expect("insert pull terminal storage");
            let scope = LocalSyncScope {
                storage_id: storage.id,
                vault_id: Uuid::now_v7(),
            };
            let vault = zann_db::local::LocalVault {
                id: scope.vault_id,
                storage_id: scope.storage_id,
                slug: "terminal_pull".to_string(),
                name: "Terminal pull".to_string(),
                kind: VaultKind::Personal,
                is_default: false,
                vault_key_enc: vec![1, 2, 3],
                key_wrap_type: KeyWrapType::RemoteStrict,
                cache_key_fp: None,
                last_synced_at: None,
            };
            LocalVaultRepo::new(&pool)
                .create(&vault)
                .await
                .expect("insert pull terminal vault");
            let generation = LocalSyncGenerationProof::new([4_u8; 32], [5_u8; 32], 11, [6; 32]);
            let storage_proof =
                LocalStorageProof::try_from(&storage).expect("valid pull storage proof");
            LocalVaultRepo::new(&pool)
                .bind_cache_key_fingerprints_leased(
                    &storage_proof,
                    &generation,
                    &[CacheKeyFingerprintBinding {
                        storage_id: vault.storage_id,
                        vault_id: vault.id,
                        expected_slug: &vault.slug,
                        expected_name: &vault.name,
                        expected_kind: vault.kind,
                        expected_is_default: vault.is_default,
                        expected_vault_key_enc: &vault.vault_key_enc,
                        expected_key_wrap_type: vault.key_wrap_type,
                        target_cache_key_fp: "001122aabbcc",
                    }],
                )
                .await
                .expect("claim generation and bind pull vault");
            let page = PullPage::new(
                scope,
                "001122aabbcc".to_string(),
                None,
                None,
                "terminal-cursor".to_string(),
                Some(1),
                chrono::Utc::now(),
                Vec::new(),
            )
            .expect("valid empty pull page");
            let store = Arc::new(
                SqliteSyncStore::from_pool(
                    bound_paths(&fixture, &database_path),
                    file_location(&database_path),
                    pool.clone(),
                    Arc::clone(&fixture.master_key),
                    fixture.target.clone(),
                )
                .expect("construct pull terminal store"),
            );

            let config = ConfigRepository::new(fixture.paths.clone());
            let source_revision = config
                .snapshot()
                .expect("prime exact pull sync gate file")
                .revision();
            let sync_gate = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(fixture.paths.sync_commit_lock())
                .expect("open real Config v2 sync gate");
            let worker_pool = pool.clone();
            let entered = Arc::new(AtomicBool::new(false));
            let release = Arc::new(AtomicBool::new(false));
            let committed = Arc::new(AtomicBool::new(false));
            let entered_in_task = Arc::clone(&entered);
            let release_in_task = Arc::clone(&release);
            let committed_in_task = Arc::clone(&committed);
            let outer = store.dispatch_terminal_mutation(async move {
                sync_gate
                    .lock()
                    .map_err(|_| store_error(SyncStoreErrorKind::Unavailable))?;
                entered_in_task.store(true, Ordering::Release);
                while !release_in_task.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
                let result = LocalSyncRepo::new(&worker_pool)
                    .commit_pull_page_leased(&page, &storage_proof, &generation)
                    .await
                    .map_err(map_local_sync_error)
                    .map(|_| ());
                committed_in_task.store(result.is_ok(), Ordering::Release);
                drop(sync_gate);
                result
            });
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while !entered.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("detached pull task owns the sync gate");
            drop(outer);

            let writer_started = Arc::new(AtomicBool::new(false));
            let writer_started_in_task = Arc::clone(&writer_started);
            let writer_config = config.clone();
            let mut writer = tokio::task::spawn_blocking(move || {
                writer_started_in_task.store(true, Ordering::Release);
                writer_config.upsert_connection(
                    ConnectionId::deterministic("terminal-pull-writer", "https://writer.test/"),
                    ConnectionMetadata::new("Terminal writer", "https://writer.test/"),
                )
            });
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while !writer_started.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("pull config writer starts");
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(100), &mut writer)
                    .await
                    .is_err(),
                "config writer must remain behind the detached pull sync gate"
            );

            release.store(true, Ordering::Release);
            let snapshot = tokio::time::timeout(std::time::Duration::from_secs(2), writer)
                .await
                .expect("pull writer completes after DB commit")
                .expect("pull writer task joins")
                .expect("pull writer advances config");
            assert!(snapshot.revision() > source_revision);
            assert!(
                committed.load(Ordering::Acquire),
                "pull commit must finish before the sync gate is released"
            );
            let checkpoint = SyncCursorRepo::new(&pool)
                .get_checkpoint(scope.storage_id, scope.vault_id)
                .await
                .expect("read detached pull checkpoint")
                .expect("detached pull checkpoint exists");
            assert_eq!(checkpoint.cursor.as_deref(), Some("terminal-cursor"));
            assert_eq!(checkpoint.last_seq, Some(1));
            pool.close().await;
        });
    }

    #[test]
    fn canonical_uuid_rejects_aliases() {
        let id = Uuid::now_v7();
        assert_eq!(canonical_uuid(&id.to_string()).expect("canonical uuid"), id);
        assert!(canonical_uuid(&id.simple().to_string()).is_err());
        assert!(canonical_uuid(&id.to_string().to_uppercase()).is_err());
    }

    #[test]
    fn catalog_key_resolution_uses_personal_vault_aad_and_shared_master_cache_key() {
        let master = SecretKey::from_bytes([7_u8; 32]);
        let personal_key = SecretKey::from_bytes([9_u8; 32]);
        let vault_id = Uuid::now_v7();
        let envelope = zann_crypto::encrypt_vault_key(&master, vault_id, &personal_key)
            .expect("encrypt personal catalog key");
        let (kind, wrap, resolved) =
            resolve_catalog_key(&master, vault_id, VaultPlane::PersonalClient, &envelope)
                .expect("resolve personal catalog key");
        assert_eq!(kind, VaultKind::Personal);
        assert_eq!(wrap, KeyWrapType::RemoteStrict);
        assert_eq!(
            resolved.cache_key_fingerprint(),
            zann_crypto::cache_key_fingerprint(&personal_key)
        );
        let resolved_debug = format!("{resolved:?}");
        assert_eq!(resolved_debug, "VaultPayloadKey(<redacted>)");
        assert!(!resolved_debug.contains(resolved.cache_key_fingerprint()));
        let wrong_aad = resolve_catalog_key(
            &master,
            Uuid::now_v7(),
            VaultPlane::PersonalClient,
            &envelope,
        )
        .expect_err("wrong vault AAD must fail closed");
        assert_eq!(wrong_aad.kind(), SyncStoreErrorKind::StaleKeyBinding);

        let (kind, wrap, resolved) =
            resolve_catalog_key(&master, vault_id, VaultPlane::SharedServer, &envelope)
                .expect("resolve shared catalog key");
        assert_eq!(kind, VaultKind::Shared);
        assert_eq!(wrap, KeyWrapType::RemoteServer);
        assert_eq!(
            resolved.cache_key_fingerprint(),
            zann_crypto::cache_key_fingerprint(&master)
        );
        assert_eq!(format!("{resolved:?}"), "VaultPayloadKey(<redacted>)");
    }

    #[tokio::test]
    async fn db_backed_catalog_reconcile_binds_personal_and_shared_keys_atomically() {
        let fixture = configured_fixture();
        let database_path = fixture.temp.path().join("positive-catalog.sqlite");
        let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
            .await
            .expect("open positive catalog database");
        zann_db::migrate_local(&pool)
            .await
            .expect("migrate positive catalog database");
        let storage = matching_storage(&fixture);
        LocalStorageRepo::new(&pool)
            .upsert(&storage)
            .await
            .expect("insert positive catalog storage");

        let personal_id = Uuid::now_v7();
        let shared_id = Uuid::now_v7();
        let personal_key = SecretKey::from_bytes([9_u8; 32]);
        let personal_fingerprint = zann_crypto::cache_key_fingerprint(&personal_key);
        let shared_fingerprint = zann_crypto::cache_key_fingerprint(&fixture.master_key);
        let personal_envelope =
            zann_crypto::encrypt_vault_key(&fixture.master_key, personal_id, &personal_key)
                .expect("encrypt personal catalog envelope");
        let shared_envelope = vec![4_u8, 5, 6];
        for vault in [
            zann_db::local::LocalVault {
                id: personal_id,
                storage_id: storage.id,
                slug: "personal-positive".to_string(),
                name: "Personal positive".to_string(),
                kind: VaultKind::Personal,
                is_default: false,
                vault_key_enc: personal_envelope.clone(),
                key_wrap_type: KeyWrapType::RemoteStrict,
                cache_key_fp: None,
                last_synced_at: None,
            },
            zann_db::local::LocalVault {
                id: shared_id,
                storage_id: storage.id,
                slug: "shared-positive".to_string(),
                name: "Shared positive".to_string(),
                kind: VaultKind::Shared,
                is_default: false,
                vault_key_enc: shared_envelope.clone(),
                key_wrap_type: KeyWrapType::RemoteServer,
                cache_key_fp: None,
                last_synced_at: None,
            },
        ] {
            LocalVaultRepo::new(&pool)
                .create(&vault)
                .await
                .expect("insert exact local catalog row");
        }
        let catalog = [
            CatalogExpectation {
                id: personal_id,
                slug: "personal-positive",
                name: "Personal positive",
                plane: VaultPlane::PersonalClient,
                vault_key_envelope: &personal_envelope,
            },
            CatalogExpectation {
                id: shared_id,
                slug: "shared-positive",
                name: "Shared positive",
                plane: VaultPlane::SharedServer,
                vault_key_envelope: &shared_envelope,
            },
        ];

        let resolved =
            reconcile_catalog_rows_for_test(&pool, &storage, &fixture.master_key, &catalog)
                .await
                .expect("reconcile exact personal/shared catalog");
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].scope().vault_id(), personal_id);
        assert_eq!(resolved[0].plane(), VaultPlane::PersonalClient);
        assert_eq!(resolved[1].scope().vault_id(), shared_id);
        assert_eq!(resolved[1].plane(), VaultPlane::SharedServer);
        assert!(format!("{resolved:?}").contains("<redacted>"));

        let rebound = LocalVaultRepo::new(&pool)
            .list_by_storage_bounded(storage.id)
            .await
            .expect("read rebound catalog");
        let fingerprints = rebound
            .iter()
            .map(|vault| (vault.id, vault.cache_key_fp.as_deref()))
            .collect::<HashMap<_, _>>();
        assert_eq!(
            fingerprints.get(&personal_id).copied().flatten(),
            Some(personal_fingerprint.as_str())
        );
        assert_eq!(
            fingerprints.get(&shared_id).copied().flatten(),
            Some(shared_fingerprint.as_str())
        );
        let repeated =
            reconcile_catalog_rows_for_test(&pool, &storage, &fixture.master_key, &catalog)
                .await
                .expect("repeat exact bound catalog");
        assert_eq!(repeated.len(), 2);
        pool.close().await;
    }

    #[tokio::test]
    async fn db_backed_pull_helper_commits_nonempty_page_and_maps_stale_key() {
        const CURSOR_ONE: &str = "eyJzZXEiOjF9";
        const CURSOR_TWO: &str = "eyJzZXEiOjJ9";
        const CURSOR_THREE: &str = "eyJzZXEiOjN9";

        let fixture = configured_fixture();
        let database_path = fixture.temp.path().join("positive-pull.sqlite");
        let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
            .await
            .expect("open positive pull database");
        zann_db::migrate_local(&pool)
            .await
            .expect("migrate positive pull database");
        let storage = matching_storage(&fixture);
        LocalStorageRepo::new(&pool)
            .upsert(&storage)
            .await
            .expect("insert positive pull storage");
        let vault_id = Uuid::now_v7();
        let cache_key_fingerprint = zann_crypto::cache_key_fingerprint(&fixture.master_key);
        LocalVaultRepo::new(&pool)
            .create(&zann_db::local::LocalVault {
                id: vault_id,
                storage_id: storage.id,
                slug: "positive-pull".to_string(),
                name: "Positive pull".to_string(),
                kind: VaultKind::Shared,
                is_default: false,
                vault_key_enc: vec![1, 2, 3],
                key_wrap_type: KeyWrapType::RemoteServer,
                cache_key_fp: Some(cache_key_fingerprint.clone()),
                last_synced_at: None,
            })
            .await
            .expect("insert positive pull vault");
        let local_scope = LocalSyncScope {
            storage_id: storage.id,
            vault_id,
        };
        SyncCursorRepo::new(&pool)
            .upsert_checkpoint(&LocalSyncCheckpoint {
                storage_id: storage.id,
                vault_id,
                cursor: Some(CURSOR_ONE.to_string()),
                last_seq: Some(1),
                last_sync_at: Some(chrono::Utc::now()),
            })
            .await
            .expect("insert initial pull checkpoint");
        let item_id = Uuid::now_v7();
        let payload = vec![7_u8, 8, 9];
        let pulled_item = LocalItem {
            id: item_id,
            storage_id: storage.id,
            vault_id,
            path: "accounts/positive-pull".to_string(),
            name: "positive-pull".to_string(),
            type_id: "login".to_string(),
            payload_enc: payload.clone(),
            checksum: zann_crypto::payload_checksum(&payload),
            cache_key_fp: Some(cache_key_fingerprint.clone()),
            version: 2,
            deleted_at: None,
            updated_at: chrono::Utc::now(),
            sync_status: SyncStatus::Synced,
        };
        let change = PullChange::new(
            local_scope,
            LocalItemExpectation::Absent,
            pulled_item.clone(),
            Vec::new(),
        )
        .expect("construct positive pull change");
        let page = PullPage::new(
            local_scope,
            cache_key_fingerprint.clone(),
            Some(CURSOR_ONE.to_string()),
            Some(1),
            CURSOR_TWO.to_string(),
            Some(2),
            chrono::Utc::now(),
            vec![change],
        )
        .expect("construct positive pull page");

        let receipt = commit_bound_pull_page_for_test(&pool, &storage, &page)
            .await
            .expect("commit positive pull page");
        assert_eq!(receipt.items(), 1);
        assert_eq!(receipt.history_entries(), 0);
        assert_eq!(receipt.cursor().as_str(), CURSOR_TWO);
        assert_eq!(receipt.last_seq().map(SyncSeq::get), Some(2));
        let persisted_item = LocalItemRepo::new(&pool)
            .get_by_id_bounded(storage.id, item_id)
            .await
            .expect("read pulled item")
            .expect("pulled item must be durable");
        assert_eq!(persisted_item.id, pulled_item.id);
        assert_eq!(persisted_item.storage_id, pulled_item.storage_id);
        assert_eq!(persisted_item.vault_id, pulled_item.vault_id);
        assert_eq!(persisted_item.path, pulled_item.path);
        assert_eq!(persisted_item.name, pulled_item.name);
        assert_eq!(persisted_item.type_id, pulled_item.type_id);
        assert_eq!(persisted_item.payload_enc, pulled_item.payload_enc);
        assert_eq!(persisted_item.checksum, pulled_item.checksum);
        assert_eq!(persisted_item.cache_key_fp, pulled_item.cache_key_fp);
        assert_eq!(persisted_item.version, pulled_item.version);
        assert_eq!(persisted_item.deleted_at, pulled_item.deleted_at);
        assert_eq!(persisted_item.updated_at, pulled_item.updated_at);
        assert_eq!(persisted_item.sync_status, pulled_item.sync_status);

        let stale_page = PullPage::new(
            local_scope,
            "ffeeddccbbaa".to_string(),
            Some(CURSOR_TWO.to_string()),
            Some(2),
            CURSOR_THREE.to_string(),
            Some(3),
            chrono::Utc::now(),
            Vec::new(),
        )
        .expect("construct stale-key pull page");
        let error = commit_bound_pull_page_for_test(&pool, &storage, &stale_page)
            .await
            .expect_err("stale key binding must reject empty pull page");
        assert_eq!(error.kind(), SyncStoreErrorKind::StaleKeyBinding);
        let checkpoint = SyncCursorRepo::new(&pool)
            .get_checkpoint(storage.id, vault_id)
            .await
            .expect("read checkpoint after stale-key rollback")
            .expect("checkpoint remains present");
        assert_eq!(checkpoint.cursor.as_deref(), Some(CURSOR_TWO));
        assert_eq!(checkpoint.last_seq, Some(2));
        pool.close().await;
    }

    #[test]
    fn pulled_tombstone_and_restore_map_to_synced_local_projection_exactly() {
        let scope = SyncScope::new(Uuid::now_v7(), Uuid::now_v7()).expect("sync scope");
        let item_id = Uuid::now_v7();
        let deleted_at = chrono::Utc::now();
        let deleted_payload = vec![1, 2, 3];
        let tombstone = ItemProjection::new(
            scope,
            item_id,
            "accounts/deleted",
            "deleted",
            "login",
            deleted_payload.clone(),
            ContentChecksum::parse(&zann_crypto::payload_checksum(&deleted_payload))
                .expect("deleted checksum"),
            "001122aabbcc",
            SyncSeq::new(2).expect("deleted sequence"),
            deleted_at,
            Some(deleted_at),
        )
        .expect("valid tombstone projection");
        let deleted = local_item_from_projection(&tombstone, tombstone.sync_status())
            .expect("map tombstone projection");
        assert_eq!(deleted.sync_status, SyncStatus::Synced);
        assert_eq!(deleted.deleted_at, Some(deleted_at));
        assert_eq!(deleted.payload_enc, deleted_payload);
        assert_eq!(deleted.cache_key_fp.as_deref(), Some("001122aabbcc"));

        let restored_at = deleted_at + chrono::Duration::seconds(1);
        let restored_payload = vec![4, 5, 6];
        let restore = ItemProjection::new(
            scope,
            item_id,
            "accounts/deleted",
            "deleted",
            "login",
            restored_payload.clone(),
            ContentChecksum::parse(&zann_crypto::payload_checksum(&restored_payload))
                .expect("restore checksum"),
            "001122aabbcc",
            SyncSeq::new(3).expect("restore sequence"),
            restored_at,
            None,
        )
        .expect("valid restore projection");
        let restored = local_item_from_projection(&restore, restore.sync_status())
            .expect("map restore projection");
        assert_eq!(restored.sync_status, SyncStatus::Synced);
        assert_eq!(restored.deleted_at, None);
        assert_eq!(restored.payload_enc, restored_payload);
        assert_eq!(restored.version, 3);
    }

    #[test]
    fn database_cas_errors_map_to_clean_sync_store_kinds() {
        let scope = LocalSyncScope {
            storage_id: Uuid::now_v7(),
            vault_id: Uuid::now_v7(),
        };
        assert_eq!(
            map_local_sync_error(LocalSyncError::StaleCursor { scope }).kind(),
            SyncStoreErrorKind::StaleCheckpoint
        );
        assert_eq!(
            map_local_sync_error(LocalSyncError::StalePending {
                pending_id: Uuid::now_v7(),
            })
            .kind(),
            SyncStoreErrorKind::PendingChanged
        );
        assert_eq!(
            map_local_sync_error(LocalSyncError::StaleVaultKey { scope }).kind(),
            SyncStoreErrorKind::StaleKeyBinding
        );
        assert_eq!(
            map_local_sync_error(LocalSyncError::StorageBindingChanged {
                storage_id: scope.storage_id,
            })
            .kind(),
            SyncStoreErrorKind::StaleCheckpoint
        );
        assert_eq!(
            map_local_sync_error(LocalSyncError::CommitOutcomeUnknown).kind(),
            SyncStoreErrorKind::CommitOutcomeUnknown
        );
        assert_eq!(
            map_key_bind_error(LocalVaultKeyBindError::KeyBindingChanged).kind(),
            SyncStoreErrorKind::StaleKeyBinding
        );
        assert_eq!(
            map_key_bind_error(LocalVaultKeyBindError::CommitOutcomeUnknown).kind(),
            SyncStoreErrorKind::CommitOutcomeUnknown
        );
    }

    #[test]
    fn resolved_location_is_immutable_across_cwd_changes_and_rejects_relative_paths() {
        let _lock = CWD_LOCK.lock().expect("lock process working directory");
        let original = std::env::current_dir().expect("read working directory");
        let _restore = CurrentDirGuard(original);
        let first = TempDir::new().expect("first location root");
        let second = TempDir::new().expect("second location root");

        std::env::set_current_dir(first.path()).expect("enter first location root");
        let location = SqliteFileLocation::from_path(Path::new("cache.sqlite"))
            .expect("resolve location once");
        let bound = ClientPaths::with_local_db(location.root(), location.path());
        std::env::set_current_dir(second.path()).expect("switch working directory");

        ensure_paths_match_location(&bound, &location)
            .expect("resolved absolute binding does not follow cwd");
        assert!(ensure_paths_match_location(
            &ClientPaths::with_local_db(Path::new("."), Path::new("cache.sqlite")),
            &location,
        )
        .is_err());
        assert!(ensure_paths_match_location(
            &ClientPaths::with_local_db(second.path(), second.path().join("cache.sqlite")),
            &location,
        )
        .is_err());
    }

    #[tokio::test]
    async fn open_rejects_crossed_config_and_database_roots_before_sqlite_creation() {
        let fixture = configured_fixture();
        let second = TempDir::new().expect("second adapter root");
        let second_paths = ClientPaths::new(second.path());
        fs::copy(fixture.paths.config(), second_paths.config())
            .expect("copy semantically identical config");
        let crossed_database = second.path().join("crossed.sqlite");
        let error = SqliteSyncStore::open(
            ClientPaths::with_local_db(fixture.paths.root(), &crossed_database),
            &crossed_database,
            fixture.master_key,
        )
        .await
        .expect_err("crossed roots must fail before config or SQLite access");
        assert_eq!(error.kind(), SyncStoreErrorKind::InvalidData);
        assert!(!crossed_database.exists());
    }

    #[tokio::test]
    async fn explicit_literal_path_is_used_and_wrong_master_cannot_create_it() {
        let fixture = configured_fixture();
        let wrong_path = fixture.temp.path().join("wrong#?% master.sqlite");
        let error = SqliteSyncStore::open(
            bound_paths(&fixture, &wrong_path),
            &wrong_path,
            Arc::new(SecretKey::from_bytes([8_u8; 32])),
        )
        .await
        .expect_err("missing database must never be created");
        assert_eq!(error.kind(), SyncStoreErrorKind::Unavailable);
        assert!(!wrong_path.exists());

        let literal_path = fixture.temp.path().join("literal#?% database.sqlite");
        let pool = zann_db::connect_sqlite_path_with_max(&literal_path, 1)
            .await
            .expect("create existing literal database");
        zann_db::migrate_local(&pool)
            .await
            .expect("migrate existing literal database");
        pool.close().await;
        let store = SqliteSyncStore::open(
            bound_paths(&fixture, &literal_path),
            &literal_path,
            fixture.master_key,
        )
        .await
        .expect("open exact literal path");
        assert!(literal_path.exists());
        store.database.pool().close().await;
    }

    #[tokio::test]
    async fn app_factory_opens_only_its_exact_existing_database() {
        let fixture = configured_fixture();
        let database_path = fixture.temp.path().join("app-factory.sqlite");
        let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
            .await
            .expect("create factory database");
        zann_db::migrate_local(&pool)
            .await
            .expect("migrate factory database");
        pool.close().await;

        let factory = Arc::new(
            SqliteSyncStoreFactory::new(&database_path)
                .expect("resolve exact existing factory database"),
        );
        assert_eq!(format!("{factory:?}"), "SqliteSyncStoreFactory { .. }");
        let store = factory
            .clone()
            .open_existing(
                bound_paths(&fixture, &database_path),
                fixture.target.clone(),
                Arc::clone(&fixture.master_key),
            )
            .await
            .expect("open exact existing operation store");
        drop(store);

        let crossed = fixture.temp.path().join("crossed-app-factory.sqlite");
        let crossed_result = factory
            .open_existing(
                bound_paths(&fixture, &crossed),
                fixture.target,
                fixture.master_key,
            )
            .await;
        let Err(error) = crossed_result else {
            panic!("factory location and client paths must remain exact");
        };
        assert_eq!(error.kind(), SyncStoreErrorKind::InvalidData);
        assert!(!crossed.exists());

        let missing = fixture.temp.path().join("missing-app-factory.sqlite");
        let error = SqliteSyncStoreFactory::new(&missing)
            .expect_err("factory must never create a missing database");
        assert_eq!(error.kind(), SyncStoreErrorKind::Unavailable);
        assert!(!missing.exists());
    }

    #[tokio::test]
    async fn exact_local_account_and_auth_method_are_required() {
        let fixture = configured_fixture();
        let database_path = fixture.temp.path().join("binding.sqlite");
        let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
            .await
            .expect("open adapter database");
        zann_db::migrate_local(&pool)
            .await
            .expect("migrate adapter database");
        let mut storage = matching_storage(&fixture);
        storage.auth_method = Some(AuthMethod::Oidc);
        LocalStorageRepo::new(&pool)
            .upsert(&storage)
            .await
            .expect("insert mismatched local storage");
        let store = SqliteSyncStore::from_pool(
            bound_paths(&fixture, &database_path),
            file_location(&database_path),
            pool.clone(),
            fixture.master_key,
            fixture.target.clone(),
        )
        .expect("construct exact config-bound adapter");
        let error = store
            .resolve_exact_target_for_test(&fixture.target)
            .await
            .expect_err("auth-method drift must fail closed");
        assert_eq!(error.kind(), SyncStoreErrorKind::InvalidData);

        storage.auth_method = Some(AuthMethod::Password);
        storage.account_subject = Some(Uuid::now_v7().to_string());
        LocalStorageRepo::new(&pool)
            .upsert(&storage)
            .await
            .expect("install account drift");
        let error = store
            .resolve_exact_target_for_test(&fixture.target)
            .await
            .expect_err("account drift must fail closed");
        assert_eq!(error.kind(), SyncStoreErrorKind::InvalidData);
        pool.close().await;
    }

    #[tokio::test]
    async fn local_endpoint_drift_and_multiple_remote_caches_fail_closed() {
        let fixture = configured_fixture();
        let database_path = fixture.temp.path().join("endpoint-drift.sqlite");
        let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
            .await
            .expect("open adapter database");
        zann_db::migrate_local(&pool)
            .await
            .expect("migrate adapter database");
        let mut storage = matching_storage(&fixture);
        LocalStorageRepo::new(&pool)
            .upsert(&storage)
            .await
            .expect("insert matching local storage");
        let store = SqliteSyncStore::from_pool(
            bound_paths(&fixture, &database_path),
            file_location(&database_path),
            pool.clone(),
            fixture.master_key,
            fixture.target.clone(),
        )
        .expect("construct endpoint-bound adapter");
        store
            .resolve_exact_target_for_test(&fixture.target)
            .await
            .expect("matching endpoint resolves");

        storage.server_url = Some("https://drifted.test".to_string());
        LocalStorageRepo::new(&pool)
            .upsert(&storage)
            .await
            .expect("install endpoint drift");
        let error = store
            .resolve_exact_target_for_test(&fixture.target)
            .await
            .expect_err("endpoint drift must fail closed");
        assert_eq!(error.kind(), SyncStoreErrorKind::InvalidData);

        storage.server_url = Some("https://adapter.test".to_string());
        LocalStorageRepo::new(&pool)
            .upsert(&storage)
            .await
            .expect("restore matching endpoint");
        let mut second = storage;
        second.id = Uuid::now_v7();
        second.name = "Second remote cache".to_string();
        second.server_url = Some("https://second-cache.test".to_string());
        second.server_fingerprint = Some("second-cache-fingerprint".to_string());
        LocalStorageRepo::new(&pool)
            .upsert(&second)
            .await
            .expect("insert second remote cache");
        let error = store
            .resolve_exact_target_for_test(&fixture.target)
            .await
            .expect_err("multiple remote caches must fail closed");
        assert_eq!(error.kind(), SyncStoreErrorKind::InvalidData);
        pool.close().await;
    }

    #[tokio::test]
    async fn reset_is_unavailable_before_any_database_mutation() {
        let fixture = configured_fixture();
        let database_path = fixture.temp.path().join("reset-unavailable.sqlite");
        let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
            .await
            .expect("open reset-unavailable database");
        zann_db::migrate_local(&pool)
            .await
            .expect("migrate reset-unavailable database");
        let storage = matching_storage(&fixture);
        LocalStorageRepo::new(&pool)
            .upsert(&storage)
            .await
            .expect("insert reset-unavailable storage");
        let vault_id = Uuid::now_v7();
        LocalVaultRepo::new(&pool)
            .create(&zann_db::local::LocalVault {
                id: vault_id,
                storage_id: storage.id,
                slug: "reset-unavailable".to_string(),
                name: "Reset unavailable".to_string(),
                kind: VaultKind::Personal,
                is_default: false,
                vault_key_enc: vec![1, 2, 3],
                key_wrap_type: KeyWrapType::RemoteStrict,
                cache_key_fp: Some("001122aabbcc".to_string()),
                last_synced_at: None,
            })
            .await
            .expect("insert reset-unavailable vault");
        let binding = StorageBindingProof::new(
            storage.id,
            storage.name.clone(),
            storage.server_url.clone().expect("remote URL"),
            storage.server_name.clone(),
            storage
                .server_fingerprint
                .clone()
                .expect("remote fingerprint"),
            storage.account_subject.clone(),
            storage.personal_vaults_enabled,
            storage.auth_method,
        )
        .expect("valid reset binding");
        let store = Arc::new(
            SqliteSyncStore::from_pool(
                bound_paths(&fixture, &database_path),
                file_location(&database_path),
                pool.clone(),
                fixture.master_key,
                fixture.target,
            )
            .expect("construct reset-unavailable adapter"),
        );
        let error = store
            .reset_projection_if_clean(ProjectionReset::new(binding))
            .await
            .expect_err("projection reset must remain unavailable");
        assert_eq!(error.kind(), SyncStoreErrorKind::Unavailable);
        assert!(LocalStorageRepo::new(&pool)
            .get_bounded(storage.id)
            .await
            .expect("read storage after rejected reset")
            .is_some());
        assert!(LocalVaultRepo::new(&pool)
            .exists(storage.id, vault_id)
            .await
            .expect("read vault after rejected reset"));
        pool.close().await;
    }

    async fn reset_test_database(
        fixture: &ConfigFixture,
        file_name: &str,
    ) -> (std::path::PathBuf, SqlitePool) {
        let database_path = fixture.temp.path().join(file_name);
        let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
            .await
            .expect("open reset test database");
        zann_db::migrate_local(&pool)
            .await
            .expect("migrate reset test database");
        (database_path, pool)
    }

    async fn seed_reset_projection(pool: &SqlitePool, storage: &LocalStorage) -> Uuid {
        LocalStorageRepo::new(pool)
            .upsert(storage)
            .await
            .expect("insert reset storage");
        let vault_id = Uuid::now_v7();
        LocalVaultRepo::new(pool)
            .create(&LocalVault {
                id: vault_id,
                storage_id: storage.id,
                slug: "factory-reset".to_string(),
                name: "Factory reset".to_string(),
                kind: VaultKind::Personal,
                is_default: false,
                vault_key_enc: vec![1, 2, 3],
                key_wrap_type: KeyWrapType::RemoteStrict,
                cache_key_fp: Some("001122aabbcc".to_string()),
                last_synced_at: None,
            })
            .await
            .expect("insert reset vault");
        vault_id
    }

    fn canonical_reset_paths(database_path: &Path) -> (std::path::PathBuf, ClientPaths) {
        let database_path = database_path
            .canonicalize()
            .expect("canonicalize reset database path");
        let root = database_path
            .parent()
            .expect("reset database parent")
            .to_path_buf();
        (
            database_path.clone(),
            ClientPaths::with_local_db(root, database_path),
        )
    }

    #[test]
    fn factory_reset_removes_the_single_remote_projection() {
        let _serial = TERMINAL_MUTATION_TEST_LOCK
            .lock()
            .expect("serialize process-global terminal admission test");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("factory reset test runtime");
        runtime.block_on(async {
            let fixture = configured_fixture();
            let (database_path, pool) =
                reset_test_database(&fixture, "factory-reset-clean.sqlite").await;
            let storage = matching_storage(&fixture);
            let vault_id = seed_reset_projection(&pool, &storage).await;
            SyncCursorRepo::new(&pool)
                .upsert_checkpoint(&LocalSyncCheckpoint {
                    storage_id: storage.id,
                    vault_id,
                    cursor: Some("eyJzZXEiOjF9".to_string()),
                    last_seq: Some(1),
                    last_sync_at: Some(chrono::Utc::now()),
                })
                .await
                .expect("insert reset checkpoint");
            let item_id = Uuid::now_v7();
            LocalItemRepo::new(&pool)
                .create(&LocalItem {
                    id: item_id,
                    storage_id: storage.id,
                    vault_id,
                    path: "accounts/factory-reset".to_string(),
                    name: "factory-reset".to_string(),
                    type_id: "login".to_string(),
                    payload_enc: vec![7, 8, 9],
                    checksum: zann_crypto::payload_checksum(&[7, 8, 9]),
                    cache_key_fp: Some("001122aabbcc".to_string()),
                    version: 1,
                    deleted_at: None,
                    updated_at: chrono::Utc::now(),
                    sync_status: SyncStatus::Synced,
                })
                .await
                .expect("insert reset item");
            pool.close().await;

            let (database_path, paths) = canonical_reset_paths(&database_path);
            let factory = Arc::new(
                SqliteSyncStoreFactory::new(&database_path).expect("construct reset factory"),
            );
            factory
                .clone()
                .reset_projection(paths, fixture.target.clone(), fixture.master_key.clone())
                .await
                .expect("reset the clean projection");

            let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
                .await
                .expect("reopen reset database");
            assert!(LocalStorageRepo::new(&pool)
                .get_bounded(storage.id)
                .await
                .expect("read storage after reset")
                .is_some());
            assert!(!LocalVaultRepo::new(&pool)
                .exists(storage.id, vault_id)
                .await
                .expect("read vault after reset"));
            assert!(LocalItemRepo::new(&pool)
                .get_by_id_bounded(storage.id, item_id)
                .await
                .expect("read item after reset")
                .is_none());
            assert!(SyncCursorRepo::new(&pool)
                .get(storage.id, vault_id)
                .await
                .expect("read cursor after reset")
                .is_none());
            pool.close().await;
        });
    }

    #[test]
    fn factory_reset_refuses_unconfirmed_local_state() {
        let _serial = TERMINAL_MUTATION_TEST_LOCK
            .lock()
            .expect("serialize process-global terminal admission test");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("factory reset test runtime");
        runtime.block_on(async {
            let fixture = configured_fixture();
            let (database_path, pool) =
                reset_test_database(&fixture, "factory-reset-pending.sqlite").await;
            let storage = matching_storage(&fixture);
            let vault_id = seed_reset_projection(&pool, &storage).await;
            PendingChangeRepo::new(&pool)
                .create(&LocalPendingChange {
                    id: Uuid::now_v7(),
                    storage_id: storage.id,
                    vault_id,
                    item_id: Uuid::now_v7(),
                    operation: zann_core::ChangeType::Create,
                    payload_enc: Some(vec![7]),
                    checksum: Some(zann_crypto::payload_checksum(&[7])),
                    path: Some("accounts/factory-reset-pending".to_string()),
                    name: Some("factory-reset-pending".to_string()),
                    type_id: Some("login".to_string()),
                    base_seq: None,
                    created_at: chrono::Utc::now(),
                })
                .await
                .expect("insert pending row");
            pool.close().await;

            let (database_path, paths) = canonical_reset_paths(&database_path);
            let factory = Arc::new(
                SqliteSyncStoreFactory::new(&database_path).expect("construct reset factory"),
            );
            let error = factory
                .clone()
                .reset_projection(paths, fixture.target.clone(), fixture.master_key.clone())
                .await
                .expect_err("reset must refuse to discard pending state");
            assert_eq!(error.kind(), SyncStoreErrorKind::PendingPresent);

            let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
                .await
                .expect("reopen refused reset database");
            assert!(LocalVaultRepo::new(&pool)
                .exists(storage.id, vault_id)
                .await
                .expect("read vault after refused reset"));
            assert_eq!(
                PendingChangeRepo::new(&pool)
                    .list_by_storage_vault(storage.id, vault_id)
                    .await
                    .expect("read pending after refused reset")
                    .len(),
                1
            );
            pool.close().await;
        });
    }

    #[tokio::test]
    async fn target_profile_drift_is_detected_after_construction() {
        let fixture = configured_fixture();
        let database_path = fixture.temp.path().join("config-drift.sqlite");
        let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
            .await
            .expect("open adapter database");
        let store = SqliteSyncStore::from_pool(
            bound_paths(&fixture, &database_path),
            file_location(&database_path),
            pool.clone(),
            fixture.master_key,
            fixture.target,
        )
        .expect("construct config-bound adapter");

        let config_path = fixture.paths.config();
        let mut raw: serde_json::Value =
            serde_json::from_slice(&fs::read(&config_path).expect("read adapter config"))
                .expect("parse adapter config");
        let connection_id = store
            .installed()
            .expect("installed test target")
            .target
            .connection_id()
            .as_str();
        raw["connections"][connection_id]["credential_profiles"]["profile"]["account_subject"] =
            json!(Uuid::now_v7().to_string());
        raw["revision"] = json!(raw["revision"].as_u64().expect("config revision") + 1);
        fs::write(
            &config_path,
            serde_json::to_vec_pretty(&raw).expect("serialize drifted config"),
        )
        .expect("write drifted config");

        let error = store
            .ensure_config_current_for_test()
            .expect_err("profile drift must invalidate the operation lease");
        assert_eq!(error.kind(), SyncStoreErrorKind::StaleCheckpoint);
        pool.close().await;
    }

    #[tokio::test]
    async fn configured_endpoint_drift_is_detected_after_construction() {
        let fixture = configured_fixture();
        let database_path = fixture.temp.path().join("config-endpoint-drift.sqlite");
        let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
            .await
            .expect("open adapter database");
        let store = SqliteSyncStore::from_pool(
            bound_paths(&fixture, &database_path),
            file_location(&database_path),
            pool.clone(),
            fixture.master_key,
            fixture.target,
        )
        .expect("construct endpoint-bound adapter");

        let config_path = fixture.paths.config();
        let mut raw: serde_json::Value =
            serde_json::from_slice(&fs::read(&config_path).expect("read adapter config"))
                .expect("parse adapter config");
        let connection_id = store
            .installed()
            .expect("installed test target")
            .target
            .connection_id()
            .as_str();
        raw["connections"][connection_id]["metadata"]["address"] = json!("https://drifted.test");
        raw["revision"] = json!(raw["revision"].as_u64().expect("config revision") + 1);
        fs::write(
            &config_path,
            serde_json::to_vec_pretty(&raw).expect("serialize drifted config"),
        )
        .expect("write drifted config");

        let error = store
            .ensure_config_current_for_test()
            .expect_err("endpoint drift must invalidate the operation lease");
        assert_eq!(error.kind(), SyncStoreErrorKind::StaleCheckpoint);
        pool.close().await;
    }

    #[tokio::test]
    async fn absent_master_binding_fails_before_opening_sqlite() {
        let fixture = configured_fixture();
        let config_path = fixture.paths.config();
        let mut raw: serde_json::Value =
            serde_json::from_slice(&fs::read(&config_path).expect("read adapter config"))
                .expect("parse adapter config");
        let connection_id = fixture.target.connection_id().as_str();
        raw["connections"][connection_id]["metadata"]
            .as_object_mut()
            .expect("connection metadata")
            .remove("expected_master_key_fp");
        fs::write(
            &config_path,
            serde_json::to_vec_pretty(&raw).expect("serialize unbound config"),
        )
        .expect("write unbound config");

        let database_path = fixture.temp.path().join("unbound#?%.sqlite");
        let error = SqliteSyncStore::open(
            bound_paths(&fixture, &database_path),
            &database_path,
            fixture.master_key,
        )
        .await
        .expect_err("open must not inspect config or create a missing database");
        assert_eq!(error.kind(), SyncStoreErrorKind::Unavailable);
        assert!(!database_path.exists());
    }

    #[tokio::test]
    async fn noncanonical_master_binding_fails_before_opening_sqlite() {
        let fixture = configured_fixture();
        let config_path = fixture.paths.config();
        let mut raw: serde_json::Value =
            serde_json::from_slice(&fs::read(&config_path).expect("read adapter config"))
                .expect("parse adapter config");
        let connection_id = fixture.target.connection_id().as_str();
        raw["connections"][connection_id]["metadata"]["expected_master_key_fp"] =
            json!("ABCDEF012345");
        fs::write(
            &config_path,
            serde_json::to_vec_pretty(&raw).expect("serialize invalid master binding"),
        )
        .expect("write invalid master binding");

        let database_path = fixture.temp.path().join("noncanonical#?%.sqlite");
        let error = SqliteSyncStore::open(
            bound_paths(&fixture, &database_path),
            &database_path,
            fixture.master_key,
        )
        .await
        .expect_err("open must not inspect config or create a missing database");
        assert_eq!(error.kind(), SyncStoreErrorKind::Unavailable);
        assert!(!database_path.exists());
    }

    #[tokio::test]
    async fn sixty_five_pending_rows_are_rejected_from_a_bounded_read() {
        let fixture = configured_fixture();
        let database_path = fixture.temp.path().join("pending-limit.sqlite");
        let pool = zann_db::connect_sqlite_path_with_max(&database_path, 1)
            .await
            .expect("open adapter database");
        zann_db::migrate_local(&pool)
            .await
            .expect("migrate adapter database");
        let storage = matching_storage(&fixture);
        LocalStorageRepo::new(&pool)
            .upsert(&storage)
            .await
            .expect("insert matching storage");
        let vault_id = Uuid::now_v7();
        LocalVaultRepo::new(&pool)
            .create(&zann_db::local::LocalVault {
                id: vault_id,
                storage_id: storage.id,
                slug: "pending-limit".to_string(),
                name: "Pending limit".to_string(),
                kind: VaultKind::Personal,
                is_default: false,
                vault_key_enc: vec![1, 2, 3],
                key_wrap_type: KeyWrapType::RemoteStrict,
                cache_key_fp: Some("001122aabbcc".to_string()),
                last_synced_at: None,
            })
            .await
            .expect("insert pending-limit vault");
        let scope = SyncScope::new(storage.id, vault_id).expect("sync scope");
        for index in 0..65 {
            let payload = vec![u8::try_from(index).expect("small pending index")];
            let name = format!("pending-{index}");
            PendingChangeRepo::new(&pool)
                .create(&LocalPendingChange {
                    id: Uuid::now_v7(),
                    storage_id: storage.id,
                    vault_id,
                    item_id: Uuid::now_v7(),
                    operation: zann_core::ChangeType::Create,
                    payload_enc: Some(payload.clone()),
                    checksum: Some(zann_crypto::payload_checksum(&payload)),
                    path: Some(format!("accounts/{name}")),
                    name: Some(name),
                    type_id: Some("login".to_string()),
                    base_seq: None,
                    created_at: chrono::Utc::now(),
                })
                .await
                .expect("insert bounded pending row");
        }
        let store = SqliteSyncStore::from_pool(
            bound_paths(&fixture, &database_path),
            file_location(&database_path),
            pool.clone(),
            fixture.master_key,
            fixture.target,
        )
        .expect("construct adapter");
        let error = store
            .checkpoint(scope)
            .await
            .expect_err("65 pending rows exceed the clean port limit");
        assert_eq!(error.kind(), SyncStoreErrorKind::InvalidData);
        pool.close().await;
    }
}
