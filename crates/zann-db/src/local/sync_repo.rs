use std::collections::HashSet;
use std::error::Error as StdError;
use std::fmt;

use chrono::{DateTime, Utc};
use sqlx_core::row::Row;
use sqlx_core::transaction::Transaction;
use sqlx_sqlite::Sqlite;
use uuid::Uuid;
use zann_core::{AuthMethod, ChangeType, StorageKind, SyncStatus};

use crate::local::vault_repo::{bounded_vault_preflight, bounded_vault_scope_membership};
use crate::local::{
    HistorySource, HistorySyncStatus, LocalItem, LocalItemHistory, LocalPendingChange, LocalStorage,
};
use crate::services::{
    MAX_ITEM_NAME_LEN, MAX_ITEM_PATH_LEN, MAX_ITEM_PATH_SEGMENTS, MAX_ITEM_PAYLOAD_BYTES,
};
use crate::SqlitePool;

const MAX_PUSH_BATCH_ITEMS: usize = 64;
const MAX_PULL_PAGE_ITEMS: usize = 16;
const MAX_HISTORY_PER_ITEM: usize = 5;
const MAX_HISTORY_PER_PAGE: usize = MAX_PULL_PAGE_ITEMS * MAX_HISTORY_PER_ITEM;
const MAX_PROJECTION_BYTES: usize = 32 * 1024 * 1024;
const MAX_ITEM_CIPHERTEXT_BYTES: usize = MAX_ITEM_PAYLOAD_BYTES + 256;
const MAX_CURSOR_BYTES: usize = 4_096;
const MAX_CHECKSUM_BYTES: usize = 256;
const MAX_TYPE_ID_BYTES: usize = 128;
const CACHE_KEY_FINGERPRINT_BYTES: usize = 12;
const MAX_EMAIL_BYTES: usize = 320;
const MAX_DISPLAY_NAME_BYTES: usize = 200;
const MAX_SERVER_URL_BYTES: usize = 2_048;
const MAX_SERVER_METADATA_BYTES: usize = 512;
const MAX_TIMESTAMP_BYTES: usize = 64;

/// Identifies the one remote-vault projection changed by a sync transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalSyncScope {
    pub storage_id: Uuid,
    pub vault_id: Uuid,
}

/// Exact configuration generation authorized to mutate one local projection.
///
/// Fingerprints are opaque SHA-256 digests.  `config_revision` is persisted as
/// unsigned big-endian bytes so SQLite compares the complete `u64` domain
/// lexicographically without signed-integer coercion.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalSyncGenerationProof {
    repository_fingerprint: [u8; 32],
    stable_target_fingerprint: [u8; 32],
    config_revision: u64,
    config_content_fingerprint: [u8; 32],
}

impl LocalSyncGenerationProof {
    pub fn new(
        repository_fingerprint: [u8; 32],
        stable_target_fingerprint: [u8; 32],
        config_revision: u64,
        config_content_fingerprint: [u8; 32],
    ) -> Self {
        Self {
            repository_fingerprint,
            stable_target_fingerprint,
            config_revision,
            config_content_fingerprint,
        }
    }

    pub fn repository_fingerprint(&self) -> &[u8; 32] {
        &self.repository_fingerprint
    }

    pub fn stable_target_fingerprint(&self) -> &[u8; 32] {
        &self.stable_target_fingerprint
    }

    pub fn config_revision(&self) -> u64 {
        self.config_revision
    }

    pub fn config_content_fingerprint(&self) -> &[u8; 32] {
        &self.config_content_fingerprint
    }

    pub(crate) fn revision_be(&self) -> [u8; 8] {
        self.config_revision.to_be_bytes()
    }
}

impl fmt::Debug for LocalSyncGenerationProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalSyncGenerationProof")
            .field("generation", &"<redacted>")
            .finish()
    }
}

/// Every persisted column of an item observed before a remote call.
///
/// This proof intentionally has no ordinary `Debug` implementation because it
/// carries encrypted payload bytes.
#[derive(PartialEq, Eq)]
pub struct LocalItemProof {
    id: Uuid,
    storage_id: Uuid,
    vault_id: Uuid,
    path: String,
    name: String,
    type_id: String,
    payload_enc: Vec<u8>,
    checksum: String,
    cache_key_fp: Option<String>,
    version: i64,
    deleted_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
    sync_status: SyncStatus,
}

impl TryFrom<&LocalItem> for LocalItemProof {
    type Error = LocalSyncError;

    fn try_from(item: &LocalItem) -> Result<Self, Self::Error> {
        let scope = LocalSyncScope {
            storage_id: item.storage_id,
            vault_id: item.vault_id,
        };
        validate_scope(scope)?;
        validate_item(item, scope)?;
        Ok(Self {
            id: item.id,
            storage_id: item.storage_id,
            vault_id: item.vault_id,
            path: item.path.clone(),
            name: item.name.clone(),
            type_id: item.type_id.clone(),
            payload_enc: item.payload_enc.clone(),
            checksum: item.checksum.clone(),
            cache_key_fp: item.cache_key_fp.clone(),
            version: item.version,
            deleted_at: item.deleted_at,
            updated_at: item.updated_at,
            sync_status: item.sync_status,
        })
    }
}

/// A compare-and-swap proof for the local item observed before a remote call.
#[derive(PartialEq, Eq)]
pub enum LocalItemExpectation {
    Absent,
    Exact(Box<LocalItemProof>),
}

/// The complete durable pending row that caused one push request entry.
///
/// This type intentionally has no ordinary `Debug` implementation because it
/// carries encrypted payload bytes. Every persisted field participates in the
/// push commit's compare-and-swap proof.
#[derive(PartialEq, Eq)]
pub struct LocalPendingProof {
    id: Uuid,
    storage_id: Uuid,
    vault_id: Uuid,
    item_id: Uuid,
    operation: ChangeType,
    payload_enc: Option<Vec<u8>>,
    checksum: Option<String>,
    path: Option<String>,
    name: Option<String>,
    type_id: Option<String>,
    base_seq: Option<i64>,
    created_at: DateTime<Utc>,
}

impl TryFrom<&LocalPendingChange> for LocalPendingProof {
    type Error = LocalSyncError;

    fn try_from(change: &LocalPendingChange) -> Result<Self, Self::Error> {
        validate_pending_change(change)?;
        Ok(Self {
            id: change.id,
            storage_id: change.storage_id,
            vault_id: change.vault_id,
            item_id: change.item_id,
            operation: change.operation,
            payload_enc: change.payload_enc.clone(),
            checksum: change.checksum.clone(),
            path: change.path.clone(),
            name: change.name.clone(),
            type_id: change.type_id.clone(),
            base_seq: change.base_seq,
            created_at: change.created_at,
        })
    }
}

/// A typed local projection produced by one push response outcome.
pub struct PushOutcome {
    kind: PushOutcomeKind,
}

enum PushOutcomeKind {
    Applied {
        pending: Box<LocalPendingProof>,
        expected_item: LocalItemExpectation,
        item: Box<LocalItem>,
    },
    /// A payload-free fail-closed marker. It can be placed in a candidate
    /// batch, but validation always rejects the complete batch before opening
    /// a transaction.
    Conflict,
}

impl PushOutcome {
    pub fn applied(
        scope: LocalSyncScope,
        pending: LocalPendingProof,
        expected_item: LocalItemExpectation,
        item: LocalItem,
    ) -> Result<Self, LocalSyncError> {
        let outcome = Self {
            kind: PushOutcomeKind::Applied {
                pending: Box::new(pending),
                expected_item,
                item: Box::new(item),
            },
        };
        validate_push_outcome(scope, &outcome)?;
        Ok(outcome)
    }

    /// Marks a conflicted push response. A [`PushCommit`] containing this
    /// marker is deliberately invalid: encrypted payload bytes are never
    /// copied under a fresh item identifier.
    pub fn conflict() -> Self {
        Self {
            kind: PushOutcomeKind::Conflict,
        }
    }
}

/// A complete push response persistence plan.
pub struct PushCommit {
    scope: LocalSyncScope,
    expected_cursor: Option<String>,
    expected_last_seq: Option<i64>,
    /// The server head returned by push. This is deliberately a hint and is
    /// never persisted as the local pull cursor: doing so could skip remote
    /// changes committed between the prior pull and this push.
    server_head_hint: String,
    outcomes: Vec<PushOutcome>,
}

impl PushCommit {
    pub fn new(
        scope: LocalSyncScope,
        expected_cursor: Option<String>,
        expected_last_seq: Option<i64>,
        server_head_hint: String,
        outcomes: Vec<PushOutcome>,
    ) -> Result<Self, LocalSyncError> {
        let commit = Self {
            scope,
            expected_cursor,
            expected_last_seq,
            server_head_hint,
            outcomes,
        };
        validate_push(&commit)?;
        Ok(commit)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PushReceipt {
    applied: usize,
    pending_deleted: usize,
    server_head_hint: String,
    last_seq: Option<i64>,
}

impl PushReceipt {
    pub fn applied(&self) -> usize {
        self.applied
    }

    pub fn pending_deleted(&self) -> usize {
        self.pending_deleted
    }

    pub fn server_head_hint(&self) -> &str {
        &self.server_head_hint
    }

    pub fn last_seq(&self) -> Option<i64> {
        self.last_seq
    }
}

/// One full item and history projection in a pull page.
///
/// `history` is the complete confirmed server history projection for `item`.
/// Committing replaces only prior `Server + Confirmed` rows; local,
/// UI-optimistic, pending, and rejected history remains untouched.
pub struct PullChange {
    expected_item: LocalItemExpectation,
    item: LocalItem,
    history: Vec<LocalItemHistory>,
}

impl PullChange {
    pub fn new(
        scope: LocalSyncScope,
        expected_item: LocalItemExpectation,
        item: LocalItem,
        history: Vec<LocalItemHistory>,
    ) -> Result<Self, LocalSyncError> {
        let change = Self {
            expected_item,
            item,
            history,
        };
        validate_pull_change(scope, &change)?;
        Ok(change)
    }
}

/// A complete pull page persistence plan.
pub struct PullPage {
    scope: LocalSyncScope,
    expected_vault_cache_key_fp: String,
    expected_cursor: Option<String>,
    expected_last_seq: Option<i64>,
    next_cursor: String,
    next_last_seq: Option<i64>,
    committed_at: DateTime<Utc>,
    changes: Vec<PullChange>,
}

impl PullPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: LocalSyncScope,
        expected_vault_cache_key_fp: String,
        expected_cursor: Option<String>,
        expected_last_seq: Option<i64>,
        next_cursor: String,
        next_last_seq: Option<i64>,
        committed_at: DateTime<Utc>,
        changes: Vec<PullChange>,
    ) -> Result<Self, LocalSyncError> {
        let page = Self {
            scope,
            expected_vault_cache_key_fp,
            expected_cursor,
            expected_last_seq,
            next_cursor,
            next_last_seq,
            committed_at,
            changes,
        };
        validate_pull(&page)?;
        Ok(page)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PullReceipt {
    items: usize,
    history_entries: usize,
    cursor: String,
    last_seq: Option<i64>,
}

impl PullReceipt {
    pub fn items(&self) -> usize {
        self.items
    }

    pub fn history_entries(&self) -> usize {
        self.history_entries
    }

    pub fn cursor(&self) -> &str {
        &self.cursor
    }

    pub fn last_seq(&self) -> Option<i64> {
        self.last_seq
    }
}

/// An exact, storage-scoped projection reset plan.
#[derive(PartialEq, Eq)]
pub struct LocalStorageProof {
    id: Uuid,
    kind: StorageKind,
    name: String,
    server_url: Option<String>,
    server_name: Option<String>,
    server_fingerprint: Option<String>,
    account_subject: Option<String>,
    personal_vaults_enabled: bool,
    auth_method: Option<AuthMethod>,
}

impl LocalStorageProof {
    pub(crate) fn storage_id(&self) -> Uuid {
        self.id
    }
}

impl TryFrom<&LocalStorage> for LocalStorageProof {
    type Error = LocalSyncError;

    fn try_from(storage: &LocalStorage) -> Result<Self, Self::Error> {
        validate_storage(storage)?;
        Ok(Self {
            id: storage.id,
            kind: storage.kind,
            name: storage.name.clone(),
            server_url: storage.server_url.clone(),
            server_name: storage.server_name.clone(),
            server_fingerprint: storage.server_fingerprint.clone(),
            account_subject: storage.account_subject.clone(),
            personal_vaults_enabled: storage.personal_vaults_enabled,
            auth_method: storage.auth_method,
        })
    }
}

/// An exact, storage-scoped projection reset plan. A reset is always rejected
/// while the storage has pending rows, non-`Synced` items, or history outside
/// the confirmed server projection.
pub struct ResetProjection {
    storage_id: Uuid,
    expected_storage: LocalStorageProof,
    replacement_storage: Option<LocalStorage>,
}

impl ResetProjection {
    pub fn new(
        expected_storage: LocalStorageProof,
        replacement_storage: Option<LocalStorage>,
    ) -> Result<Self, LocalSyncError> {
        let reset = Self {
            storage_id: expected_storage.id,
            expected_storage,
            replacement_storage,
        };
        validate_reset(&reset)?;
        Ok(reset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetReceipt {
    pub pending_deleted: u64,
    pub cursors_deleted: u64,
    pub history_deleted: u64,
    pub items_deleted: u64,
    pub vaults_deleted: u64,
    pub storage_metadata_updated: bool,
}

pub enum LocalSyncError {
    StaleCursor {
        scope: LocalSyncScope,
    },
    StaleItem {
        item_id: Uuid,
    },
    StalePending {
        pending_id: Uuid,
    },
    StaleVaultKey {
        scope: LocalSyncScope,
    },
    PendingChangesPresent {
        storage_id: Uuid,
        count: u64,
    },
    ProjectionNotClean {
        storage_id: Uuid,
        dirty_items: u64,
        non_server_history: u64,
    },
    CrossStorageVaultReference {
        storage_id: Uuid,
        foreign_items: u64,
        foreign_history: u64,
    },
    StorageBindingChanged {
        storage_id: Uuid,
    },
    StorageGenerationChanged {
        storage_id: Uuid,
    },
    InvalidPlan {
        reason: &'static str,
    },
    /// SQLite returned an error while committing. The transaction may or may
    /// not be durable; callers must reconcile state and must not blindly retry.
    CommitOutcomeUnknown,
    Database(sqlx_core::Error),
}

impl fmt::Debug for LocalSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleCursor { scope } => formatter
                .debug_struct("StaleCursor")
                .field("scope", scope)
                .finish(),
            Self::StaleItem { item_id } => formatter
                .debug_struct("StaleItem")
                .field("item_id", item_id)
                .finish(),
            Self::StalePending { pending_id } => formatter
                .debug_struct("StalePending")
                .field("pending_id", pending_id)
                .finish(),
            Self::StaleVaultKey { scope } => formatter
                .debug_struct("StaleVaultKey")
                .field("scope", scope)
                .finish(),
            Self::PendingChangesPresent { storage_id, count } => formatter
                .debug_struct("PendingChangesPresent")
                .field("storage_id", storage_id)
                .field("count", count)
                .finish(),
            Self::ProjectionNotClean {
                storage_id,
                dirty_items,
                non_server_history,
            } => formatter
                .debug_struct("ProjectionNotClean")
                .field("storage_id", storage_id)
                .field("dirty_items", dirty_items)
                .field("non_server_history", non_server_history)
                .finish(),
            Self::CrossStorageVaultReference {
                storage_id,
                foreign_items,
                foreign_history,
            } => formatter
                .debug_struct("CrossStorageVaultReference")
                .field("storage_id", storage_id)
                .field("foreign_items", foreign_items)
                .field("foreign_history", foreign_history)
                .finish(),
            Self::StorageBindingChanged { storage_id } => formatter
                .debug_struct("StorageBindingChanged")
                .field("storage_id", storage_id)
                .finish(),
            Self::StorageGenerationChanged { storage_id } => formatter
                .debug_struct("StorageGenerationChanged")
                .field("storage_id", storage_id)
                .field("generation", &"<redacted>")
                .finish(),
            Self::InvalidPlan { reason } => formatter
                .debug_struct("InvalidPlan")
                .field("reason", reason)
                .finish(),
            Self::CommitOutcomeUnknown => formatter.write_str("CommitOutcomeUnknown(<redacted>)"),
            Self::Database(_) => formatter.write_str("Database(<redacted>)"),
        }
    }
}

impl fmt::Display for LocalSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::StaleCursor { .. } => "local sync cursor changed",
            Self::StaleItem { .. } => "local sync item changed",
            Self::StalePending { .. } => "local pending change changed",
            Self::StaleVaultKey { .. } => "local vault cache key changed",
            Self::PendingChangesPresent { .. } => "local pending changes prevent projection reset",
            Self::ProjectionNotClean { .. } => "local projection is not safe to reset",
            Self::CrossStorageVaultReference { .. } => {
                "cross-storage vault references prevent projection reset"
            }
            Self::StorageBindingChanged { .. } => "local storage binding changed",
            Self::StorageGenerationChanged { .. } => "local sync generation changed",
            Self::InvalidPlan { .. } => "invalid local sync persistence plan",
            Self::CommitOutcomeUnknown => "local sync commit outcome is unknown",
            Self::Database(_) => "local sync database operation failed",
        };
        formatter.write_str(message)
    }
}

impl StdError for LocalSyncError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Database(source) => Some(source),
            _ => None,
        }
    }
}

pub struct LocalSyncRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> LocalSyncRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Atomically publishes a push response after proving that its request
    /// cursor, items, and pending rows are still the exact local inputs used by
    /// the caller.
    pub async fn commit_push(&self, commit: &PushCommit) -> Result<PushReceipt, LocalSyncError> {
        validate_push(commit)?;
        let mut tx = self.begin_immediate().await?;
        let result = commit_push_in(&mut tx, commit).await;
        finish_transaction(tx, result).await
    }

    /// Commits a push response only while the exact endpoint/account binding
    /// and authorized configuration generation still match the local cache.
    pub async fn commit_push_leased(
        &self,
        commit: &PushCommit,
        expected_storage: &LocalStorageProof,
        generation: &LocalSyncGenerationProof,
    ) -> Result<PushReceipt, LocalSyncError> {
        validate_push(commit)?;
        validate_storage_proof(expected_storage)?;
        if expected_storage.id != commit.scope.storage_id {
            return invalid("push storage proof does not match its scope");
        }
        let mut tx = self.begin_immediate().await?;
        let result = commit_push_leased_in(&mut tx, commit, expected_storage, generation).await;
        finish_transaction(tx, result).await
    }

    /// Atomically installs a pull page and advances its cursor only after every
    /// item and complete history projection has been persisted.
    pub async fn commit_pull_page(&self, page: &PullPage) -> Result<PullReceipt, LocalSyncError> {
        validate_pull(page)?;
        let mut tx = self.begin_immediate().await?;
        let result = commit_pull_in(&mut tx, page).await;
        finish_transaction(tx, result).await
    }

    /// Commits a pull page only while the complete endpoint/account binding
    /// and the single-remote-cache invariant still match inside the same
    /// `BEGIN IMMEDIATE` transaction as the cursor and item CAS operations.
    pub async fn commit_pull_page_bound(
        &self,
        page: &PullPage,
        expected_storage: &LocalStorageProof,
    ) -> Result<PullReceipt, LocalSyncError> {
        validate_pull(page)?;
        validate_storage_proof(expected_storage)?;
        if expected_storage.id != page.scope.storage_id {
            return invalid("pull storage proof does not match its scope");
        }
        let mut tx = self.begin_immediate().await?;
        let result = commit_pull_bound_in(&mut tx, page, expected_storage).await;
        finish_transaction(tx, result).await
    }

    /// Commits a pull page only under an exact, already-claimed configuration
    /// generation.  A newer authorized revision advances the stored revision
    /// and content digest in the same writer transaction as the pull.  An
    /// equal revision must carry the exact same content digest; rollback and
    /// cross-repository/target reuse fail closed before projection writes.
    pub async fn commit_pull_page_leased(
        &self,
        page: &PullPage,
        expected_storage: &LocalStorageProof,
        generation: &LocalSyncGenerationProof,
    ) -> Result<PullReceipt, LocalSyncError> {
        validate_pull(page)?;
        validate_storage_proof(expected_storage)?;
        if expected_storage.id != page.scope.storage_id {
            return invalid("pull storage proof does not match its scope");
        }
        let mut tx = self.begin_immediate().await?;
        let result = commit_pull_leased_in(&mut tx, page, expected_storage, generation).await;
        finish_transaction(tx, result).await
    }

    /// Atomically removes only one storage's sync projection after checking the
    /// exact full storage row and proving that no pending, dirty-item, or local
    /// history state would be discarded.
    pub async fn reset_projection(
        &self,
        reset: &ResetProjection,
    ) -> Result<ResetReceipt, LocalSyncError> {
        validate_reset(reset)?;
        let mut tx = self.begin_immediate().await?;
        let result = reset_projection_in(&mut tx, reset).await;
        finish_transaction(tx, result).await
    }

    async fn begin_immediate(&self) -> Result<Transaction<'static, Sqlite>, LocalSyncError> {
        // SQLx 0.8 supports a custom SQLite begin statement. BEGIN IMMEDIATE
        // takes the single writer reservation before any CAS proof is read.
        self.pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(LocalSyncError::Database)
    }
}

async fn finish_transaction<T>(
    tx: Transaction<'static, Sqlite>,
    result: Result<T, LocalSyncError>,
) -> Result<T, LocalSyncError> {
    match result {
        Ok(receipt) => {
            // A COMMIT transport/IO error does not prove whether SQLite made
            // the transaction durable. Expose ambiguity explicitly so callers
            // reconcile state instead of replaying a destructive plan.
            tx.commit()
                .await
                .map_err(|_| LocalSyncError::CommitOutcomeUnknown)?;
            Ok(receipt)
        }
        Err(error) => {
            tx.rollback().await.map_err(LocalSyncError::Database)?;
            Err(error)
        }
    }
}

async fn commit_push_in(
    tx: &mut Transaction<'static, Sqlite>,
    commit: &PushCommit,
) -> Result<PushReceipt, LocalSyncError> {
    ensure_materialized_scope(tx, commit.scope).await?;
    ensure_checkpoint(
        tx,
        commit.scope,
        commit.expected_cursor.as_deref(),
        commit.expected_last_seq,
    )
    .await?;

    // Prove the whole response against one writer-serialized snapshot before
    // applying any outcome. Mutations still repeat the CAS in their WHERE
    // clauses so this invariant remains visible in the SQL itself.
    for outcome in &commit.outcomes {
        match &outcome.kind {
            PushOutcomeKind::Applied {
                pending,
                expected_item,
                ..
            } => {
                ensure_item_expectation(tx, commit.scope, pending.item_id, expected_item).await?;
                ensure_pending_proof(tx, commit.scope, pending).await?;
            }
            PushOutcomeKind::Conflict => return invalid("conflicted push batch is fail-closed"),
        }
    }

    let mut applied = 0;
    for outcome in &commit.outcomes {
        match &outcome.kind {
            PushOutcomeKind::Applied {
                pending,
                expected_item,
                item,
            } => {
                apply_item_projection(tx, commit.scope, pending.item_id, expected_item, item)
                    .await?;
                delete_pending_exact(tx, commit.scope, pending).await?;
                applied += 1;
            }
            PushOutcomeKind::Conflict => return invalid("conflicted push batch is fail-closed"),
        }
    }

    Ok(PushReceipt {
        applied,
        pending_deleted: commit.outcomes.len(),
        server_head_hint: commit.server_head_hint.clone(),
        last_seq: commit.expected_last_seq,
    })
}

async fn commit_push_leased_in(
    tx: &mut Transaction<'static, Sqlite>,
    commit: &PushCommit,
    expected_storage: &LocalStorageProof,
    generation: &LocalSyncGenerationProof,
) -> Result<PushReceipt, LocalSyncError> {
    ensure_storage_proof(tx, expected_storage).await?;
    ensure_single_remote_storage(tx, expected_storage.id).await?;
    ensure_bound_generation_and_advance(tx, expected_storage.id, generation).await?;
    commit_push_in(tx, commit).await
}

async fn commit_pull_in(
    tx: &mut Transaction<'static, Sqlite>,
    page: &PullPage,
) -> Result<PullReceipt, LocalSyncError> {
    ensure_materialized_scope(tx, page.scope).await?;
    ensure_vault_cache_key_fingerprint(tx, page.scope, page.expected_vault_cache_key_fp.as_str())
        .await?;
    ensure_checkpoint(
        tx,
        page.scope,
        page.expected_cursor.as_deref(),
        page.expected_last_seq,
    )
    .await?;

    for change in &page.changes {
        ensure_item_expectation(tx, page.scope, change.item.id, &change.expected_item).await?;
        ensure_no_pending_for_item(tx, page.scope, change.item.id).await?;
    }

    let mut history_entries = 0;
    for change in &page.changes {
        apply_item_projection(
            tx,
            page.scope,
            change.item.id,
            &change.expected_item,
            &change.item,
        )
        .await?;
        replace_history(tx, page.scope, change).await?;
        history_entries += change.history.len();
    }

    publish_checkpoint(tx, page).await?;

    Ok(PullReceipt {
        items: page.changes.len(),
        history_entries,
        cursor: page.next_cursor.clone(),
        last_seq: page.next_last_seq,
    })
}

async fn commit_pull_bound_in(
    tx: &mut Transaction<'static, Sqlite>,
    page: &PullPage,
    expected_storage: &LocalStorageProof,
) -> Result<PullReceipt, LocalSyncError> {
    ensure_storage_proof(tx, expected_storage).await?;
    ensure_single_remote_storage(tx, expected_storage.id).await?;
    commit_pull_in(tx, page).await
}

async fn commit_pull_leased_in(
    tx: &mut Transaction<'static, Sqlite>,
    page: &PullPage,
    expected_storage: &LocalStorageProof,
    generation: &LocalSyncGenerationProof,
) -> Result<PullReceipt, LocalSyncError> {
    ensure_storage_proof(tx, expected_storage).await?;
    ensure_single_remote_storage(tx, expected_storage.id).await?;
    ensure_bound_generation_and_advance(tx, expected_storage.id, generation).await?;
    commit_pull_in(tx, page).await
}

async fn reset_projection_in(
    tx: &mut Transaction<'static, Sqlite>,
    reset: &ResetProjection,
) -> Result<ResetReceipt, LocalSyncError> {
    ensure_storage_proof(tx, &reset.expected_storage).await?;
    ensure_vault_references_are_storage_scoped(tx, reset.storage_id).await?;

    let pending_count: i64 = query!(
        r#"SELECT COUNT(*) AS count FROM pending_changes WHERE storage_id = ?1"#,
        reset.storage_id
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?
    .try_get("count")
    .map_err(LocalSyncError::Database)?;
    let pending_count = u64::try_from(pending_count).map_err(|_| LocalSyncError::InvalidPlan {
        reason: "pending row count is outside the supported range",
    })?;
    if pending_count != 0 {
        return Err(LocalSyncError::PendingChangesPresent {
            storage_id: reset.storage_id,
            count: pending_count,
        });
    }

    let cleanliness = query!(
        r#"
        SELECT
            (
                SELECT COUNT(*)
                FROM items_cache
                WHERE storage_id = ?1 AND sync_status != ?2
            ) AS dirty_items,
            (
                SELECT COUNT(*)
                FROM item_history
                WHERE storage_id = ?1 AND (source != ?3 OR sync_status != ?4)
            ) AS non_server_history
        "#,
        reset.storage_id,
        SyncStatus::Synced.as_i32(),
        HistorySource::Server.as_i32(),
        HistorySyncStatus::Confirmed.as_i32()
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let dirty_items = u64::try_from(
        cleanliness
            .try_get::<i64, _>("dirty_items")
            .map_err(LocalSyncError::Database)?,
    )
    .map_err(|_| LocalSyncError::InvalidPlan {
        reason: "dirty item count is outside the supported range",
    })?;
    let non_server_history = u64::try_from(
        cleanliness
            .try_get::<i64, _>("non_server_history")
            .map_err(LocalSyncError::Database)?,
    )
    .map_err(|_| LocalSyncError::InvalidPlan {
        reason: "local history count is outside the supported range",
    })?;
    if dirty_items != 0 || non_server_history != 0 {
        return Err(LocalSyncError::ProjectionNotClean {
            storage_id: reset.storage_id,
            dirty_items,
            non_server_history,
        });
    }

    let pending_deleted = delete_storage_rows(tx, "pending_changes", reset.storage_id).await?;
    let cursors_deleted = delete_storage_rows(tx, "sync_cursors", reset.storage_id).await?;
    let history_deleted = delete_storage_rows(tx, "item_history", reset.storage_id).await?;
    let items_deleted = delete_storage_rows(tx, "items_cache", reset.storage_id).await?;
    let vaults_deleted = delete_storage_rows(tx, "local_vaults", reset.storage_id).await?;

    let storage_metadata_updated = if let Some(storage) = &reset.replacement_storage {
        let expected = &reset.expected_storage;
        let result = query!(
            r#"
            UPDATE storages
            SET kind = ?1,
                name = ?2,
                server_url = ?3,
                server_name = ?4,
                server_fingerprint = ?5,
                account_subject = ?6,
                personal_vaults_enabled = ?7,
                auth_method = ?8
            WHERE id = ?9
              AND kind = ?10
              AND name = ?11
              AND server_url IS ?12
              AND server_name IS ?13
              AND server_fingerprint IS ?14
              AND account_subject IS ?15
              AND personal_vaults_enabled = ?16
              AND auth_method IS ?17
            "#,
            storage.kind.as_i32(),
            storage.name.as_str(),
            storage.server_url.as_deref(),
            storage.server_name.as_deref(),
            storage.server_fingerprint.as_deref(),
            storage.account_subject.as_deref(),
            storage.personal_vaults_enabled,
            storage.auth_method.map(|value| value.as_i32()),
            expected.id,
            expected.kind.as_i32(),
            expected.name.as_str(),
            expected.server_url.as_deref(),
            expected.server_name.as_deref(),
            expected.server_fingerprint.as_deref(),
            expected.account_subject.as_deref(),
            expected.personal_vaults_enabled,
            expected.auth_method.map(|value| value.as_i32())
        )
        .execute(&mut **tx)
        .await
        .map_err(LocalSyncError::Database)?;
        if result.rows_affected() != 1 {
            return Err(LocalSyncError::StorageBindingChanged {
                storage_id: reset.storage_id,
            });
        }
        true
    } else {
        false
    };

    Ok(ResetReceipt {
        pending_deleted,
        cursors_deleted,
        history_deleted,
        items_deleted,
        vaults_deleted,
        storage_metadata_updated,
    })
}

async fn ensure_vault_references_are_storage_scoped(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
) -> Result<(), LocalSyncError> {
    // `items_cache` and `item_history` currently reference a vault by its
    // globally unique id, not by `(storage_id, vault_id)`. Fail closed before
    // deleting target vaults if malformed rows from another storage would be
    // reached by SQLite's `ON DELETE CASCADE`.
    let references = sqlx_core::query::query::<Sqlite>(
        r#"
        SELECT
            (
                SELECT COUNT(*)
                FROM items_cache AS item
                WHERE item.storage_id != ?1
                  AND EXISTS (
                      SELECT 1
                      FROM local_vaults AS vault
                      WHERE vault.storage_id = ?1 AND vault.id = item.vault_id
                  )
            ) AS foreign_items,
            (
                SELECT COUNT(*)
                FROM item_history AS history
                WHERE history.storage_id != ?1
                  AND EXISTS (
                      SELECT 1
                      FROM local_vaults AS vault
                      WHERE vault.storage_id = ?1 AND vault.id = history.vault_id
                  )
            ) AS foreign_history
        "#,
    )
    .bind(storage_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let foreign_items = u64::try_from(
        references
            .try_get::<i64, _>("foreign_items")
            .map_err(LocalSyncError::Database)?,
    )
    .map_err(|_| LocalSyncError::InvalidPlan {
        reason: "cross-storage item count is outside the supported range",
    })?;
    let foreign_history = u64::try_from(
        references
            .try_get::<i64, _>("foreign_history")
            .map_err(LocalSyncError::Database)?,
    )
    .map_err(|_| LocalSyncError::InvalidPlan {
        reason: "cross-storage history count is outside the supported range",
    })?;
    if foreign_items != 0 || foreign_history != 0 {
        return Err(LocalSyncError::CrossStorageVaultReference {
            storage_id,
            foreign_items,
            foreign_history,
        });
    }
    Ok(())
}

async fn delete_storage_rows(
    tx: &mut Transaction<'static, Sqlite>,
    table: &'static str,
    storage_id: Uuid,
) -> Result<u64, LocalSyncError> {
    // `table` is internal and selected only by the fixed call sites above.
    let sql = format!("DELETE FROM {table} WHERE storage_id = ?1");
    sqlx_core::query::query::<Sqlite>(&sql)
        .bind(storage_id)
        .execute(&mut **tx)
        .await
        .map(|result| result.rows_affected())
        .map_err(LocalSyncError::Database)
}

async fn ensure_materialized_scope(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
) -> Result<(), LocalSyncError> {
    ensure_storage_kinds_bounded(tx, scope.storage_id).await?;
    let storage = query!(
        r#"
        SELECT 1
        FROM storages
        WHERE id = ?1
          AND CASE
            WHEN typeof(kind) = 'integer' THEN kind = ?2
            ELSE 0
          END
        "#,
        scope.storage_id,
        StorageKind::Remote.as_i32()
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let vault = bounded_vault_scope_membership(tx, scope.storage_id, scope.vault_id)
        .await
        .map_err(LocalSyncError::Database)?;
    if storage.is_none() || vault != Some(true) {
        return Err(LocalSyncError::InvalidPlan {
            reason: "sync scope is not materialized locally",
        });
    }
    Ok(())
}

pub(crate) async fn ensure_storage_proof(
    tx: &mut Transaction<'static, Sqlite>,
    proof: &LocalStorageProof,
) -> Result<(), LocalSyncError> {
    ensure_storage_kinds_bounded(tx, proof.id).await?;
    ensure_storage_projection_bounded(tx, proof.id).await?;
    let row = query!(
        r#"
        SELECT 1
        FROM storages
        WHERE id = ?1
          AND kind = ?2
          AND name = ?3
          AND server_url IS ?4
          AND server_name IS ?5
          AND server_fingerprint IS ?6
          AND account_subject IS ?7
          AND personal_vaults_enabled = ?8
          AND auth_method IS ?9
        "#,
        proof.id,
        proof.kind.as_i32(),
        proof.name.as_str(),
        proof.server_url.as_deref(),
        proof.server_name.as_deref(),
        proof.server_fingerprint.as_deref(),
        proof.account_subject.as_deref(),
        proof.personal_vaults_enabled,
        proof.auth_method.map(|value| value.as_i32())
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if row.is_none() {
        return Err(LocalSyncError::StorageBindingChanged {
            storage_id: proof.id,
        });
    }
    Ok(())
}

async fn ensure_storage_projection_bounded(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
) -> Result<(), LocalSyncError> {
    let valid = query!(
        r#"
        SELECT CASE WHEN
            CASE WHEN typeof(id) IN ('blob', 'text')
                THEN octet_length(id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(kind) = 'integer'
                THEN kind IN (1, 2) ELSE 0 END
            AND CASE WHEN typeof(name) = 'text'
                THEN octet_length(name) BETWEEN 1 AND ?2 ELSE 0 END
            AND (server_url IS NULL OR CASE WHEN typeof(server_url) = 'text'
                THEN octet_length(server_url) BETWEEN 1 AND ?3 ELSE 0 END)
            AND (server_name IS NULL OR CASE WHEN typeof(server_name) = 'text'
                THEN octet_length(server_name) BETWEEN 1 AND ?4 ELSE 0 END)
            AND (server_fingerprint IS NULL OR CASE
                WHEN typeof(server_fingerprint) = 'text'
                THEN octet_length(server_fingerprint) BETWEEN 1 AND ?4 ELSE 0 END)
            AND (account_subject IS NULL OR CASE WHEN typeof(account_subject) = 'text'
                THEN octet_length(account_subject) BETWEEN 1 AND ?4 ELSE 0 END)
            AND CASE WHEN typeof(personal_vaults_enabled) = 'integer'
                THEN personal_vaults_enabled IN (0, 1) ELSE 0 END
            AND CASE
                WHEN auth_method IS NULL THEN 1
                WHEN typeof(auth_method) = 'integer'
                    THEN auth_method IN (1, 2, 3)
                ELSE 0
            END
            AND CASE
                WHEN sync_config_repository_fp IS NULL THEN
                    sync_stable_target_fp IS NULL
                    AND sync_config_revision IS NULL
                    AND sync_config_content_fp IS NULL
                WHEN kind != ?5 THEN 0
                WHEN typeof(sync_config_repository_fp) != 'blob' THEN 0
                WHEN octet_length(sync_config_repository_fp) != 32 THEN 0
                WHEN typeof(sync_stable_target_fp) != 'blob' THEN 0
                WHEN octet_length(sync_stable_target_fp) != 32 THEN 0
                WHEN typeof(sync_config_revision) != 'blob' THEN 0
                WHEN octet_length(sync_config_revision) != 8 THEN 0
                WHEN typeof(sync_config_content_fp) != 'blob' THEN 0
                WHEN octet_length(sync_config_content_fp) != 32 THEN 0
                ELSE 1
            END
        THEN 1 ELSE 0 END AS valid
        FROM storages
        WHERE id = ?1
        "#,
        storage_id,
        MAX_DISPLAY_NAME_BYTES as i64,
        MAX_SERVER_URL_BYTES as i64,
        MAX_SERVER_METADATA_BYTES as i64,
        StorageKind::Remote.as_i32()
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let is_valid = match valid {
        Some(row) => {
            row.try_get::<i64, _>("valid")
                .map_err(LocalSyncError::Database)?
                == 1
        }
        None => false,
    };
    if !is_valid {
        return Err(LocalSyncError::StorageBindingChanged { storage_id });
    }
    Ok(())
}

pub(crate) async fn ensure_single_remote_storage(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
) -> Result<(), LocalSyncError> {
    ensure_storage_kinds_bounded(tx, storage_id).await?;
    let row = query!(
        r#"
        SELECT COUNT(*) AS count
        FROM (
            SELECT 1
            FROM storages
            WHERE CASE
                WHEN typeof(kind) = 'integer' THEN kind = ?1
                ELSE 0
            END
            LIMIT 2
        )
        "#,
        StorageKind::Remote.as_i32()
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let count: i64 = row.try_get("count").map_err(LocalSyncError::Database)?;
    if count != 1 {
        return Err(LocalSyncError::StorageBindingChanged { storage_id });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalGenerationBindingState {
    Unbound,
    Exact,
    Older,
}

/// Reads only scalar comparison results after the storage preflight has
/// proved every generation field fixed-size.  No persisted digest is copied
/// into application memory.
pub(crate) async fn inspect_generation_binding(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
    generation: &LocalSyncGenerationProof,
) -> Result<LocalGenerationBindingState, LocalSyncError> {
    ensure_storage_projection_bounded(tx, storage_id).await?;
    let revision = generation.revision_be();
    let row = query!(
        r#"
        SELECT CASE
            WHEN sync_config_repository_fp IS NULL THEN 0
            WHEN sync_config_repository_fp != ?2 OR sync_stable_target_fp != ?3 THEN 3
            WHEN sync_config_revision > ?4 THEN 3
            WHEN sync_config_revision = ?4 AND sync_config_content_fp != ?5 THEN 3
            WHEN sync_config_revision = ?4 THEN 1
            ELSE 2
        END AS generation_state
        FROM storages
        WHERE id = ?1
        "#,
        storage_id,
        generation.repository_fingerprint.as_slice(),
        generation.stable_target_fingerprint.as_slice(),
        revision.as_slice(),
        generation.config_content_fingerprint.as_slice()
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let state = row
        .ok_or(LocalSyncError::StorageGenerationChanged { storage_id })?
        .try_get::<i64, _>("generation_state")
        .map_err(LocalSyncError::Database)?;
    match state {
        0 => Ok(LocalGenerationBindingState::Unbound),
        1 => Ok(LocalGenerationBindingState::Exact),
        2 => Ok(LocalGenerationBindingState::Older),
        _ => Err(LocalSyncError::StorageGenerationChanged { storage_id }),
    }
}

pub(crate) async fn claim_generation(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
    generation: &LocalSyncGenerationProof,
) -> Result<(), LocalSyncError> {
    let revision = generation.revision_be();
    let updated = query!(
        r#"
        UPDATE storages
        SET sync_config_repository_fp = ?2,
            sync_stable_target_fp = ?3,
            sync_config_revision = ?4,
            sync_config_content_fp = ?5
        WHERE id = ?1
          AND kind = ?6
          AND sync_config_repository_fp IS NULL
          AND sync_stable_target_fp IS NULL
          AND sync_config_revision IS NULL
          AND sync_config_content_fp IS NULL
        "#,
        storage_id,
        generation.repository_fingerprint.as_slice(),
        generation.stable_target_fingerprint.as_slice(),
        revision.as_slice(),
        generation.config_content_fingerprint.as_slice(),
        StorageKind::Remote.as_i32()
    )
    .execute(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?
    .rows_affected();
    if updated != 1 {
        return Err(LocalSyncError::StorageGenerationChanged { storage_id });
    }
    Ok(())
}

pub(crate) async fn ensure_bound_generation_and_advance(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
    generation: &LocalSyncGenerationProof,
) -> Result<(), LocalSyncError> {
    match inspect_generation_binding(tx, storage_id, generation).await? {
        LocalGenerationBindingState::Unbound => {
            Err(LocalSyncError::StorageGenerationChanged { storage_id })
        }
        LocalGenerationBindingState::Exact => Ok(()),
        LocalGenerationBindingState::Older => {
            let revision = generation.revision_be();
            let updated = query!(
                r#"
                UPDATE storages
                SET sync_config_revision = ?4,
                    sync_config_content_fp = ?5
                WHERE id = ?1
                  AND sync_config_repository_fp = ?2
                  AND sync_stable_target_fp = ?3
                  AND sync_config_revision < ?4
                "#,
                storage_id,
                generation.repository_fingerprint.as_slice(),
                generation.stable_target_fingerprint.as_slice(),
                revision.as_slice(),
                generation.config_content_fingerprint.as_slice()
            )
            .execute(&mut **tx)
            .await
            .map_err(LocalSyncError::Database)?
            .rows_affected();
            if updated != 1 {
                return Err(LocalSyncError::StorageGenerationChanged { storage_id });
            }
            Ok(())
        }
    }
}

async fn ensure_storage_kinds_bounded(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
) -> Result<(), LocalSyncError> {
    let corrupt = query!(
        r#"
        SELECT 1
        FROM storages
        WHERE CASE
            WHEN typeof(id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(id) NOT IN (16, 36) THEN 1
            WHEN typeof(kind) != 'integer' THEN 1
            WHEN kind NOT IN (1, 2) THEN 1
            ELSE 0
        END
        LIMIT 1
        "#
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if corrupt.is_some() {
        return Err(LocalSyncError::StorageBindingChanged { storage_id });
    }
    Ok(())
}

async fn ensure_checkpoint(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    expected_cursor: Option<&str>,
    expected_last_seq: Option<i64>,
) -> Result<(), LocalSyncError> {
    ensure_checkpoint_projection_bounded(tx, scope).await?;
    // Compare both checkpoint fields inside SQLite. A missing row is equivalent
    // only to the all-NULL initial checkpoint.
    let matches = query!(
        r#"
        SELECT 1
        WHERE EXISTS (
            SELECT 1
            FROM sync_cursors
            WHERE storage_id = ?1
              AND vault_id = ?2
              AND cursor IS ?3
              AND last_seq IS ?4
        )
        OR (
            ?3 IS NULL
            AND ?4 IS NULL
            AND NOT EXISTS (
                SELECT 1
                FROM sync_cursors
                WHERE storage_id = ?1 AND vault_id = ?2
            )
        )
        "#,
        scope.storage_id,
        scope.vault_id,
        expected_cursor,
        expected_last_seq
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?
    .is_some();
    if !matches {
        return Err(LocalSyncError::StaleCursor { scope });
    }
    Ok(())
}

async fn ensure_checkpoint_projection_bounded(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
) -> Result<(), LocalSyncError> {
    ensure_checkpoint_identifiers_bounded(tx, scope).await?;
    let valid = query!(
        r#"
        SELECT CASE WHEN
            CASE WHEN typeof(storage_id) IN ('blob', 'text')
                THEN octet_length(storage_id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(vault_id) IN ('blob', 'text')
                THEN octet_length(vault_id) IN (16, 36) ELSE 0 END
            AND (cursor IS NULL OR CASE WHEN typeof(cursor) = 'text'
                THEN octet_length(cursor) BETWEEN 1 AND ?3 ELSE 0 END)
            AND CASE
                WHEN last_seq IS NULL THEN 1
                WHEN typeof(last_seq) = 'integer' THEN last_seq >= 1
                ELSE 0
            END
            AND (last_sync_at IS NULL OR CASE WHEN typeof(last_sync_at) = 'text'
                THEN octet_length(last_sync_at) BETWEEN 1 AND ?4 ELSE 0 END)
        THEN 1 ELSE 0 END AS valid
        FROM sync_cursors
        WHERE storage_id = ?1 AND vault_id = ?2
        "#,
        scope.storage_id,
        scope.vault_id,
        MAX_CURSOR_BYTES as i64,
        MAX_TIMESTAMP_BYTES as i64
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if let Some(row) = valid {
        let is_valid = row
            .try_get::<i64, _>("valid")
            .map_err(LocalSyncError::Database)?
            == 1;
        if !is_valid {
            return Err(LocalSyncError::StaleCursor { scope });
        }
    }
    Ok(())
}

async fn ensure_checkpoint_identifiers_bounded(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
) -> Result<(), LocalSyncError> {
    let corrupt = query!(
        r#"
        SELECT 1
        FROM sync_cursors
        WHERE CASE
            WHEN typeof(storage_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(storage_id) NOT IN (16, 36) THEN 1
            WHEN typeof(vault_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(vault_id) NOT IN (16, 36) THEN 1
            ELSE 0
        END
        LIMIT 1
        "#
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if corrupt.is_some() {
        return Err(LocalSyncError::StaleCursor { scope });
    }
    Ok(())
}

async fn ensure_vault_cache_key_fingerprint(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    expected_cache_key_fp: &str,
) -> Result<(), LocalSyncError> {
    let bounded = bounded_vault_preflight(tx, scope.storage_id, Some(scope.vault_id))
        .await
        .map_err(LocalSyncError::Database)?;
    if bounded != Some(true) {
        return Err(LocalSyncError::StaleVaultKey { scope });
    }
    let matches = query!(
        r#"
        SELECT 1
        FROM local_vaults
        WHERE storage_id = ?1
          AND id = ?2
          AND cache_key_fp = ?3
        "#,
        scope.storage_id,
        scope.vault_id,
        expected_cache_key_fp
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?
    .is_some();
    if !matches {
        return Err(LocalSyncError::StaleVaultKey { scope });
    }
    Ok(())
}

async fn ensure_item_expectation(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    item_id: Uuid,
    expectation: &LocalItemExpectation,
) -> Result<(), LocalSyncError> {
    let matches = match expectation {
        LocalItemExpectation::Absent => {
            query!(r#"SELECT 1 FROM items_cache WHERE id = ?1"#, item_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(LocalSyncError::Database)?
                .is_none()
        }
        LocalItemExpectation::Exact(proof) => {
            ensure_item_projection_bounded(tx, item_id).await?;
            query!(
                r#"
                SELECT 1
                FROM items_cache
                WHERE id = ?1
                  AND storage_id = ?2
                  AND vault_id = ?3
                  AND path = ?4
                  AND name = ?5
                  AND type_id = ?6
                  AND payload_enc = ?7
                  AND checksum = ?8
                  AND cache_key_fp IS ?9
                  AND version = ?10
                  AND deleted_at IS ?11
                  AND updated_at = ?12
                  AND sync_status = ?13
                "#,
                proof.id,
                scope.storage_id,
                scope.vault_id,
                proof.path.as_str(),
                proof.name.as_str(),
                proof.type_id.as_str(),
                &proof.payload_enc,
                proof.checksum.as_str(),
                proof.cache_key_fp.as_deref(),
                proof.version,
                proof.deleted_at,
                proof.updated_at,
                proof.sync_status.as_i32()
            )
            .fetch_optional(&mut **tx)
            .await
            .map_err(LocalSyncError::Database)?
            .is_some()
        }
    };
    if !matches {
        return Err(LocalSyncError::StaleItem { item_id });
    }
    Ok(())
}

async fn ensure_item_projection_bounded(
    tx: &mut Transaction<'static, Sqlite>,
    item_id: Uuid,
) -> Result<(), LocalSyncError> {
    let valid = query!(
        r#"
        SELECT CASE WHEN
            CASE WHEN typeof(id) IN ('blob', 'text')
                THEN octet_length(id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(storage_id) IN ('blob', 'text')
                THEN octet_length(storage_id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(vault_id) IN ('blob', 'text')
                THEN octet_length(vault_id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(path) = 'text'
                THEN octet_length(path) BETWEEN 1 AND ?2 ELSE 0 END
            AND CASE WHEN typeof(name) = 'text'
                THEN octet_length(name) BETWEEN 1 AND ?3 ELSE 0 END
            AND CASE WHEN typeof(type_id) = 'text'
                THEN octet_length(type_id) BETWEEN 1 AND ?4 ELSE 0 END
            AND CASE WHEN typeof(payload_enc) = 'blob'
                THEN length(payload_enc) <= ?5 ELSE 0 END
            AND CASE WHEN typeof(checksum) = 'text'
                THEN octet_length(checksum) BETWEEN 1 AND ?6 ELSE 0 END
            AND (cache_key_fp IS NULL OR CASE WHEN typeof(cache_key_fp) = 'text'
                THEN octet_length(cache_key_fp) = ?7 ELSE 0 END)
            AND CASE WHEN typeof(version) = 'integer'
                THEN version >= 1 ELSE 0 END
            AND (deleted_at IS NULL OR CASE WHEN typeof(deleted_at) = 'text'
                THEN octet_length(deleted_at) BETWEEN 1 AND ?8 ELSE 0 END)
            AND CASE WHEN typeof(updated_at) = 'text'
                THEN octet_length(updated_at) BETWEEN 1 AND ?8 ELSE 0 END
            AND CASE WHEN typeof(sync_status) = 'integer'
                THEN sync_status IN (1, 2, 3, 4, 5, 6) ELSE 0 END
        THEN 1 ELSE 0 END AS valid
        FROM items_cache
        WHERE id = ?1
        "#,
        item_id,
        MAX_ITEM_PATH_LEN as i64,
        MAX_ITEM_NAME_LEN as i64,
        MAX_TYPE_ID_BYTES as i64,
        MAX_ITEM_CIPHERTEXT_BYTES as i64,
        MAX_CHECKSUM_BYTES as i64,
        CACHE_KEY_FINGERPRINT_BYTES as i64,
        MAX_TIMESTAMP_BYTES as i64
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let is_valid = match valid {
        Some(row) => {
            row.try_get::<i64, _>("valid")
                .map_err(LocalSyncError::Database)?
                == 1
        }
        None => false,
    };
    if !is_valid {
        return Err(LocalSyncError::StaleItem { item_id });
    }
    Ok(())
}

async fn ensure_no_pending_for_item(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    item_id: Uuid,
) -> Result<(), LocalSyncError> {
    ensure_pending_identifiers_bounded(tx).await?;
    let row = query!(
        r#"
        SELECT id as "id"
        FROM pending_changes
        WHERE storage_id = ?1 AND item_id = ?2
        LIMIT 1
        "#,
        scope.storage_id,
        item_id
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if let Some(row) = row {
        let pending_id = row.try_get("id").map_err(LocalSyncError::Database)?;
        return Err(LocalSyncError::StalePending { pending_id });
    }
    Ok(())
}

async fn ensure_pending_identifiers_bounded(
    tx: &mut Transaction<'static, Sqlite>,
) -> Result<(), LocalSyncError> {
    let corrupt = query!(
        r#"
        SELECT 1
        FROM pending_changes
        WHERE CASE
            WHEN typeof(id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(id) NOT IN (16, 36) THEN 1
            WHEN typeof(storage_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(storage_id) NOT IN (16, 36) THEN 1
            WHEN typeof(vault_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(vault_id) NOT IN (16, 36) THEN 1
            WHEN typeof(item_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(item_id) NOT IN (16, 36) THEN 1
            ELSE 0
        END
        LIMIT 1
        "#
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if corrupt.is_some() {
        return invalid("local pending identifiers are corrupt");
    }
    Ok(())
}

async fn ensure_pending_proof(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    proof: &LocalPendingProof,
) -> Result<(), LocalSyncError> {
    ensure_pending_identifiers_bounded(tx).await?;
    ensure_pending_projection_bounded(tx, proof.id).await?;
    let row = query!(
        r#"
        SELECT 1
        FROM pending_changes
        WHERE id = ?1
          AND storage_id = ?2
          AND vault_id = ?3
          AND item_id = ?4
          AND operation = ?5
          AND payload_enc IS ?6
          AND checksum IS ?7
          AND path IS ?8
          AND name IS ?9
          AND type_id IS ?10
          AND base_seq IS ?11
          AND created_at = ?12
        "#,
        proof.id,
        scope.storage_id,
        scope.vault_id,
        proof.item_id,
        proof.operation.as_i32(),
        proof.payload_enc.as_deref(),
        proof.checksum.as_deref(),
        proof.path.as_deref(),
        proof.name.as_deref(),
        proof.type_id.as_deref(),
        proof.base_seq,
        proof.created_at
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if row.is_none() {
        return Err(LocalSyncError::StalePending {
            pending_id: proof.id,
        });
    }
    Ok(())
}

async fn ensure_pending_projection_bounded(
    tx: &mut Transaction<'static, Sqlite>,
    pending_id: Uuid,
) -> Result<(), LocalSyncError> {
    let valid = query!(
        r#"
        SELECT CASE WHEN
            CASE WHEN typeof(id) IN ('blob', 'text')
                THEN octet_length(id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(storage_id) IN ('blob', 'text')
                THEN octet_length(storage_id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(vault_id) IN ('blob', 'text')
                THEN octet_length(vault_id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(item_id) IN ('blob', 'text')
                THEN octet_length(item_id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(operation) = 'integer'
                THEN operation IN (1, 2, 3, 4) ELSE 0 END
            AND (payload_enc IS NULL OR CASE WHEN typeof(payload_enc) = 'blob'
                THEN length(payload_enc) <= ?2 ELSE 0 END)
            AND (checksum IS NULL OR CASE WHEN typeof(checksum) = 'text'
                THEN octet_length(checksum) BETWEEN 1 AND ?3 ELSE 0 END)
            AND (path IS NULL OR CASE WHEN typeof(path) = 'text'
                THEN octet_length(path) BETWEEN 1 AND ?4 ELSE 0 END)
            AND (name IS NULL OR CASE WHEN typeof(name) = 'text'
                THEN octet_length(name) BETWEEN 1 AND ?5 ELSE 0 END)
            AND (type_id IS NULL OR CASE WHEN typeof(type_id) = 'text'
                THEN octet_length(type_id) BETWEEN 1 AND ?6 ELSE 0 END)
            AND CASE
                WHEN base_seq IS NULL THEN 1
                WHEN typeof(base_seq) = 'integer' THEN base_seq >= 1
                ELSE 0
            END
            AND CASE WHEN typeof(created_at) = 'text'
                THEN octet_length(created_at) BETWEEN 1 AND ?7 ELSE 0 END
        THEN 1 ELSE 0 END AS valid
        FROM pending_changes
        WHERE id = ?1
        "#,
        pending_id,
        MAX_ITEM_CIPHERTEXT_BYTES as i64,
        MAX_CHECKSUM_BYTES as i64,
        MAX_ITEM_PATH_LEN as i64,
        MAX_ITEM_NAME_LEN as i64,
        MAX_TYPE_ID_BYTES as i64,
        MAX_TIMESTAMP_BYTES as i64
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let is_valid = match valid {
        Some(row) => {
            row.try_get::<i64, _>("valid")
                .map_err(LocalSyncError::Database)?
                == 1
        }
        None => false,
    };
    if !is_valid {
        return Err(LocalSyncError::StalePending { pending_id });
    }
    Ok(())
}

async fn apply_item_projection(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    expected_item_id: Uuid,
    expectation: &LocalItemExpectation,
    item: &LocalItem,
) -> Result<(), LocalSyncError> {
    match expectation {
        LocalItemExpectation::Absent => {
            let result = query!(
                r#"
                INSERT INTO items_cache (
                    id, storage_id, vault_id, path, name, type_id, payload_enc, checksum,
                    cache_key_fp, version, deleted_at, updated_at, sync_status
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                "#,
                item.id,
                item.storage_id,
                item.vault_id,
                item.path.as_str(),
                item.name.as_str(),
                item.type_id.as_str(),
                &item.payload_enc,
                item.checksum.as_str(),
                item.cache_key_fp.as_deref(),
                item.version,
                item.deleted_at,
                item.updated_at,
                item.sync_status.as_i32()
            )
            .execute(&mut **tx)
            .await;
            if let Err(error) = result {
                return Err(LocalSyncError::Database(error));
            }
        }
        LocalItemExpectation::Exact(proof) => {
            let result = query!(
                r#"
                UPDATE items_cache
                SET path = ?14,
                    name = ?15,
                    type_id = ?16,
                    payload_enc = ?17,
                    checksum = ?18,
                    cache_key_fp = ?19,
                    version = ?20,
                    deleted_at = ?21,
                    updated_at = ?22,
                    sync_status = ?23
                WHERE id = ?1
                  AND storage_id = ?2
                  AND vault_id = ?3
                  AND path = ?4
                  AND name = ?5
                  AND type_id = ?6
                  AND payload_enc = ?7
                  AND checksum = ?8
                  AND cache_key_fp IS ?9
                  AND version = ?10
                  AND deleted_at IS ?11
                  AND updated_at = ?12
                  AND sync_status = ?13
                "#,
                proof.id,
                scope.storage_id,
                scope.vault_id,
                proof.path.as_str(),
                proof.name.as_str(),
                proof.type_id.as_str(),
                &proof.payload_enc,
                proof.checksum.as_str(),
                proof.cache_key_fp.as_deref(),
                proof.version,
                proof.deleted_at,
                proof.updated_at,
                proof.sync_status.as_i32(),
                item.path.as_str(),
                item.name.as_str(),
                item.type_id.as_str(),
                &item.payload_enc,
                item.checksum.as_str(),
                item.cache_key_fp.as_deref(),
                item.version,
                item.deleted_at,
                item.updated_at,
                item.sync_status.as_i32()
            )
            .execute(&mut **tx)
            .await
            .map_err(LocalSyncError::Database)?;
            if result.rows_affected() != 1 {
                return Err(LocalSyncError::StaleItem {
                    item_id: expected_item_id,
                });
            }
        }
    }
    Ok(())
}

async fn delete_pending_exact(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    proof: &LocalPendingProof,
) -> Result<(), LocalSyncError> {
    let result = query!(
        r#"
        DELETE FROM pending_changes
        WHERE id = ?1
          AND storage_id = ?2
          AND vault_id = ?3
          AND item_id = ?4
          AND operation = ?5
          AND payload_enc IS ?6
          AND checksum IS ?7
          AND path IS ?8
          AND name IS ?9
          AND type_id IS ?10
          AND base_seq IS ?11
          AND created_at = ?12
        "#,
        proof.id,
        scope.storage_id,
        scope.vault_id,
        proof.item_id,
        proof.operation.as_i32(),
        proof.payload_enc.as_deref(),
        proof.checksum.as_deref(),
        proof.path.as_deref(),
        proof.name.as_deref(),
        proof.type_id.as_deref(),
        proof.base_seq,
        proof.created_at
    )
    .execute(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if result.rows_affected() != 1 {
        return Err(LocalSyncError::StalePending {
            pending_id: proof.id,
        });
    }
    Ok(())
}

async fn replace_history(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    change: &PullChange,
) -> Result<(), LocalSyncError> {
    ensure_history_identifiers_bounded(tx).await?;
    let corrupt_filter = query!(
        r#"
        SELECT 1
        FROM item_history
        WHERE storage_id = ?1 AND vault_id = ?2 AND item_id = ?3
          AND CASE
            WHEN typeof(source) != 'integer' THEN 1
            WHEN source NOT IN (1, 2, 3) THEN 1
            WHEN typeof(sync_status) != 'integer' THEN 1
            WHEN sync_status NOT IN (1, 2, 3) THEN 1
            ELSE 0
          END
        LIMIT 1
        "#,
        scope.storage_id,
        scope.vault_id,
        change.item.id
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if corrupt_filter.is_some() {
        return invalid("local history authority fields are corrupt");
    }
    query!(
        r#"
        DELETE FROM item_history
        WHERE storage_id = ?1 AND vault_id = ?2 AND item_id = ?3
          AND source = ?4 AND sync_status = ?5
        "#,
        scope.storage_id,
        scope.vault_id,
        change.item.id,
        HistorySource::Server.as_i32(),
        HistorySyncStatus::Confirmed.as_i32()
    )
    .execute(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;

    for entry in &change.history {
        query!(
            r#"
            INSERT INTO item_history (
                id, storage_id, vault_id, item_id, payload_enc, checksum, version,
                change_type, changed_by_email, changed_by_name, changed_by_device_id,
                changed_by_device_name, source, sync_status, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            "#,
            entry.id,
            entry.storage_id,
            entry.vault_id,
            entry.item_id,
            &entry.payload_enc,
            entry.checksum.as_str(),
            entry.version,
            entry.change_type.as_i32(),
            entry.changed_by_email.as_str(),
            entry.changed_by_name.as_deref(),
            entry.changed_by_device_id,
            entry.changed_by_device_name.as_deref(),
            entry.source.as_i32(),
            entry.sync_status.as_i32(),
            entry.created_at
        )
        .execute(&mut **tx)
        .await
        .map_err(LocalSyncError::Database)?;
    }
    Ok(())
}

async fn ensure_history_identifiers_bounded(
    tx: &mut Transaction<'static, Sqlite>,
) -> Result<(), LocalSyncError> {
    let corrupt = query!(
        r#"
        SELECT 1
        FROM item_history
        WHERE CASE
            WHEN typeof(id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(id) NOT IN (16, 36) THEN 1
            WHEN typeof(storage_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(storage_id) NOT IN (16, 36) THEN 1
            WHEN typeof(vault_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(vault_id) NOT IN (16, 36) THEN 1
            WHEN typeof(item_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(item_id) NOT IN (16, 36) THEN 1
            ELSE 0
        END
        LIMIT 1
        "#
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if corrupt.is_some() {
        return invalid("local history identifiers are corrupt");
    }
    Ok(())
}

async fn publish_checkpoint(
    tx: &mut Transaction<'static, Sqlite>,
    page: &PullPage,
) -> Result<(), LocalSyncError> {
    let result = query!(
        r#"
        INSERT INTO sync_cursors (storage_id, vault_id, cursor, last_sync_at, last_seq)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(storage_id, vault_id) DO UPDATE SET
            cursor = excluded.cursor,
            last_sync_at = excluded.last_sync_at,
            last_seq = excluded.last_seq
        WHERE sync_cursors.cursor IS ?6
          AND sync_cursors.last_seq IS ?7
        "#,
        page.scope.storage_id,
        page.scope.vault_id,
        page.next_cursor.as_str(),
        page.committed_at,
        page.next_last_seq,
        page.expected_cursor.as_deref(),
        page.expected_last_seq
    )
    .execute(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if result.rows_affected() != 1 {
        return Err(LocalSyncError::StaleCursor { scope: page.scope });
    }
    Ok(())
}

fn validate_push_outcome(
    scope: LocalSyncScope,
    outcome: &PushOutcome,
) -> Result<(), LocalSyncError> {
    validate_scope(scope)?;
    match &outcome.kind {
        PushOutcomeKind::Applied {
            pending,
            expected_item,
            item,
        } => {
            validate_pending(pending, scope)?;
            validate_expectation(expected_item, scope, pending.item_id)?;
            validate_item(item, scope)?;
            if pending.item_id != item.id {
                return invalid("applied item does not match its pending provenance");
            }
            let LocalItemExpectation::Exact(proof) = expected_item else {
                return invalid("applied push outcome requires an exact existing item");
            };
            validate_applied_server_version(pending, item)?;
            validate_applied_binding(pending, proof, item)?;
            validate_remote_item_status(item)
        }
        PushOutcomeKind::Conflict => invalid("conflicted push batch is fail-closed"),
    }
}

fn validate_pull_change(scope: LocalSyncScope, change: &PullChange) -> Result<(), LocalSyncError> {
    validate_scope(scope)?;
    validate_expectation(&change.expected_item, scope, change.item.id)?;
    validate_item(&change.item, scope)?;
    validate_remote_item_status(&change.item)?;
    if let LocalItemExpectation::Exact(proof) = &change.expected_item {
        if proof.sync_status != SyncStatus::Synced {
            return invalid("pull may overwrite only an exact clean synced item");
        }
        if change.item.version <= proof.version {
            return invalid("pulled item version must advance monotonically");
        }
    }
    if change.history.len() > MAX_HISTORY_PER_ITEM {
        return invalid("item history count exceeds the supported range");
    }
    let mut ids = HashSet::with_capacity(change.history.len());
    let mut versions = HashSet::with_capacity(change.history.len());
    for entry in &change.history {
        validate_history(entry, scope, change.item.id)?;
        if !ids.insert(entry.id) {
            return invalid("pull item contains a duplicate history id");
        }
        if !versions.insert(entry.version) {
            return invalid("item history contains a duplicate version");
        }
    }
    Ok(())
}

fn validate_push(commit: &PushCommit) -> Result<(), LocalSyncError> {
    validate_scope(commit.scope)?;
    validate_cursors(commit.expected_cursor.as_deref(), &commit.server_head_hint)?;
    validate_last_seq(
        commit.expected_last_seq,
        "expected last sequence is invalid",
    )?;
    if commit.outcomes.is_empty() || commit.outcomes.len() > MAX_PUSH_BATCH_ITEMS {
        return invalid("push outcome count is outside the supported range");
    }

    let mut pending_ids = HashSet::with_capacity(commit.outcomes.len());
    let mut canonical_item_ids = HashSet::with_capacity(commit.outcomes.len());
    let mut projection_bytes = 0usize;
    for outcome in &commit.outcomes {
        validate_push_outcome(commit.scope, outcome)?;
        let pending = match &outcome.kind {
            PushOutcomeKind::Applied { pending, .. } => pending,
            PushOutcomeKind::Conflict => return invalid("conflicted push batch is fail-closed"),
        };
        validate_pending(pending, commit.scope)?;
        if !pending_ids.insert(pending.id) {
            return invalid("push contains a duplicate pending proof");
        }
        if !canonical_item_ids.insert(pending.item_id) {
            return invalid("push contains a duplicate item outcome");
        }
        if let Some(payload) = &pending.payload_enc {
            projection_bytes = add_projection_bytes(projection_bytes, payload.len())?;
        }

        let PushOutcomeKind::Applied { item, .. } = &outcome.kind else {
            return invalid("conflicted push batch is fail-closed");
        };
        projection_bytes = add_projection_bytes(projection_bytes, item.payload_enc.len())?;
    }
    Ok(())
}

fn validate_pull(page: &PullPage) -> Result<(), LocalSyncError> {
    validate_scope(page.scope)?;
    validate_cache_key_fingerprint(
        &page.expected_vault_cache_key_fp,
        "pull page cache-key fingerprint is not canonical",
    )?;
    validate_cursors(page.expected_cursor.as_deref(), &page.next_cursor)?;
    validate_last_seq(page.expected_last_seq, "expected last sequence is invalid")?;
    validate_last_seq(page.next_last_seq, "next last sequence is invalid")?;
    if page.expected_last_seq.is_some() && page.next_last_seq.is_none() {
        return invalid("pull page cannot clear the last sequence");
    }
    if let (Some(expected), Some(next)) = (page.expected_last_seq, page.next_last_seq) {
        if next < expected {
            return invalid("pull page last sequence must not move backwards");
        }
    }
    if page.changes.len() > MAX_PULL_PAGE_ITEMS {
        return invalid("pull change count exceeds the supported range");
    }

    let mut item_ids = HashSet::with_capacity(page.changes.len());
    let mut history_ids = HashSet::new();
    let mut history_count = 0usize;
    let mut projection_bytes = 0usize;
    for change in &page.changes {
        validate_pull_change(page.scope, change)?;
        if change.item.cache_key_fp.as_deref() != Some(page.expected_vault_cache_key_fp.as_str()) {
            return invalid("pulled item cache-key fingerprint does not match its vault proof");
        }
        if !item_ids.insert(change.item.id) {
            return invalid("pull page contains a duplicate item");
        }
        if change.history.len() > MAX_HISTORY_PER_ITEM {
            return invalid("item history count exceeds the supported range");
        }
        history_count = history_count
            .checked_add(change.history.len())
            .ok_or_else(|| LocalSyncError::InvalidPlan {
                reason: "pull history count overflowed",
            })?;
        if history_count > MAX_HISTORY_PER_PAGE {
            return invalid("pull history count exceeds the supported range");
        }
        projection_bytes = add_projection_bytes(projection_bytes, change.item.payload_enc.len())?;

        let mut versions = HashSet::with_capacity(change.history.len());
        for entry in &change.history {
            validate_history(entry, page.scope, change.item.id)?;
            if !history_ids.insert(entry.id) {
                return invalid("pull page contains a duplicate history id");
            }
            if !versions.insert(entry.version) {
                return invalid("item history contains a duplicate version");
            }
            projection_bytes = add_projection_bytes(projection_bytes, entry.payload_enc.len())?;
        }
    }
    Ok(())
}

fn validate_reset(reset: &ResetProjection) -> Result<(), LocalSyncError> {
    validate_storage_proof(&reset.expected_storage)?;
    if reset.storage_id != reset.expected_storage.id {
        return invalid("storage proof id does not match reset scope");
    }
    if let Some(storage) = &reset.replacement_storage {
        validate_storage(storage)?;
        if storage.id != reset.storage_id {
            return invalid("replacement storage id does not match reset scope");
        }
    }
    Ok(())
}

pub(crate) fn validate_storage_proof(proof: &LocalStorageProof) -> Result<(), LocalSyncError> {
    if proof.id.is_nil() || proof.kind != StorageKind::Remote {
        return invalid("storage proof must identify a non-nil remote storage");
    }
    validate_required_bounded(
        &proof.name,
        MAX_DISPLAY_NAME_BYTES,
        "storage proof name is outside the supported range",
    )?;
    validate_optional_bounded(
        proof.server_url.as_deref(),
        MAX_SERVER_URL_BYTES,
        "storage proof server URL is outside the supported range",
    )?;
    if proof.server_url.is_none() {
        return invalid("remote storage proof requires a server URL");
    }
    validate_optional_bounded(
        proof.server_name.as_deref(),
        MAX_SERVER_METADATA_BYTES,
        "storage proof server name is outside the supported range",
    )?;
    validate_optional_bounded(
        proof.server_fingerprint.as_deref(),
        MAX_SERVER_METADATA_BYTES,
        "storage proof fingerprint is outside the supported range",
    )?;
    validate_optional_bounded(
        proof.account_subject.as_deref(),
        MAX_SERVER_METADATA_BYTES,
        "storage proof account subject is outside the supported range",
    )
}

fn validate_scope(scope: LocalSyncScope) -> Result<(), LocalSyncError> {
    if scope.storage_id.is_nil() || scope.vault_id.is_nil() {
        return invalid("sync scope ids must be non-nil");
    }
    Ok(())
}

fn validate_cursors(expected: Option<&str>, next: &str) -> Result<(), LocalSyncError> {
    validate_optional_bounded(
        expected,
        MAX_CURSOR_BYTES,
        "expected cursor is outside the supported range",
    )?;
    validate_required_bounded(
        next,
        MAX_CURSOR_BYTES,
        "next cursor is outside the supported range",
    )
}

fn validate_last_seq(value: Option<i64>, reason: &'static str) -> Result<(), LocalSyncError> {
    if value.is_some_and(|sequence| sequence < 1) {
        return invalid(reason);
    }
    Ok(())
}

fn validate_pending(
    proof: &LocalPendingProof,
    scope: LocalSyncScope,
) -> Result<(), LocalSyncError> {
    if proof.storage_id != scope.storage_id || proof.vault_id != scope.vault_id {
        return invalid("pending proof ids do not match the sync scope");
    }
    validate_pending_fields(
        proof.id,
        proof.storage_id,
        proof.vault_id,
        proof.item_id,
        proof.operation,
        proof.payload_enc.as_deref(),
        proof.checksum.as_deref(),
        proof.path.as_deref(),
        proof.name.as_deref(),
        proof.type_id.as_deref(),
        proof.base_seq,
    )
}

fn validate_pending_change(change: &LocalPendingChange) -> Result<(), LocalSyncError> {
    validate_scope(LocalSyncScope {
        storage_id: change.storage_id,
        vault_id: change.vault_id,
    })?;
    validate_pending_fields(
        change.id,
        change.storage_id,
        change.vault_id,
        change.item_id,
        change.operation,
        change.payload_enc.as_deref(),
        change.checksum.as_deref(),
        change.path.as_deref(),
        change.name.as_deref(),
        change.type_id.as_deref(),
        change.base_seq,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_pending_fields(
    id: Uuid,
    storage_id: Uuid,
    vault_id: Uuid,
    item_id: Uuid,
    operation: ChangeType,
    payload_enc: Option<&[u8]>,
    checksum: Option<&str>,
    path: Option<&str>,
    name: Option<&str>,
    type_id: Option<&str>,
    base_seq: Option<i64>,
) -> Result<(), LocalSyncError> {
    if id.is_nil() || storage_id.is_nil() || vault_id.is_nil() || item_id.is_nil() {
        return invalid("pending proof ids must be non-nil");
    }
    if payload_enc.is_some_and(|payload| payload.len() > MAX_ITEM_CIPHERTEXT_BYTES) {
        return invalid("pending payload exceeds the supported size");
    }
    validate_optional_bounded(
        checksum,
        MAX_CHECKSUM_BYTES,
        "pending checksum is outside the supported range",
    )?;
    if let Some(checksum) = checksum {
        validate_checksum(checksum, "pending checksum is not canonical")?;
    }
    if let Some(path) = path {
        validate_path(path)?;
    }
    validate_optional_bounded(
        name,
        MAX_ITEM_NAME_LEN,
        "pending name is outside the supported range",
    )?;
    validate_optional_bounded(
        type_id,
        MAX_TYPE_ID_BYTES,
        "pending item type is outside the supported range",
    )?;
    if let (Some(path), Some(name)) = (path, name) {
        if path.rsplit('/').next() != Some(name) {
            return invalid("pending name must match its path basename");
        }
    }
    if base_seq.is_some_and(|version| version < 1) {
        return invalid("pending base version must be positive");
    }
    match operation {
        ChangeType::Create => {
            if payload_enc.is_none()
                || checksum.is_none()
                || path.is_none()
                || name.is_none()
                || type_id.is_none()
                || base_seq.is_some()
            {
                return invalid("pending create proof has invalid provenance fields");
            }
        }
        ChangeType::Update | ChangeType::Restore => {
            if payload_enc.is_none()
                || checksum.is_none()
                || path.is_none()
                || name.is_none()
                || type_id.is_none()
                || base_seq.is_none()
            {
                return invalid("pending mutation proof has invalid provenance fields");
            }
        }
        ChangeType::Delete => {
            if payload_enc.is_some()
                || checksum.is_some()
                || path.is_none()
                || name.is_none()
                || type_id.is_none()
                || base_seq.is_none()
            {
                return invalid("pending delete proof has invalid provenance fields");
            }
        }
    }
    Ok(())
}

fn validate_expectation(
    expectation: &LocalItemExpectation,
    scope: LocalSyncScope,
    item_id: Uuid,
) -> Result<(), LocalSyncError> {
    if let LocalItemExpectation::Exact(proof) = expectation {
        if proof.id != item_id
            || proof.storage_id != scope.storage_id
            || proof.vault_id != scope.vault_id
        {
            return invalid("item proof ids do not match the expected scope");
        }
        validate_path(&proof.path)?;
        validate_required_bounded(
            &proof.name,
            MAX_ITEM_NAME_LEN,
            "item proof name is outside the supported range",
        )?;
        validate_required_bounded(
            &proof.type_id,
            MAX_TYPE_ID_BYTES,
            "item proof type is outside the supported range",
        )?;
        if proof.payload_enc.len() > MAX_ITEM_CIPHERTEXT_BYTES {
            return invalid("item proof payload exceeds the supported size");
        }
        validate_checksum(&proof.checksum, "item proof checksum is not canonical")?;
        if let Some(fingerprint) = proof.cache_key_fp.as_deref() {
            validate_cache_key_fingerprint(
                fingerprint,
                "item proof cache-key fingerprint is not canonical",
            )?;
        }
        if proof.version < 1 {
            return invalid("item proof version must be positive");
        }
    }
    Ok(())
}

fn validate_item(item: &LocalItem, scope: LocalSyncScope) -> Result<(), LocalSyncError> {
    if item.id.is_nil() || item.storage_id != scope.storage_id || item.vault_id != scope.vault_id {
        return invalid("item ids do not match the sync scope");
    }
    validate_path(&item.path)?;
    validate_required_bounded(
        &item.name,
        MAX_ITEM_NAME_LEN,
        "item name is outside the supported range",
    )?;
    if item.path.rsplit('/').next() != Some(item.name.as_str()) {
        return invalid("item name must match its path basename");
    }
    validate_required_bounded(
        &item.type_id,
        MAX_TYPE_ID_BYTES,
        "item type is outside the supported range",
    )?;
    if item.payload_enc.len() > MAX_ITEM_CIPHERTEXT_BYTES {
        return invalid("item payload exceeds the supported size");
    }
    validate_checksum(&item.checksum, "item checksum is not canonical")?;
    if let Some(fingerprint) = item.cache_key_fp.as_deref() {
        validate_cache_key_fingerprint(fingerprint, "cache-key fingerprint is not canonical")?;
    }
    if item.version < 1 {
        return invalid("item version must be positive");
    }
    Ok(())
}

fn validate_remote_item_status(item: &LocalItem) -> Result<(), LocalSyncError> {
    if item.sync_status == SyncStatus::Synced {
        Ok(())
    } else {
        invalid("remote item projection must use the clean synced status")
    }
}

fn validate_applied_binding(
    pending: &LocalPendingProof,
    proof: &LocalItemProof,
    item: &LocalItem,
) -> Result<(), LocalSyncError> {
    if pending.created_at != proof.updated_at {
        return invalid("pending creation time does not match the local item revision");
    }
    match pending.operation {
        ChangeType::Delete => {
            let (Some(path), Some(name), Some(type_id), Some(base_seq)) = (
                pending.path.as_deref(),
                pending.name.as_deref(),
                pending.type_id.as_deref(),
                pending.base_seq,
            ) else {
                return invalid("pending delete proof lacks exact item metadata");
            };
            if path != proof.path
                || name != proof.name
                || type_id != proof.type_id
                || proof.sync_status != SyncStatus::Tombstone
                || proof.deleted_at.is_none()
                || base_seq >= proof.version
            {
                return invalid("pending delete proof does not match the tombstoned item");
            }
            if item.path.as_str() != proof.path.as_str()
                || item.name.as_str() != proof.name.as_str()
                || item.type_id.as_str() != proof.type_id.as_str()
                || item.payload_enc.as_slice() != proof.payload_enc.as_slice()
                || item.checksum.as_str() != proof.checksum.as_str()
                || item.cache_key_fp.as_deref() != proof.cache_key_fp.as_deref()
                || item.sync_status != SyncStatus::Synced
                || item.deleted_at.is_none()
            {
                return invalid("applied delete projection changed canonical item content");
            }
        }
        ChangeType::Create | ChangeType::Update | ChangeType::Restore => {
            let (Some(payload), Some(checksum), Some(path), Some(name), Some(type_id)) = (
                pending.payload_enc.as_ref(),
                pending.checksum.as_ref(),
                pending.path.as_ref(),
                pending.name.as_ref(),
                pending.type_id.as_ref(),
            ) else {
                return invalid("applied pending proof lacks a complete item projection");
            };
            if proof.sync_status != SyncStatus::Modified
                || proof.deleted_at.is_some()
                || proof.path.as_str() != path.as_str()
                || proof.name.as_str() != name.as_str()
                || proof.type_id.as_str() != type_id.as_str()
                || proof.payload_enc.as_slice() != payload.as_slice()
                || proof.checksum.as_str() != checksum.as_str()
            {
                return invalid("pending mutation proof does not match the modified item");
            }
            match pending.operation {
                ChangeType::Create if pending.base_seq.is_none() && proof.version >= 1 => {}
                ChangeType::Update | ChangeType::Restore
                    if pending
                        .base_seq
                        .is_some_and(|base_seq| base_seq < proof.version) => {}
                _ => return invalid("pending base sequence does not match the item revision"),
            }
            if item.path.as_str() != proof.path.as_str()
                || item.name.as_str() != name.as_str()
                || item.type_id.as_str() != type_id.as_str()
                || item.payload_enc.as_slice() != payload.as_slice()
                || item.checksum.as_str() != checksum.as_str()
                || item.cache_key_fp.as_deref() != proof.cache_key_fp.as_deref()
                || item.sync_status != SyncStatus::Synced
                || item.deleted_at.is_some()
            {
                return invalid("applied item projection does not match pending provenance");
            }
        }
    }
    Ok(())
}

fn validate_applied_server_version(
    pending: &LocalPendingProof,
    item: &LocalItem,
) -> Result<(), LocalSyncError> {
    match pending.operation {
        ChangeType::Create if item.version >= 1 => Ok(()),
        ChangeType::Create => invalid("applied create version must be positive"),
        ChangeType::Update | ChangeType::Restore | ChangeType::Delete => {
            let Some(base_seq) = pending.base_seq else {
                return invalid("applied mutation lacks a pending base sequence");
            };
            if item.version <= base_seq {
                return invalid("applied version must advance beyond the pending base sequence");
            }
            Ok(())
        }
    }
}

fn validate_history(
    entry: &LocalItemHistory,
    scope: LocalSyncScope,
    item_id: Uuid,
) -> Result<(), LocalSyncError> {
    if entry.id.is_nil()
        || entry.storage_id != scope.storage_id
        || entry.vault_id != scope.vault_id
        || entry.item_id != item_id
    {
        return invalid("history ids do not match the pull item scope");
    }
    if entry.payload_enc.len() > MAX_ITEM_CIPHERTEXT_BYTES {
        return invalid("history payload exceeds the supported size");
    }
    validate_checksum(&entry.checksum, "history checksum is not canonical")?;
    if entry.version < 1 {
        return invalid("history version must be positive");
    }
    validate_required_bounded(
        &entry.changed_by_email,
        MAX_EMAIL_BYTES,
        "history actor email is outside the supported range",
    )?;
    validate_optional_bounded(
        entry.changed_by_name.as_deref(),
        MAX_DISPLAY_NAME_BYTES,
        "history actor name is outside the supported range",
    )?;
    validate_optional_bounded(
        entry.changed_by_device_name.as_deref(),
        MAX_DISPLAY_NAME_BYTES,
        "history device name is outside the supported range",
    )?;
    if entry.changed_by_device_id.is_some_and(|id| id.is_nil()) {
        return invalid("history device id must be non-nil when present");
    }
    if entry.source != HistorySource::Server || entry.sync_status != HistorySyncStatus::Confirmed {
        return invalid("pull history must be a confirmed server projection");
    }
    Ok(())
}

fn validate_storage(storage: &LocalStorage) -> Result<(), LocalSyncError> {
    if storage.id.is_nil() || storage.kind != StorageKind::Remote {
        return invalid("replacement storage must be a non-nil remote storage");
    }
    validate_required_bounded(
        &storage.name,
        MAX_DISPLAY_NAME_BYTES,
        "storage name is outside the supported range",
    )?;
    validate_optional_bounded(
        storage.server_url.as_deref(),
        MAX_SERVER_URL_BYTES,
        "server URL is outside the supported range",
    )?;
    if storage.server_url.is_none() {
        return invalid("remote replacement storage requires a server URL");
    }
    validate_optional_bounded(
        storage.server_name.as_deref(),
        MAX_SERVER_METADATA_BYTES,
        "server name is outside the supported range",
    )?;
    validate_optional_bounded(
        storage.server_fingerprint.as_deref(),
        MAX_SERVER_METADATA_BYTES,
        "server fingerprint is outside the supported range",
    )?;
    validate_optional_bounded(
        storage.account_subject.as_deref(),
        MAX_SERVER_METADATA_BYTES,
        "account subject is outside the supported range",
    )
}

fn validate_path(path: &str) -> Result<(), LocalSyncError> {
    validate_required_bounded(
        path,
        MAX_ITEM_PATH_LEN,
        "item path is outside the supported range",
    )?;
    let mut segments = 0usize;
    for segment in path.split('/') {
        segments += 1;
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.starts_with('.')
            || segment.len() > MAX_ITEM_NAME_LEN
        {
            return invalid("item path contains an invalid segment");
        }
    }
    if segments > MAX_ITEM_PATH_SEGMENTS {
        return invalid("item path has too many segments");
    }
    Ok(())
}

fn validate_required_bounded(
    value: &str,
    max: usize,
    reason: &'static str,
) -> Result<(), LocalSyncError> {
    if value.is_empty() || value.len() > max {
        return invalid(reason);
    }
    Ok(())
}

fn validate_checksum(checksum: &str, reason: &'static str) -> Result<(), LocalSyncError> {
    if checksum.len() != 64
        || !checksum
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(reason);
    }
    Ok(())
}

fn validate_cache_key_fingerprint(
    fingerprint: &str,
    reason: &'static str,
) -> Result<(), LocalSyncError> {
    if fingerprint.len() != CACHE_KEY_FINGERPRINT_BYTES
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(reason);
    }
    Ok(())
}

fn validate_optional_bounded(
    value: Option<&str>,
    max: usize,
    reason: &'static str,
) -> Result<(), LocalSyncError> {
    if value.is_some_and(|value| value.is_empty() || value.len() > max) {
        return invalid(reason);
    }
    Ok(())
}

fn add_projection_bytes(current: usize, bytes: usize) -> Result<usize, LocalSyncError> {
    let total = current
        .checked_add(bytes)
        .ok_or(LocalSyncError::InvalidPlan {
            reason: "projection byte count overflowed",
        })?;
    if total > MAX_PROJECTION_BYTES {
        return invalid("projection payloads exceed the supported total size");
    }
    Ok(total)
}

fn invalid<T>(reason: &'static str) -> Result<T, LocalSyncError> {
    Err(LocalSyncError::InvalidPlan { reason })
}
