use super::*;

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
    pub(super) repository_fingerprint: [u8; 32],
    pub(super) stable_target_fingerprint: [u8; 32],
    pub(super) config_revision: u64,
    pub(super) config_content_fingerprint: [u8; 32],
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
    pub(super) id: Uuid,
    pub(super) storage_id: Uuid,
    pub(super) vault_id: Uuid,
    pub(super) path: String,
    pub(super) name: String,
    pub(super) type_id: String,
    pub(super) payload_enc: Vec<u8>,
    pub(super) checksum: String,
    pub(super) cache_key_fp: Option<String>,
    pub(super) version: i64,
    pub(super) deleted_at: Option<DateTime<Utc>>,
    pub(super) updated_at: DateTime<Utc>,
    pub(super) sync_status: SyncStatus,
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
    pub(super) id: Uuid,
    pub(super) storage_id: Uuid,
    pub(super) vault_id: Uuid,
    pub(super) item_id: Uuid,
    pub(super) operation: ChangeType,
    pub(super) payload_enc: Option<Vec<u8>>,
    pub(super) checksum: Option<String>,
    pub(super) path: Option<String>,
    pub(super) name: Option<String>,
    pub(super) type_id: Option<String>,
    pub(super) base_seq: Option<i64>,
    pub(super) created_at: DateTime<Utc>,
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
    pub(super) kind: PushOutcomeKind,
}

pub(super) enum PushOutcomeKind {
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
    pub(super) scope: LocalSyncScope,
    pub(super) expected_cursor: Option<String>,
    pub(super) expected_last_seq: Option<i64>,
    /// The server head returned by push. This is deliberately a hint and is
    /// never persisted as the local pull cursor: doing so could skip remote
    /// changes committed between the prior pull and this push.
    pub(super) server_head_hint: String,
    pub(super) outcomes: Vec<PushOutcome>,
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
    pub(super) applied: usize,
    pub(super) pending_deleted: usize,
    pub(super) server_head_hint: String,
    pub(super) last_seq: Option<i64>,
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
    pub(super) expected_item: LocalItemExpectation,
    pub(super) item: LocalItem,
    pub(super) history: Vec<LocalItemHistory>,
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
    pub(super) scope: LocalSyncScope,
    pub(super) expected_vault_cache_key_fp: String,
    pub(super) expected_cursor: Option<String>,
    pub(super) expected_last_seq: Option<i64>,
    pub(super) next_cursor: String,
    pub(super) next_last_seq: Option<i64>,
    pub(super) committed_at: DateTime<Utc>,
    pub(super) changes: Vec<PullChange>,
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
    pub(super) items: usize,
    pub(super) history_entries: usize,
    pub(super) cursor: String,
    pub(super) last_seq: Option<i64>,
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
    pub(super) id: Uuid,
    pub(super) kind: StorageKind,
    pub(super) name: String,
    pub(super) server_url: Option<String>,
    pub(super) server_name: Option<String>,
    pub(super) server_fingerprint: Option<String>,
    pub(super) account_subject: Option<String>,
    pub(super) personal_vaults_enabled: bool,
    pub(super) auth_method: Option<AuthMethod>,
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
    pub(super) storage_id: Uuid,
    pub(super) expected_storage: LocalStorageProof,
    pub(super) replacement_storage: Option<LocalStorage>,
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
