use super::*;

pub struct SyncCheckpoint {
    pub(super) cursor: Option<SyncCursor>,
    pub(super) last_seq: Option<SyncSeq>,
    pub(super) pending: Vec<PendingProof>,
}

impl fmt::Debug for SyncCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncCheckpoint")
            .field("cursor", &self.cursor)
            .field("last_seq", &self.last_seq)
            .field("pending_count", &self.pending.len())
            .finish()
    }
}

impl SyncCheckpoint {
    pub fn new(
        cursor: Option<SyncCursor>,
        last_seq: Option<SyncSeq>,
        pending: Vec<PendingProof>,
    ) -> Result<Self, SyncModelError> {
        if pending.len() > MAX_PENDING_CHANGES {
            return Err(SyncModelError::PendingTooLarge);
        }
        let mut pending_ids = HashSet::with_capacity(pending.len());
        let mut item_ids = HashSet::with_capacity(pending.len());
        for proof in &pending {
            if !pending_ids.insert(proof.pending_id()) || !item_ids.insert(proof.item_id()) {
                return Err(SyncModelError::DuplicateIdentifier);
            }
        }
        Ok(Self {
            cursor,
            last_seq,
            pending,
        })
    }

    #[must_use]
    pub fn cursor(&self) -> Option<&SyncCursor> {
        self.cursor.as_ref()
    }

    #[must_use]
    pub fn last_seq(&self) -> Option<SyncSeq> {
        self.last_seq
    }

    #[must_use]
    pub fn pending(&self) -> &[PendingProof] {
        &self.pending
    }

    #[must_use]
    pub(crate) fn into_parts(self) -> (Option<SyncCursor>, Option<SyncSeq>, Vec<PendingProof>) {
        (self.cursor, self.last_seq, self.pending)
    }
}

pub struct HistoryProjection {
    pub(super) history_id: Uuid,
    pub(super) scope: SyncScope,
    pub(super) item_id: Uuid,
    pub(super) payload_enc: Vec<u8>,
    pub(super) checksum: ContentChecksum,
    pub(super) version: SyncSeq,
    pub(super) change_type: ChangeType,
    pub(super) changed_by_email: String,
    pub(super) changed_by_name: Option<String>,
    pub(super) created_at: DateTime<Utc>,
    pub(super) authority: HistoryAuthority,
}

impl HistoryProjection {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validated(
        history_id: Uuid,
        scope: SyncScope,
        item_id: Uuid,
        payload_enc: Vec<u8>,
        checksum: ContentChecksum,
        version: SyncSeq,
        change_type: ChangeType,
        changed_by_email: String,
        changed_by_name: Option<String>,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            history_id,
            scope,
            item_id,
            payload_enc,
            checksum,
            version,
            change_type,
            changed_by_email,
            changed_by_name,
            created_at,
            authority: HistoryAuthority::ServerConfirmed,
        }
    }

    #[must_use]
    pub fn history_id(&self) -> Uuid {
        self.history_id
    }

    #[must_use]
    pub fn scope(&self) -> SyncScope {
        self.scope
    }

    #[must_use]
    pub fn item_id(&self) -> Uuid {
        self.item_id
    }

    #[must_use]
    pub fn payload_enc(&self) -> &[u8] {
        &self.payload_enc
    }

    #[must_use]
    pub fn checksum(&self) -> ContentChecksum {
        self.checksum
    }

    #[must_use]
    pub fn version(&self) -> SyncSeq {
        self.version
    }

    #[must_use]
    pub fn change_type(&self) -> ChangeType {
        self.change_type
    }

    #[must_use]
    pub fn changed_by_email(&self) -> &str {
        &self.changed_by_email
    }

    #[must_use]
    pub fn changed_by_name(&self) -> Option<&str> {
        self.changed_by_name.as_deref()
    }

    #[must_use]
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    #[must_use]
    pub fn authority(&self) -> HistoryAuthority {
        self.authority
    }
}

impl fmt::Debug for HistoryProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HistoryProjection")
            .field("history_id", &self.history_id)
            .field("scope", &self.scope)
            .field("item_id", &self.item_id)
            .field("payload_bytes", &self.payload_enc.len())
            .field("checksum", &"<redacted>")
            .field("version", &self.version)
            .field("change_type", &self.change_type)
            .field("created_at", &self.created_at)
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

/// One item update and its exact pre-call local proof.
pub struct PullCommitChange {
    pub(super) expected: ItemState,
    pub(super) item: ItemProjection,
    pub(super) history: Vec<HistoryProjection>,
}

impl PullCommitChange {
    #[must_use]
    pub(crate) fn validated(
        expected: ItemState,
        item: ItemProjection,
        history: Vec<HistoryProjection>,
    ) -> Self {
        Self {
            expected,
            item,
            history,
        }
    }

    #[must_use]
    pub fn expected(&self) -> &ItemState {
        &self.expected
    }

    #[must_use]
    pub fn item(&self) -> &ItemProjection {
        &self.item
    }

    #[must_use]
    pub fn history(&self) -> &[HistoryProjection] {
        &self.history
    }
}

impl fmt::Debug for PullCommitChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PullCommitChange")
            .field("expected", &self.expected)
            .field("item", &self.item)
            .field("history_entries", &self.history.len())
            .finish()
    }
}

#[derive(Debug)]
pub struct PullPageCommit {
    pub(super) scope: SyncScope,
    pub(super) cache_key_fingerprint: String,
    pub(super) expected_cursor: Option<SyncCursor>,
    pub(super) expected_last_seq: Option<SyncSeq>,
    pub(super) next_cursor: SyncCursor,
    pub(super) next_last_seq: Option<SyncSeq>,
    pub(super) committed_at: DateTime<Utc>,
    pub(super) changes: Vec<PullCommitChange>,
}

impl PullPageCommit {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validated(
        scope: SyncScope,
        cache_key_fingerprint: String,
        expected_cursor: Option<SyncCursor>,
        expected_last_seq: Option<SyncSeq>,
        next_cursor: SyncCursor,
        next_last_seq: Option<SyncSeq>,
        committed_at: DateTime<Utc>,
        changes: Vec<PullCommitChange>,
    ) -> Result<Self, SyncModelError> {
        validate_cache_key_fingerprint(&cache_key_fingerprint)?;
        if changes
            .iter()
            .any(|change| change.item().cache_key_fingerprint() != cache_key_fingerprint)
        {
            return Err(SyncModelError::InvalidText);
        }
        Ok(Self {
            scope,
            cache_key_fingerprint,
            expected_cursor,
            expected_last_seq,
            next_cursor,
            next_last_seq,
            committed_at,
            changes,
        })
    }

    #[must_use]
    pub fn scope(&self) -> SyncScope {
        self.scope
    }

    /// Fingerprint of the exact payload key used to validate or encrypt this
    /// page. Persistence adapters must CAS the durable vault binding against
    /// this value in the same transaction, including for empty pages.
    #[must_use]
    pub fn cache_key_fingerprint(&self) -> &str {
        &self.cache_key_fingerprint
    }

    #[must_use]
    pub fn expected_cursor(&self) -> Option<&SyncCursor> {
        self.expected_cursor.as_ref()
    }

    #[must_use]
    pub fn expected_last_seq(&self) -> Option<SyncSeq> {
        self.expected_last_seq
    }

    #[must_use]
    pub fn next_cursor(&self) -> &SyncCursor {
        &self.next_cursor
    }

    #[must_use]
    pub fn next_last_seq(&self) -> Option<SyncSeq> {
        self.next_last_seq
    }

    #[must_use]
    pub fn committed_at(&self) -> DateTime<Utc> {
        self.committed_at
    }

    #[must_use]
    pub fn changes(&self) -> &[PullCommitChange] {
        &self.changes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullCommitReceipt {
    pub(super) items: usize,
    pub(super) history_entries: usize,
    pub(super) cursor: SyncCursor,
    pub(super) last_seq: Option<SyncSeq>,
}

impl PullCommitReceipt {
    pub fn new(
        items: usize,
        history_entries: usize,
        cursor: SyncCursor,
        last_seq: Option<SyncSeq>,
    ) -> Result<Self, SyncModelError> {
        if items > PULL_PAGE_LIMIT || history_entries > PULL_PAGE_LIMIT * MAX_HISTORY_PER_ITEM {
            return Err(SyncModelError::PageTooLarge);
        }
        Ok(Self {
            items,
            history_entries,
            cursor,
            last_seq,
        })
    }

    #[must_use]
    pub fn items(&self) -> usize {
        self.items
    }

    #[must_use]
    pub fn history_entries(&self) -> usize {
        self.history_entries
    }

    #[must_use]
    pub fn cursor(&self) -> &SyncCursor {
        &self.cursor
    }

    #[must_use]
    pub fn last_seq(&self) -> Option<SyncSeq> {
        self.last_seq
    }
}

/// Adapter-generated personal-vault key publication bound to one empty remote envelope.
pub struct GeneratedVaultKeyCommit {
    pub(super) scope: SyncScope,
    pub(super) expected_remote_envelope: Vec<u8>,
    pub(super) published_envelope: Vec<u8>,
    pub(super) generated_key: VaultPayloadKey,
}

impl GeneratedVaultKeyCommit {
    pub fn new(
        scope: SyncScope,
        expected_remote_envelope: Vec<u8>,
        published_envelope: Vec<u8>,
        generated_key: VaultPayloadKey,
    ) -> Result<Self, SyncModelError> {
        if expected_remote_envelope.len() > 64 * 1_024
            || published_envelope.is_empty()
            || published_envelope.len() > 64 * 1_024
        {
            return Err(SyncModelError::PayloadTooLarge);
        }
        Ok(Self {
            scope,
            expected_remote_envelope,
            published_envelope,
            generated_key,
        })
    }

    #[must_use]
    pub fn scope(&self) -> SyncScope {
        self.scope
    }

    #[must_use]
    pub fn expected_remote_envelope(&self) -> &[u8] {
        &self.expected_remote_envelope
    }

    #[must_use]
    pub fn published_envelope(&self) -> &[u8] {
        &self.published_envelope
    }

    #[must_use]
    pub fn generated_key(&self) -> &VaultPayloadKey {
        &self.generated_key
    }
}

impl fmt::Debug for GeneratedVaultKeyCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedVaultKeyCommit")
            .field("scope", &self.scope)
            .field(
                "expected_remote_envelope_bytes",
                &self.expected_remote_envelope.len(),
            )
            .field("published_envelope_bytes", &self.published_envelope.len())
            .field("generated_key", &"<redacted>")
            .finish()
    }
}

/// One server-confirmed push result and the exact local inputs that produced it.
pub struct PushCommitChange {
    pub(super) pending: PendingProof,
    pub(super) expected: ItemState,
    pub(super) item: ItemProjection,
}

impl PushCommitChange {
    pub(crate) fn validated(
        pending: PendingProof,
        expected: ItemState,
        item: ItemProjection,
    ) -> Result<Self, SyncModelError> {
        if pending.scope() != item.scope()
            || pending.item_id() != item.item_id()
            || expected.item_id() != item.item_id()
        {
            return Err(SyncModelError::InvalidIdentifier);
        }
        match expected.pending() {
            PendingExpectation::Exact(proof)
                if proof.pending_id() == pending.pending_id()
                    && proof.item_id() == pending.item_id() => {}
            _ => return Err(SyncModelError::InvalidPendingProof),
        }
        // A create pushes a row with no prior local projection; every other
        // operation rewrites an existing exact projection.
        let creates_item = expected.exact_proof().is_none();
        if creates_item != matches!(pending.operation(), ChangeType::Create) {
            return Err(SyncModelError::InvalidPendingProof);
        }
        Ok(Self {
            pending,
            expected,
            item,
        })
    }

    #[must_use]
    pub fn pending(&self) -> &PendingProof {
        &self.pending
    }

    #[must_use]
    pub fn expected(&self) -> &ItemState {
        &self.expected
    }

    #[must_use]
    pub fn item(&self) -> &ItemProjection {
        &self.item
    }
}

impl fmt::Debug for PushCommitChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PushCommitChange")
            .field("pending_id", &self.pending.pending_id())
            .field("item_id", &self.item.item_id())
            .finish_non_exhaustive()
    }
}

/// Atomic push commit. The server head is an observation, never a pull cursor.
#[derive(Debug)]
pub struct PushCommitPlan {
    pub(super) scope: SyncScope,
    pub(super) expected_cursor: Option<SyncCursor>,
    pub(super) expected_last_seq: Option<SyncSeq>,
    pub(super) server_head_hint: SyncCursor,
    pub(super) changes: Vec<PushCommitChange>,
}

impl PushCommitPlan {
    pub fn new(
        scope: SyncScope,
        expected_cursor: Option<SyncCursor>,
        expected_last_seq: Option<SyncSeq>,
        server_head_hint: SyncCursor,
        changes: Vec<PushCommitChange>,
    ) -> Result<Self, SyncModelError> {
        if changes.is_empty() || changes.len() > MAX_PENDING_CHANGES {
            return Err(SyncModelError::PendingTooLarge);
        }
        let mut pending_ids = HashSet::with_capacity(changes.len());
        let mut item_ids = HashSet::with_capacity(changes.len());
        for change in &changes {
            if change.item().scope() != scope
                || !pending_ids.insert(change.pending().pending_id())
                || !item_ids.insert(change.item().item_id())
            {
                return Err(SyncModelError::DuplicateIdentifier);
            }
        }
        Ok(Self {
            scope,
            expected_cursor,
            expected_last_seq,
            server_head_hint,
            changes,
        })
    }

    #[must_use]
    pub fn scope(&self) -> SyncScope {
        self.scope
    }

    #[must_use]
    pub fn expected_cursor(&self) -> Option<&SyncCursor> {
        self.expected_cursor.as_ref()
    }

    #[must_use]
    pub fn expected_last_seq(&self) -> Option<SyncSeq> {
        self.expected_last_seq
    }

    #[must_use]
    pub fn server_head_hint(&self) -> &SyncCursor {
        &self.server_head_hint
    }

    #[must_use]
    pub fn changes(&self) -> &[PushCommitChange] {
        &self.changes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushCommitReceipt {
    pub(super) pending_deleted: usize,
    pub(super) server_head_hint: SyncCursor,
}

impl PushCommitReceipt {
    #[must_use]
    pub fn new(pending_deleted: usize, server_head_hint: SyncCursor) -> Self {
        Self {
            pending_deleted,
            server_head_hint,
        }
    }

    #[must_use]
    pub fn pending_deleted(&self) -> usize {
        self.pending_deleted
    }

    #[must_use]
    pub fn server_head_hint(&self) -> &SyncCursor {
        &self.server_head_hint
    }
}

pub struct ProjectionReset {
    pub(super) expected_binding: StorageBindingProof,
}

impl ProjectionReset {
    #[must_use]
    pub fn new(expected_binding: StorageBindingProof) -> Self {
        Self { expected_binding }
    }

    #[must_use]
    pub fn storage_id(&self) -> Uuid {
        self.expected_binding.storage_id()
    }

    #[must_use]
    pub fn expected_binding(&self) -> &StorageBindingProof {
        &self.expected_binding
    }
}

impl fmt::Debug for ProjectionReset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectionReset")
            .field("expected_binding", &self.expected_binding)
            .finish()
    }
}
