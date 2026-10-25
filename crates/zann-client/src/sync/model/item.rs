use super::*;

/// Exact local item projection used as a compare-and-swap proof.
#[derive(Clone, Eq, PartialEq)]
pub struct ItemProjection {
    pub(super) scope: SyncScope,
    pub(super) item_id: Uuid,
    pub(super) path: String,
    pub(super) name: String,
    pub(super) type_id: String,
    pub(super) payload_enc: Vec<u8>,
    pub(super) checksum: ContentChecksum,
    pub(super) cache_key_fingerprint: String,
    pub(super) seq: SyncSeq,
    pub(super) updated_at: DateTime<Utc>,
    pub(super) deleted_at: Option<DateTime<Utc>>,
    pub(super) sync_status: SyncStatus,
}

impl ItemProjection {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validated(
        scope: SyncScope,
        item_id: Uuid,
        path: String,
        name: String,
        type_id: String,
        payload_enc: Vec<u8>,
        checksum: ContentChecksum,
        cache_key_fingerprint: String,
        seq: SyncSeq,
        updated_at: DateTime<Utc>,
        deleted_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            scope,
            item_id,
            path,
            name,
            type_id,
            payload_enc,
            checksum,
            cache_key_fingerprint,
            seq,
            updated_at,
            deleted_at,
            sync_status: SyncStatus::Synced,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: SyncScope,
        item_id: Uuid,
        path: impl Into<String>,
        name: impl Into<String>,
        type_id: impl Into<String>,
        payload_enc: Vec<u8>,
        checksum: ContentChecksum,
        cache_key_fingerprint: impl Into<String>,
        seq: SyncSeq,
        updated_at: DateTime<Utc>,
        deleted_at: Option<DateTime<Utc>>,
    ) -> Result<Self, SyncModelError> {
        let path = path.into();
        let name = name.into();
        let type_id = type_id.into();
        let cache_key_fingerprint = cache_key_fingerprint.into();
        if item_id.is_nil() || payload_enc.len() > MAX_CIPHERTEXT_BYTES {
            return Err(SyncModelError::InvalidIdentifier);
        }
        validate_path(&path)?;
        validate_required(&name, MAX_ITEM_NAME_BYTES)?;
        validate_required(&type_id, MAX_TYPE_ID_BYTES)?;
        if path.rsplit('/').next() != Some(name.as_str()) {
            return Err(SyncModelError::InvalidPath);
        }
        if deleted_at.is_some_and(|deleted| deleted != updated_at) {
            return Err(SyncModelError::InvalidTimestamp);
        }
        validate_cache_key_fingerprint(&cache_key_fingerprint)?;
        Ok(Self::validated(
            scope,
            item_id,
            path,
            name,
            type_id,
            payload_enc,
            checksum,
            cache_key_fingerprint,
            seq,
            updated_at,
            deleted_at,
        ))
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
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn type_id(&self) -> &str {
        &self.type_id
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
    pub fn cache_key_fingerprint(&self) -> &str {
        &self.cache_key_fingerprint
    }

    #[must_use]
    pub fn seq(&self) -> SyncSeq {
        self.seq
    }

    #[must_use]
    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    #[must_use]
    pub fn deleted_at(&self) -> Option<DateTime<Utc>> {
        self.deleted_at
    }

    #[must_use]
    pub fn is_tombstone(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Every authoritative projection produced by pull is locally synced.
    /// A remote delete is represented only by `deleted_at`, never by the
    /// ambiguous local `Tombstone` producer status.
    #[must_use]
    pub fn sync_status(&self) -> SyncStatus {
        self.sync_status
    }
}

impl fmt::Debug for ItemProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ItemProjection")
            .field("scope", &self.scope)
            .field("item_id", &self.item_id)
            .field("metadata", &"<redacted>")
            .field("payload_bytes", &self.payload_enc.len())
            .field("checksum", &"<redacted>")
            .field("cache_key_fingerprint", &"<redacted>")
            .field("seq", &self.seq)
            .field("updated_at", &self.updated_at)
            .field("deleted_at", &self.deleted_at)
            .field("sync_status", &self.sync_status)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ItemProof {
    pub(super) projection: ItemProjection,
    pub(super) sync_status: SyncStatus,
}

impl ItemProof {
    #[must_use]
    pub fn new(projection: ItemProjection, sync_status: SyncStatus) -> Self {
        Self {
            projection,
            sync_status,
        }
    }

    #[must_use]
    pub fn projection(&self) -> &ItemProjection {
        &self.projection
    }

    #[must_use]
    pub fn cache_key_fingerprint(&self) -> &str {
        self.projection.cache_key_fingerprint()
    }

    #[must_use]
    pub fn sync_status(&self) -> SyncStatus {
        self.sync_status
    }
}

impl fmt::Debug for ItemProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ItemProof")
            .field("item_id", &self.projection.item_id)
            .field("seq", &self.projection.seq)
            .field("sync_status", &self.sync_status)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ItemState {
    Absent {
        item_id: Uuid,
        pending: PendingExpectation,
    },
    Exact {
        proof: Box<ItemProof>,
        pending: PendingExpectation,
    },
}

impl ItemState {
    pub fn absent(item_id: Uuid) -> Result<Self, SyncModelError> {
        if item_id.is_nil() {
            return Err(SyncModelError::InvalidIdentifier);
        }
        Ok(Self::Absent {
            item_id,
            pending: PendingExpectation::Absent,
        })
    }

    #[must_use]
    pub fn exact(proof: ItemProof) -> Self {
        Self::Exact {
            proof: Box::new(proof),
            pending: PendingExpectation::Absent,
        }
    }

    #[must_use]
    pub fn with_pending(mut self, pending: PendingProof) -> Self {
        match &mut self {
            Self::Absent {
                pending: expectation,
                ..
            }
            | Self::Exact {
                pending: expectation,
                ..
            } => *expectation = PendingExpectation::Exact(Box::new(pending)),
        }
        self
    }

    #[must_use]
    pub fn item_id(&self) -> Uuid {
        match self {
            Self::Absent { item_id, .. } => *item_id,
            Self::Exact { proof, .. } => proof.projection().item_id(),
        }
    }

    #[must_use]
    pub fn pending(&self) -> &PendingExpectation {
        match self {
            Self::Absent { pending, .. } | Self::Exact { pending, .. } => pending,
        }
    }

    #[must_use]
    pub fn exact_proof(&self) -> Option<&ItemProof> {
        match self {
            Self::Absent { .. } => None,
            Self::Exact { proof, .. } => Some(proof),
        }
    }
}

impl fmt::Debug for ItemState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent { item_id, pending } => formatter
                .debug_struct("Absent")
                .field("item_id", item_id)
                .field("pending", pending)
                .finish(),
            Self::Exact { proof, pending } => formatter
                .debug_struct("Exact")
                .field("proof", proof)
                .field("pending", pending)
                .finish(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum PendingExpectation {
    Absent,
    Exact(Box<PendingProof>),
}

impl fmt::Debug for PendingExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("Absent"),
            Self::Exact(proof) => formatter
                .debug_tuple("Exact")
                .field(&proof.pending_id())
                .finish(),
        }
    }
}

/// Exact pending row provenance. Ciphertext is deliberately omitted from Debug.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingProof {
    pub(super) pending_id: Uuid,
    pub(super) scope: SyncScope,
    pub(super) item_id: Uuid,
    pub(super) operation: ChangeType,
    pub(super) payload_enc: Option<Vec<u8>>,
    pub(super) checksum: Option<ContentChecksum>,
    pub(super) path: Option<String>,
    pub(super) name: Option<String>,
    pub(super) type_id: Option<String>,
    pub(super) base_seq: Option<SyncSeq>,
    pub(super) created_at: DateTime<Utc>,
}

impl PendingProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pending_id: Uuid,
        scope: SyncScope,
        item_id: Uuid,
        operation: ChangeType,
        payload_enc: Option<Vec<u8>>,
        checksum: Option<ContentChecksum>,
        path: Option<String>,
        name: Option<String>,
        type_id: Option<String>,
        base_seq: Option<SyncSeq>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, SyncModelError> {
        if pending_id.is_nil() || item_id.is_nil() {
            return Err(SyncModelError::InvalidIdentifier);
        }
        if payload_enc
            .as_ref()
            .is_some_and(|payload| payload.len() > MAX_CIPHERTEXT_BYTES)
        {
            return Err(SyncModelError::PayloadTooLarge);
        }
        validate_pending_shape(
            operation,
            payload_enc.as_ref(),
            checksum,
            path.as_deref(),
            name.as_deref(),
            type_id.as_deref(),
            base_seq,
        )?;
        Ok(Self {
            pending_id,
            scope,
            item_id,
            operation,
            payload_enc,
            checksum,
            path,
            name,
            type_id,
            base_seq,
            created_at,
        })
    }

    #[must_use]
    pub fn pending_id(&self) -> Uuid {
        self.pending_id
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
    pub fn operation(&self) -> ChangeType {
        self.operation
    }

    #[must_use]
    pub fn payload_enc(&self) -> Option<&[u8]> {
        self.payload_enc.as_deref()
    }

    #[must_use]
    pub fn checksum(&self) -> Option<ContentChecksum> {
        self.checksum
    }

    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    pub fn type_id(&self) -> Option<&str> {
        self.type_id.as_deref()
    }

    #[must_use]
    pub fn base_seq(&self) -> Option<SyncSeq> {
        self.base_seq
    }

    #[must_use]
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl fmt::Debug for PendingProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingProof")
            .field("pending_id", &self.pending_id)
            .field("scope", &self.scope)
            .field("item_id", &self.item_id)
            .field("operation", &self.operation)
            .field("payload", &self.payload_enc.as_ref().map(Vec::len))
            .field("checksum", &self.checksum.map(|_| "<redacted>"))
            .field("base_seq", &self.base_seq)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

pub(super) fn validate_pending_shape(
    operation: ChangeType,
    payload: Option<&Vec<u8>>,
    checksum: Option<ContentChecksum>,
    path: Option<&str>,
    name: Option<&str>,
    type_id: Option<&str>,
    base_seq: Option<SyncSeq>,
) -> Result<(), SyncModelError> {
    if let Some(path) = path {
        validate_path(path)?;
    }
    if let Some(name) = name {
        validate_required(name, MAX_ITEM_NAME_BYTES)?;
    }
    if let Some(type_id) = type_id {
        validate_required(type_id, MAX_TYPE_ID_BYTES)?;
    }
    let has_projection = payload.is_some()
        && checksum.is_some()
        && path.is_some()
        && name.is_some()
        && type_id.is_some();
    match operation {
        ChangeType::Create if has_projection && base_seq.is_none() => Ok(()),
        ChangeType::Update | ChangeType::Restore if has_projection && base_seq.is_some() => Ok(()),
        ChangeType::Delete if payload.is_none() && checksum.is_none() && base_seq.is_some() => {
            Ok(())
        }
        _ => Err(SyncModelError::InvalidPendingProof),
    }
}
