//! Persistence-independent sync vocabulary and ports.

use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;
use zann_core::{AuthMethod, ChangeType, SyncStatus};
use zann_crypto::SecretKey;
use zeroize::Zeroizing;

use crate::config::AuthorizedTargetGeneration;
use crate::session::{OperationCompletion, SessionOperationId, SessionTarget};

pub(crate) const CATALOG_PAGE_LIMIT: usize = 200;
// The current endpoint has offset pagination but no versioned snapshot/cursor.
// A full page could hide additional vaults, so only a strictly shorter page is
// safe to reconcile as a complete catalog.
pub(crate) const MAX_CATALOG_VAULTS: usize = CATALOG_PAGE_LIMIT - 1;
// `Vec<u8>` is represented as a JSON integer array by the current wire
// contract. Four maximum-size items with five history entries remain below the
// fixed 32 MiB response cap; a larger legal page would not be transportable.
pub(crate) const PULL_PAGE_LIMIT: usize = 4;
pub(crate) const MAX_PULL_PAGES: usize = 1_024;
pub(crate) const MAX_PULL_CHANGES: usize = 16_384;
pub(crate) const MAX_HISTORY_PER_ITEM: usize = 5;
pub(crate) const MAX_CURSOR_BYTES: usize = 4_096;
pub(crate) const MAX_PENDING_CHANGES: usize = 64;
pub(crate) const MAX_PAYLOAD_BYTES: usize = 262_144;
pub(crate) const MAX_CIPHERTEXT_BYTES: usize = MAX_PAYLOAD_BYTES + 256;
pub(crate) const MAX_ITEM_NAME_BYTES: usize = 200;
pub(crate) const MAX_ITEM_PATH_BYTES: usize = 500;
pub(crate) const MAX_ITEM_PATH_SEGMENTS: usize = 32;
pub(crate) const MAX_TYPE_ID_BYTES: usize = 128;
pub(crate) const MAX_EMAIL_BYTES: usize = 320;
pub(crate) const MAX_DISPLAY_NAME_BYTES: usize = 200;

/// Identifies one local projection of one remote vault.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SyncScope {
    storage_id: Uuid,
    vault_id: Uuid,
}

impl SyncScope {
    pub fn new(storage_id: Uuid, vault_id: Uuid) -> Result<Self, SyncModelError> {
        if storage_id.is_nil() || vault_id.is_nil() {
            return Err(SyncModelError::InvalidIdentifier);
        }
        Ok(Self {
            storage_id,
            vault_id,
        })
    }

    #[must_use]
    pub fn storage_id(&self) -> Uuid {
        self.storage_id
    }

    #[must_use]
    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }
}

/// The only server-side vault/encryption pairings understood by clean sync.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultPlane {
    PersonalClient,
    SharedServer,
}

/// Provenance required for history received from the authoritative server.
///
/// Adapters map this to their local `Server` source and `Confirmed` status.
/// Local/UI, pending, rejected, and conflict history is outside this authority
/// and must not be deleted while applying a pull page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryAuthority {
    ServerConfirmed,
}

/// An opaque, bounded server cursor.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SyncCursor {
    encoded: String,
    sequence: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    seq: i64,
}

impl SyncCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, SyncModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES {
            return Err(SyncModelError::InvalidCursor);
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value.as_bytes())
            .map_err(|_| SyncModelError::InvalidCursor)?;
        if decoded.len() > 64 || base64::engine::general_purpose::STANDARD.encode(&decoded) != value
        {
            return Err(SyncModelError::InvalidCursor);
        }
        let payload: CursorPayload =
            serde_json::from_slice(&decoded).map_err(|_| SyncModelError::InvalidCursor)?;
        if payload.seq < 0 {
            return Err(SyncModelError::InvalidCursor);
        }
        Ok(Self {
            encoded: value,
            sequence: payload.seq,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    #[must_use]
    pub fn sequence(&self) -> i64 {
        self.sequence
    }
}

impl fmt::Debug for SyncCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncCursor")
            .field("bytes", &self.encoded.len())
            .finish()
    }
}

/// A positive server sequence number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SyncSeq(i64);

impl SyncSeq {
    pub fn new(value: i64) -> Result<Self, SyncModelError> {
        if value < 1 {
            return Err(SyncModelError::InvalidSequence);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn get(self) -> i64 {
        self.0
    }
}

/// A canonical BLAKE3 digest: exactly 32 bytes / 64 lowercase hex characters.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ContentChecksum([u8; 32]);

impl ContentChecksum {
    pub fn parse(value: &str) -> Result<Self, SyncModelError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(SyncModelError::InvalidChecksum);
        }
        let mut bytes = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(chunk[0]).ok_or(SyncModelError::InvalidChecksum)?;
            let low = hex_nibble(chunk[1]).ok_or(SyncModelError::InvalidChecksum)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    pub(crate) fn for_ciphertext(ciphertext: &[u8]) -> Result<Self, SyncModelError> {
        let encoded = zann_crypto::payload_checksum(ciphertext);
        Self::parse(&encoded)
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            use fmt::Write as _;
            let _ = write!(&mut output, "{byte:02x}");
        }
        output
    }
}

impl fmt::Debug for ContentChecksum {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContentChecksum(<redacted>)")
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// Key material used only inside the sync owner for payload verification or local encryption.
///
/// The fingerprint is derived once from these exact bytes and travels with
/// every projection encrypted or verified by this key. Adapters must persist
/// that projection-owned value rather than consulting mutable vault metadata
/// again during commit.
pub struct VaultPayloadKey {
    key: SecretKey,
    cache_key_fingerprint: String,
}

impl VaultPayloadKey {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let bytes = Zeroizing::new(bytes);
        Self::from_secret_key(SecretKey::from_bytes(*bytes))
    }

    /// Takes ownership of already-protected key material without creating a
    /// second raw 32-byte array at the persistence boundary.
    #[must_use]
    pub fn from_secret_key(key: SecretKey) -> Self {
        let cache_key_fingerprint = zann_crypto::cache_key_fingerprint(&key);
        Self {
            key,
            cache_key_fingerprint,
        }
    }

    /// Copies a borrowed operation key through a zeroizing temporary.
    ///
    /// This is reserved for designs where ownership cannot be transferred,
    /// such as a shared-vault cache key borrowed from the operation master-key
    /// lease. The temporary is wiped on every exit path.
    #[must_use]
    pub fn copy_from_secret_key(key: &SecretKey) -> Self {
        let bytes = Zeroizing::new(*key.as_bytes());
        Self::from_secret_key(SecretKey::from_bytes(*bytes))
    }

    pub(crate) fn expose(&self) -> &SecretKey {
        &self.key
    }

    #[must_use]
    pub fn cache_key_fingerprint(&self) -> &str {
        &self.cache_key_fingerprint
    }
}

impl fmt::Debug for VaultPayloadKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultPayloadKey(<redacted>)")
    }
}

/// One fully validated remote catalog entry.
pub struct CatalogVault {
    id: Uuid,
    slug: String,
    name: String,
    plane: VaultPlane,
    tags: Vec<String>,
    created_at: DateTime<Utc>,
    vault_key_envelope: Vec<u8>,
}

impl CatalogVault {
    pub(crate) fn validated(
        id: Uuid,
        slug: String,
        name: String,
        plane: VaultPlane,
        tags: Vec<String>,
        created_at: DateTime<Utc>,
        vault_key_envelope: Vec<u8>,
    ) -> Self {
        Self {
            id,
            slug,
            name,
            plane,
            tags,
            created_at,
            vault_key_envelope,
        }
    }

    #[must_use]
    pub fn id(&self) -> Uuid {
        self.id
    }

    #[must_use]
    pub fn slug(&self) -> &str {
        &self.slug
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn plane(&self) -> VaultPlane {
        self.plane
    }

    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    #[must_use]
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    #[must_use]
    pub fn vault_key_envelope(&self) -> &[u8] {
        &self.vault_key_envelope
    }
}

impl fmt::Debug for CatalogVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogVault")
            .field("id", &self.id)
            .field("plane", &self.plane)
            .field("created_at", &self.created_at)
            .field("vault_key_envelope_bytes", &self.vault_key_envelope.len())
            .finish()
    }
}

pub struct CatalogSnapshot {
    vaults: Vec<CatalogVault>,
}

impl fmt::Debug for CatalogSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogSnapshot")
            .field("vault_count", &self.vaults.len())
            .finish()
    }
}

impl CatalogSnapshot {
    pub(crate) fn validated(vaults: Vec<CatalogVault>) -> Self {
        Self { vaults }
    }

    pub(crate) fn install_generated_envelope(
        &mut self,
        vault_id: Uuid,
        expected: &[u8],
        published: Vec<u8>,
    ) -> Result<(), SyncModelError> {
        if published.is_empty() || published.len() > 64 * 1_024 {
            return Err(SyncModelError::PayloadTooLarge);
        }
        let vault = self
            .vaults
            .iter_mut()
            .find(|vault| vault.id == vault_id)
            .ok_or(SyncModelError::InvalidIdentifier)?;
        if vault.plane != VaultPlane::PersonalClient || vault.vault_key_envelope != expected {
            return Err(SyncModelError::InvalidIdentifier);
        }
        vault.vault_key_envelope = published;
        Ok(())
    }

    #[must_use]
    pub fn vaults(&self) -> &[CatalogVault] {
        &self.vaults
    }
}

/// Local storage binding selected for the explicit authenticated target.
pub struct StorageBindingProof {
    storage_id: Uuid,
    display_name: String,
    server_url: String,
    server_name: Option<String>,
    server_fingerprint: String,
    account_subject: Option<String>,
    personal_vaults_enabled: bool,
    auth_method: Option<AuthMethod>,
}

impl StorageBindingProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage_id: Uuid,
        display_name: impl Into<String>,
        server_url: impl Into<String>,
        server_name: Option<String>,
        server_fingerprint: impl Into<String>,
        account_subject: Option<String>,
        personal_vaults_enabled: bool,
        auth_method: Option<AuthMethod>,
    ) -> Result<Self, SyncModelError> {
        let display_name = display_name.into();
        let server_url = server_url.into();
        let server_fingerprint = server_fingerprint.into();
        if storage_id.is_nil() {
            return Err(SyncModelError::InvalidIdentifier);
        }
        validate_required(&display_name, MAX_DISPLAY_NAME_BYTES)?;
        validate_required(&server_url, 2_048)?;
        validate_required(&server_fingerprint, 512)?;
        if server_name
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 512)
            || account_subject
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 512)
        {
            return Err(SyncModelError::InvalidText);
        }
        if account_subject.as_ref().is_some_and(|value| {
            Uuid::parse_str(value).map_or(true, |parsed| parsed.to_string() != *value)
        }) {
            return Err(SyncModelError::InvalidIdentifier);
        }
        Ok(Self {
            storage_id,
            display_name,
            server_url,
            server_name,
            server_fingerprint,
            account_subject,
            personal_vaults_enabled,
            auth_method,
        })
    }

    #[must_use]
    pub fn storage_id(&self) -> Uuid {
        self.storage_id
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    #[must_use]
    pub fn server_fingerprint(&self) -> &str {
        &self.server_fingerprint
    }

    #[must_use]
    pub fn account_subject(&self) -> Option<&str> {
        self.account_subject.as_deref()
    }

    #[must_use]
    pub fn personal_vaults_enabled(&self) -> bool {
        self.personal_vaults_enabled
    }

    #[must_use]
    pub fn auth_method(&self) -> Option<AuthMethod> {
        self.auth_method
    }
}

impl fmt::Debug for StorageBindingProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageBindingProof")
            .field("storage_id", &self.storage_id)
            .field("binding", &"<redacted>")
            .finish()
    }
}

pub struct ResolvedSyncTarget {
    binding: StorageBindingProof,
}

impl ResolvedSyncTarget {
    #[must_use]
    pub fn new(binding: StorageBindingProof) -> Self {
        Self { binding }
    }

    #[must_use]
    pub fn storage_id(&self) -> Uuid {
        self.binding.storage_id()
    }

    #[must_use]
    pub fn binding(&self) -> &StorageBindingProof {
        &self.binding
    }
}

impl fmt::Debug for ResolvedSyncTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSyncTarget")
            .field("binding", &self.binding)
            .finish()
    }
}

/// An already initialized full-cache vault returned by catalog reconciliation.
pub struct ResolvedSyncVault {
    scope: SyncScope,
    plane: VaultPlane,
    payload_key: VaultPayloadKey,
}

impl ResolvedSyncVault {
    #[must_use]
    pub fn new(scope: SyncScope, plane: VaultPlane, payload_key: VaultPayloadKey) -> Self {
        Self {
            scope,
            plane,
            payload_key,
        }
    }

    #[must_use]
    pub fn scope(&self) -> SyncScope {
        self.scope
    }

    #[must_use]
    pub fn plane(&self) -> VaultPlane {
        self.plane
    }

    pub(crate) fn payload_key(&self) -> &VaultPayloadKey {
        &self.payload_key
    }
}

impl fmt::Debug for ResolvedSyncVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSyncVault")
            .field("scope", &self.scope)
            .field("plane", &self.plane)
            .field("payload_key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug)]
pub struct ReconciledCatalog {
    vaults: Vec<ResolvedSyncVault>,
}

impl ReconciledCatalog {
    pub fn new(vaults: Vec<ResolvedSyncVault>) -> Result<Self, SyncModelError> {
        if vaults.len() > MAX_CATALOG_VAULTS {
            return Err(SyncModelError::CatalogTooLarge);
        }
        let mut scopes = HashSet::with_capacity(vaults.len());
        if vaults.iter().any(|vault| !scopes.insert(vault.scope())) {
            return Err(SyncModelError::DuplicateIdentifier);
        }
        Ok(Self { vaults })
    }

    #[must_use]
    pub fn vaults(&self) -> &[ResolvedSyncVault] {
        &self.vaults
    }
}

/// Exact local item projection used as a compare-and-swap proof.
#[derive(Clone, Eq, PartialEq)]
pub struct ItemProjection {
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
    sync_status: SyncStatus,
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
    projection: ItemProjection,
    sync_status: SyncStatus,
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

fn validate_pending_shape(
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

pub struct SyncCheckpoint {
    cursor: Option<SyncCursor>,
    last_seq: Option<SyncSeq>,
    pending: Vec<PendingProof>,
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
    authority: HistoryAuthority,
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
    expected: ItemState,
    item: ItemProjection,
    history: Vec<HistoryProjection>,
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
    scope: SyncScope,
    cache_key_fingerprint: String,
    expected_cursor: Option<SyncCursor>,
    expected_last_seq: Option<SyncSeq>,
    next_cursor: SyncCursor,
    next_last_seq: Option<SyncSeq>,
    committed_at: DateTime<Utc>,
    changes: Vec<PullCommitChange>,
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
    items: usize,
    history_entries: usize,
    cursor: SyncCursor,
    last_seq: Option<SyncSeq>,
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
    scope: SyncScope,
    expected_remote_envelope: Vec<u8>,
    published_envelope: Vec<u8>,
    generated_key: VaultPayloadKey,
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
    pending: PendingProof,
    expected: ItemState,
    item: ItemProjection,
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
    scope: SyncScope,
    expected_cursor: Option<SyncCursor>,
    expected_last_seq: Option<SyncSeq>,
    server_head_hint: SyncCursor,
    changes: Vec<PushCommitChange>,
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
    pending_deleted: usize,
    server_head_hint: SyncCursor,
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
    expected_binding: StorageBindingProof,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncStoreErrorKind {
    NotFound,
    Busy,
    StaleCheckpoint,
    StaleKeyBinding,
    StaleItem,
    PendingChanged,
    PendingPresent,
    CommitOutcomeUnknown,
    InvalidData,
    Unavailable,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncStoreError {
    kind: SyncStoreErrorKind,
}

impl SyncStoreError {
    #[must_use]
    pub const fn new(kind: SyncStoreErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> SyncStoreErrorKind {
        self.kind
    }
}

impl fmt::Display for SyncStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sync_store:{}", sync_store_error_code(self.kind))
    }
}

impl std::error::Error for SyncStoreError {}

const fn sync_store_error_code(kind: SyncStoreErrorKind) -> &'static str {
    match kind {
        SyncStoreErrorKind::NotFound => "not_found",
        SyncStoreErrorKind::Busy => "busy",
        SyncStoreErrorKind::StaleCheckpoint => "stale_checkpoint",
        SyncStoreErrorKind::StaleKeyBinding => "stale_key_binding",
        SyncStoreErrorKind::StaleItem => "stale_item",
        SyncStoreErrorKind::PendingChanged => "pending_changed",
        SyncStoreErrorKind::PendingPresent => "pending_present",
        SyncStoreErrorKind::CommitOutcomeUnknown => "commit_outcome_unknown",
        SyncStoreErrorKind::InvalidData => "invalid_data",
        SyncStoreErrorKind::Unavailable => "unavailable",
        SyncStoreErrorKind::Internal => "internal",
    }
}

pub type SyncStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, SyncStoreError>> + Send + 'a>>;

/// Boxed future used by the crate-internal DB-free sync owner and public facade.
pub type SyncFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SyncError>> + Send + 'a>>;

/// Transactional local projection port. Implementations may use SQLite, but this crate cannot.
pub trait SyncLocalStore: Send + Sync {
    fn resolve_target<'a>(
        &'a self,
        target: &'a SessionTarget,
        generation: Arc<AuthorizedTargetGeneration>,
        personal_vaults_enabled: bool,
    ) -> SyncStoreFuture<'a, ResolvedSyncTarget>;

    /// Atomically reconciles safe catalog metadata and existing key bindings.
    /// It must never delete dirty/pending/conflict projections, silently
    /// replace a bound key, or initialize a shared first-snapshot cursor.
    fn reconcile_catalog(
        self: Arc<Self>,
        target: Arc<ResolvedSyncTarget>,
        catalog: Arc<CatalogSnapshot>,
    ) -> SyncStoreFuture<'static, ReconciledCatalog>;

    fn load_checkpoint<'a>(&'a self, scope: SyncScope) -> SyncStoreFuture<'a, SyncCheckpoint>;

    fn load_item_states<'a>(
        &'a self,
        scope: SyncScope,
        item_ids: &'a [Uuid],
    ) -> SyncStoreFuture<'a, Vec<ItemState>>;

    fn prepare_generated_key(
        self: Arc<Self>,
        _scope: SyncScope,
        _expected_remote_envelope: Vec<u8>,
    ) -> SyncStoreFuture<'static, GeneratedVaultKeyCommit> {
        Box::pin(async { Err(SyncStoreError::new(SyncStoreErrorKind::Unavailable)) })
    }

    fn commit_generated_key(
        self: Arc<Self>,
        commit: GeneratedVaultKeyCommit,
    ) -> SyncStoreFuture<'static, ()>;

    fn commit_push(
        self: Arc<Self>,
        commit: PushCommitPlan,
    ) -> SyncStoreFuture<'static, PushCommitReceipt>;

    /// Applies the complete page and advances `(cursor, last_seq)` atomically.
    /// Every [`ItemProjection`] in the plan must be persisted with
    /// `SyncStatus::Synced`; `deleted_at` alone distinguishes a confirmed
    /// remote tombstone. Each [`HistoryProjection`] is authoritative only for
    /// the matching server-confirmed history identity. Reconciliation may
    /// replace stale server-confirmed rows for that identity, but must preserve
    /// local/UI, pending, rejected, and conflict history.
    /// The owned plan lets the engine detach this terminal transaction from a
    /// dropped/cancelled caller once dispatch has begun. Ambiguous database
    /// COMMIT outcomes must be returned as `CommitOutcomeUnknown` and
    /// reconciled from the durable checkpoint before any retry. Runtime or
    /// process shutdown can still abort the terminal task; after restart the
    /// adapter must read the atomic checkpoint before dispatching another page.
    fn commit_pull_page(
        self: Arc<Self>,
        commit: PullPageCommit,
    ) -> SyncStoreFuture<'static, PullCommitReceipt>;

    fn reset_projection_if_clean(
        self: Arc<Self>,
        reset: ProjectionReset,
    ) -> SyncStoreFuture<'static, ()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncModelError {
    InvalidIdentifier,
    DuplicateIdentifier,
    InvalidCursor,
    InvalidSequence,
    InvalidChecksum,
    InvalidText,
    InvalidPath,
    InvalidPendingProof,
    InvalidTimestamp,
    PayloadTooLarge,
    CatalogTooLarge,
    PageTooLarge,
    PendingTooLarge,
}

impl fmt::Display for SyncModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "invalid sync identifier",
            Self::DuplicateIdentifier => "duplicate sync identifier",
            Self::InvalidCursor => "invalid sync cursor",
            Self::InvalidSequence => "invalid sync sequence",
            Self::InvalidChecksum => "invalid content checksum",
            Self::InvalidText => "invalid bounded text",
            Self::InvalidPath => "invalid item path",
            Self::InvalidPendingProof => "invalid pending proof",
            Self::InvalidTimestamp => "invalid sync timestamp",
            Self::PayloadTooLarge => "sync payload is too large",
            Self::CatalogTooLarge => "sync catalog is too large",
            Self::PageTooLarge => "sync page is too large",
            Self::PendingTooLarge => "pending sync set is too large",
        })
    }
}

impl std::error::Error for SyncModelError {}

pub(crate) fn validate_required(value: &str, max_bytes: usize) -> Result<(), SyncModelError> {
    if value.is_empty() || value.len() > max_bytes || value.trim() != value {
        return Err(SyncModelError::InvalidText);
    }
    Ok(())
}

fn validate_cache_key_fingerprint(value: &str) -> Result<(), SyncModelError> {
    if value.len() != 12
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SyncModelError::InvalidText);
    }
    Ok(())
}

pub(crate) fn validate_path(path: &str) -> Result<(), SyncModelError> {
    validate_required(path, MAX_ITEM_PATH_BYTES)?;
    let segments = path.split('/').collect::<Vec<_>>();
    if segments.is_empty()
        || segments.len() > MAX_ITEM_PATH_SEGMENTS
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.len() > MAX_ITEM_NAME_BYTES
                || *segment == "."
                || *segment == ".."
                || segment.starts_with('.')
                || segment.trim() != *segment
        })
    {
        return Err(SyncModelError::InvalidPath);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncStage {
    Authorization,
    ResolveTarget,
    Catalog,
    ReconcileCatalog,
    LoadCheckpoint,
    Pull,
    LoadItemStates,
    CommitPullPage,
    Push,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SyncErrorKind {
    Cancelled,
    DeadlineExceeded,
    Session,
    NoLocalTarget,
    AccountBindingRequired,
    AccountBindingMismatch,
    ServerCapabilityMismatch,
    AuthenticationBindingRequired,
    AuthenticationBindingMismatch,
    Timeout,
    TransportUnavailable,
    TransportRejected,
    SessionExpired,
    Protocol,
    BodyTooLarge,
    Crypto,
    Local,
    ConcurrentLocalChange,
    ConcurrentRemoteChange,
    CommitOutcomeUnknown,
    PushUnavailable,
    InitialSharedSnapshotUnavailable,
    LimitExceeded,
    Internal,
}

pub struct SyncError {
    operation_id: SessionOperationId,
    kind: SyncErrorKind,
    stage: SyncStage,
    status: Option<u16>,
}

impl SyncError {
    pub(crate) const fn new(
        operation_id: SessionOperationId,
        kind: SyncErrorKind,
        stage: SyncStage,
    ) -> Self {
        Self {
            operation_id,
            kind,
            stage,
            status: None,
        }
    }

    pub(crate) const fn with_status(mut self, status: Option<u16>) -> Self {
        self.status = status;
        self
    }

    #[must_use]
    pub fn operation_id(&self) -> SessionOperationId {
        self.operation_id
    }

    #[must_use]
    pub fn kind(&self) -> SyncErrorKind {
        self.kind
    }

    #[must_use]
    pub fn stage(&self) -> SyncStage {
        self.stage
    }

    #[must_use]
    pub fn status(&self) -> Option<u16> {
        self.status
    }
}

impl fmt::Debug for SyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncError")
            .field("operation_id", &self.operation_id)
            .field("kind", &self.kind)
            .field("stage", &self.stage)
            .field("status", &self.status)
            .finish()
    }
}

impl fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "sync:{}:{:?}:{:?}",
            self.operation_id, self.stage, self.kind
        )
    }
}

impl std::error::Error for SyncError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncOutcomeStatus {
    Complete,
    CancelledPartial,
    DeadlinePartial,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncOutcome {
    operation_id: SessionOperationId,
    status: SyncOutcomeStatus,
    completion: OperationCompletion,
    vaults_reconciled: usize,
    pages_committed: usize,
    changes_committed: usize,
}

impl SyncOutcome {
    pub(crate) fn new(
        operation_id: SessionOperationId,
        status: SyncOutcomeStatus,
        completion: OperationCompletion,
        vaults_reconciled: usize,
        pages_committed: usize,
        changes_committed: usize,
    ) -> Self {
        Self {
            operation_id,
            status,
            completion,
            vaults_reconciled,
            pages_committed,
            changes_committed,
        }
    }

    #[must_use]
    pub fn operation_id(&self) -> SessionOperationId {
        self.operation_id
    }

    #[must_use]
    pub fn status(&self) -> SyncOutcomeStatus {
        self.status
    }

    #[must_use]
    pub fn completion(&self) -> OperationCompletion {
        self.completion
    }

    #[must_use]
    pub fn vaults_reconciled(&self) -> usize {
        self.vaults_reconciled
    }

    #[must_use]
    pub fn pages_committed(&self) -> usize {
        self.pages_committed
    }

    #[must_use]
    pub fn changes_committed(&self) -> usize {
        self.changes_committed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncProgressPhase {
    Authorizing,
    Catalog,
    Pushing,
    Pulling,
    Committing,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncProgress {
    operation_id: SessionOperationId,
    phase: SyncProgressPhase,
    vault_index: usize,
    vault_count: usize,
    pages_committed: usize,
    changes_committed: usize,
}

impl SyncProgress {
    pub(crate) fn new(
        operation_id: SessionOperationId,
        phase: SyncProgressPhase,
        vault_index: usize,
        vault_count: usize,
        pages_committed: usize,
        changes_committed: usize,
    ) -> Self {
        Self {
            operation_id,
            phase,
            vault_index,
            vault_count,
            pages_committed,
            changes_committed,
        }
    }

    #[must_use]
    pub fn operation_id(&self) -> SessionOperationId {
        self.operation_id
    }

    #[must_use]
    pub fn phase(&self) -> SyncProgressPhase {
        self.phase
    }

    #[must_use]
    pub fn vault_index(&self) -> usize {
        self.vault_index
    }

    #[must_use]
    pub fn vault_count(&self) -> usize {
        self.vault_count
    }

    #[must_use]
    pub fn pages_committed(&self) -> usize {
        self.pages_committed
    }

    #[must_use]
    pub fn changes_committed(&self) -> usize {
        self.changes_committed
    }
}

pub trait SyncProgressSink: Send + Sync {
    fn report(&self, progress: SyncProgress);
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use zann_crypto::SecretKey;

    use super::{SyncCursor, VaultPayloadKey};

    fn encoded(json: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
    }

    #[test]
    fn cursor_is_strict_bounded_standard_base64_json() {
        let zero = SyncCursor::new(encoded(r#"{"seq":0}"#)).expect("seq zero is valid");
        assert_eq!(zero.sequence(), 0);
        assert!(SyncCursor::new(encoded(r#"{"seq":-1}"#)).is_err());
        assert!(SyncCursor::new(encoded(r#"{"seq":1,"extra":2}"#)).is_err());
        assert!(SyncCursor::new(encoded(r#"{"seq":1,"seq":2}"#)).is_err());
        assert!(SyncCursor::new("not-base64").is_err());
    }

    #[test]
    fn payload_key_fingerprint_is_bound_to_exact_key_bytes() {
        let first = VaultPayloadKey::from_secret_key(SecretKey::from_bytes([7_u8; 32]));
        let borrowed = SecretKey::from_bytes([7_u8; 32]);
        let same = VaultPayloadKey::copy_from_secret_key(&borrowed);
        let rotated = VaultPayloadKey::from_bytes([8_u8; 32]);

        assert_eq!(first.cache_key_fingerprint(), same.cache_key_fingerprint());
        assert_ne!(
            first.cache_key_fingerprint(),
            rotated.cache_key_fingerprint()
        );
        assert_eq!(first.cache_key_fingerprint().len(), 12);
        assert_eq!(format!("{first:?}"), "VaultPayloadKey(<redacted>)");
        assert!(!format!("{first:?}").contains(first.cache_key_fingerprint()));
    }
}
