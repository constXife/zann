use super::*;

/// Key material used only inside the sync owner for payload verification or local encryption.
///
/// The fingerprint is derived once from these exact bytes and travels with
/// every projection encrypted or verified by this key. Adapters must persist
/// that projection-owned value rather than consulting mutable vault metadata
/// again during commit.
pub struct VaultPayloadKey {
    pub(super) key: SecretKey,
    pub(super) cache_key_fingerprint: String,
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
    pub(super) id: Uuid,
    pub(super) slug: String,
    pub(super) name: String,
    pub(super) plane: VaultPlane,
    pub(super) tags: Vec<String>,
    pub(super) created_at: DateTime<Utc>,
    pub(super) vault_key_envelope: Vec<u8>,
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
    pub(super) vaults: Vec<CatalogVault>,
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
    pub(super) storage_id: Uuid,
    pub(super) display_name: String,
    pub(super) server_url: String,
    pub(super) server_name: Option<String>,
    pub(super) server_fingerprint: String,
    pub(super) account_subject: Option<String>,
    pub(super) personal_vaults_enabled: bool,
    pub(super) auth_method: Option<AuthMethod>,
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
    pub(super) binding: StorageBindingProof,
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
    pub(super) scope: SyncScope,
    pub(super) plane: VaultPlane,
    pub(super) payload_key: VaultPayloadKey,
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
    pub(super) vaults: Vec<ResolvedSyncVault>,
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
