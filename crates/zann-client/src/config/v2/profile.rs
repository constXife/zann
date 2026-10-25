use super::*;

impl ConnectionConfig {
    pub(super) fn from_metadata(metadata: ConnectionMetadata) -> Self {
        Self {
            metadata,
            credential_profiles: BTreeMap::new(),
            active_credential: None,
        }
    }

    pub fn metadata(&self) -> &ConnectionMetadata {
        &self.metadata
    }

    pub fn credential_profiles(&self) -> &BTreeMap<String, CredentialProfile> {
        &self.credential_profiles
    }

    pub fn active_credential(&self) -> Option<&str> {
        self.active_credential.as_deref()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) account_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) auth_method: Option<AuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_expires_at: Option<String>,
    #[serde(default)]
    pub(super) credentials: BTreeMap<CredentialKind, CredentialId>,
}

impl CredentialProfile {
    pub fn account_subject(&self) -> Option<&str> {
        self.account_subject.as_deref()
    }

    pub fn auth_method(&self) -> Option<AuthMethod> {
        self.auth_method
    }

    pub fn credentials(&self) -> &BTreeMap<CredentialKind, CredentialId> {
        &self.credentials
    }
}

/// Secret-free compare-and-swap token for one credential profile.
///
/// Anchors are created by [`ConfigRepository::resolve_credential_profile_anchor`]. Their fields
/// are intentionally read-only and they are not serializable: an anchor is a short-lived proof of
/// the exact repository, endpoint binding and profile state observed before a network operation.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialProfileAnchor {
    pub(super) repository_binding_digest: String,
    pub(super) source_revision: u64,
    pub(super) source_digest: String,
    pub(super) connection_id: ConnectionId,
    pub(super) profile_name: String,
    pub(super) normalized_address: String,
    pub(super) server_id: Option<String>,
    pub(super) server_fingerprint: Option<String>,
    pub(super) storage_id: Option<String>,
    pub(super) expected_master_key_fp: Option<String>,
    pub(super) master_key_binding_observed: bool,
    pub(super) account_subject: Option<String>,
    pub(super) auth_method: Option<AuthMethod>,
    pub(super) access_expires_at: Option<String>,
    pub(super) credentials: BTreeMap<CredentialKind, CredentialId>,
}

/// Secret-free, repository-bound source captured before password login.
///
/// Unlike [`CredentialProfileAnchor`], this permits an absent target profile.
/// The connection itself must already exist and carry a complete pinned
/// endpoint binding.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PasswordLoginAnchor {
    pub(super) repository_binding_digest: String,
    pub(super) source_revision: u64,
    pub(super) source_digest: String,
    pub(super) connection_id: ConnectionId,
    pub(super) profile_name: String,
    pub(super) normalized_address: String,
    pub(super) server_id: String,
    pub(super) server_fingerprint: String,
    pub(super) storage_id: Option<String>,
    pub(super) profile: Option<CredentialProfile>,
    pub(super) active_profile: Option<String>,
    pub(super) client_id: ClientId,
    pub(super) client_present: bool,
    pub(super) client_active_connection: Option<ConnectionId>,
    pub(super) identity: Option<ConfigIdentity>,
}

impl fmt::Debug for PasswordLoginAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordLoginAnchor")
            .field("source_revision", &self.source_revision)
            .field("connection_id", &self.connection_id)
            .field("profile_name", &self.profile_name)
            .field("normalized_address", &self.normalized_address)
            .field("server_id", &self.server_id)
            .field("server_fingerprint", &self.server_fingerprint)
            .field("storage_id", &self.storage_id)
            .field("profile_present", &self.profile.is_some())
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

#[cfg_attr(not(feature = "session"), allow(dead_code))]
impl PasswordLoginAnchor {
    pub(crate) fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub(crate) fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub(crate) fn profile_name(&self) -> &str {
        &self.profile_name
    }

    pub(crate) fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub(crate) fn address(&self) -> &str {
        &self.normalized_address
    }

    pub(crate) fn server_id(&self) -> &str {
        &self.server_id
    }

    pub(crate) fn server_fingerprint(&self) -> &str {
        &self.server_fingerprint
    }

    pub(crate) fn storage_id(&self) -> Option<&str> {
        self.storage_id.as_deref()
    }
}

impl fmt::Debug for CredentialProfileAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialProfileAnchor")
            .field("source_revision", &self.source_revision)
            .field("connection_id", &self.connection_id)
            .field("profile_name", &self.profile_name)
            .field("normalized_address", &self.normalized_address)
            .field("server_id", &self.server_id)
            .field("server_fingerprint", &self.server_fingerprint)
            .field("storage_id", &self.storage_id)
            .field(
                "expected_master_key_fp_present",
                &self.expected_master_key_fp.is_some(),
            )
            .field("access_expires_at", &self.access_expires_at)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl CredentialProfileAnchor {
    pub fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    pub fn address(&self) -> &str {
        &self.normalized_address
    }

    pub fn server_id(&self) -> Option<&str> {
        self.server_id.as_deref()
    }

    pub fn server_fingerprint(&self) -> Option<&str> {
        self.server_fingerprint.as_deref()
    }

    pub fn storage_id(&self) -> Option<&str> {
        self.storage_id.as_deref()
    }

    /// Master-key provenance binding observed with this profile.
    ///
    /// The value is not interpreted while resolving legacy configs. New
    /// bindings written through [`ConfigRepository::bind_expected_master_key_fingerprint_if_profile_matches`]
    /// are always canonical twelve-character lowercase hexadecimal strings.
    pub fn expected_master_key_fp(&self) -> Option<&str> {
        self.expected_master_key_fp.as_deref()
    }

    /// Stable authenticated account subject returned by canonical `/me`.
    pub fn account_subject(&self) -> Option<&str> {
        self.account_subject.as_deref()
    }

    pub fn auth_method(&self) -> Option<AuthMethod> {
        self.auth_method
    }

    pub fn access_expires_at(&self) -> Option<&str> {
        self.access_expires_at.as_deref()
    }

    pub fn credentials(&self) -> &BTreeMap<CredentialKind, CredentialId> {
        &self.credentials
    }
}
