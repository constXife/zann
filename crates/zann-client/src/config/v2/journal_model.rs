use super::*;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Access,
    Refresh,
    ServiceAccount,
}

impl CredentialKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Refresh => "refresh",
            Self::ServiceAccount => "service_account",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationStamp {
    pub source_format: String,
    pub source_digest: String,
    #[serde(default)]
    pub claimed_clients: BTreeSet<ClientId>,
    #[serde(default)]
    pub deferred_legacy_fields: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigV2 {
    pub schema_version: u32,
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ConfigIdentity>,
    #[serde(default)]
    pub connections: BTreeMap<ConnectionId, ConnectionConfig>,
    #[serde(default)]
    pub clients: BTreeMap<ClientId, ClientConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration: Option<MigrationStamp>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub legacy_known_hosts: BTreeMap<String, String>,
}

impl ConfigV2 {
    pub(super) fn empty() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            revision: 0,
            identity: None,
            connections: BTreeMap::new(),
            clients: BTreeMap::new(),
            migration: None,
            legacy_known_hosts: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoreJournal {
    pub(super) journal_version: u32,
    pub(super) source_primary_digest: String,
    pub(super) source_backup_digest: String,
    pub(super) target_primary: ConfigV2,
    pub(super) target_backup: ConfigV2,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CredentialTransactionJournal {
    pub(super) journal_version: u32,
    pub(super) source_primary: CredentialGeneration,
    pub(super) source_backup: Option<CredentialGeneration>,
    pub(super) candidate: CredentialGeneration,
    pub(super) new_ids: BTreeSet<CredentialId>,
    pub(super) retired_slots: BTreeSet<CredentialSlotRef>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(super) carried_retired_slots: BTreeSet<CredentialSlotRef>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(super) settled_retired_ids: BTreeSet<CredentialId>,
    #[serde(default)]
    pub(super) aborted: bool,
    #[serde(default)]
    pub(super) aborted_after_backup_write: bool,
}

/// A durable, secret-free record of a refresh or logout which may already
/// have changed server state. It deliberately records credential identifiers
/// and config digests only; neither secrets nor secret-derived hashes belong
/// in this file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthOperationIntent {
    pub(super) journal_version: u32,
    pub(super) operation_id: String,
    pub(super) operation: AuthOperationKind,
    pub(super) state: AuthOperationIntentState,
    pub(super) repository_binding_digest: String,
    pub(super) connection_id: ConnectionId,
    pub(super) profile_name: String,
    pub(super) endpoint: AuthIntentEndpoint,
    pub(super) source: AuthIntentSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) candidate_rotation: Option<AuthIntentRotationCandidate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) client_id: Option<ClientId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reserved_login: Option<AuthIntentLoginReservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) candidate_login: Option<AuthIntentLoginCandidate>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuthOperationKind {
    Refresh,
    Logout,
    PasswordLogin,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AuthOperationIntentState {
    Armed,
    CandidatePrepared,
}

/// Live-process ownership proof for one exact durable auth intent.
///
/// It is intentionally non-`Clone`; transitions verify the digest of the
/// journal bytes before they may replace or clear that journal.
pub(crate) struct AuthOperationIntentPermit {
    pub(super) anchor: CredentialProfileAnchor,
    pub(super) operation_id: String,
    pub(super) operation: AuthOperationKind,
    pub(super) journal_bytes_digest: String,
}

/// Live-process ownership proof for one exact password-login intent.
///
/// The source may intentionally have no profile, so it cannot reuse the
/// refresh/logout profile permit. Like that permit this value is non-`Clone`
/// and every transition checks the digest of the exact durable bytes.
pub(crate) struct PasswordLoginIntentPermit {
    pub(super) anchor: PasswordLoginAnchor,
    pub(super) identity: ConfigIdentity,
    pub(super) reservation: AuthIntentLoginReservation,
    pub(super) operation_id: String,
    pub(super) journal_bytes_digest: String,
    pub(super) candidate: Option<AuthIntentLoginCandidate>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthIntentEndpoint {
    pub(super) address: String,
    pub(super) server_id: String,
    pub(super) server_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) storage_id: Option<String>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthIntentSource {
    pub(super) revision: u64,
    pub(super) raw_digest: String,
    /// Stable authenticated account binding. Older v1 journals omit it and
    /// therefore remain readable but cannot authorize sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) account_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) auth_method: Option<AuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) access_expires_at: Option<String>,
    pub(super) credentials: BTreeMap<CredentialKind, CredentialId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) profile_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) client_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) active_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) client_active_connection: Option<ConnectionId>,
}

impl fmt::Debug for AuthIntentSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthIntentSource")
            .field("revision", &self.revision)
            .field("binding", &"<redacted>")
            .field("has_account_subject", &self.account_subject.is_some())
            .field("auth_method", &self.auth_method)
            .field("has_expiry", &self.access_expires_at.is_some())
            .field("credential_count", &self.credentials.len())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthIntentRotationCandidate {
    pub(super) revision: u64,
    pub(super) raw_digest: String,
    pub(super) access_expires_at: String,
    pub(super) access_credential_id: CredentialId,
    pub(super) refresh_credential_id: CredentialId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthIntentLoginReservation {
    pub(super) access_credential_id: CredentialId,
    pub(super) refresh_credential_id: CredentialId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthIntentLoginCandidate {
    pub(super) revision: u64,
    pub(super) raw_digest: String,
    pub(super) account_subject: String,
    pub(super) auth_method: AuthMethod,
    pub(super) access_expires_at: String,
    pub(super) access_credential_id: CredentialId,
    pub(super) refresh_credential_id: CredentialId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CredentialGeneration {
    pub(super) revision: u64,
    pub(super) raw_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) migration_digest: Option<String>,
    pub(super) slots: BTreeSet<CredentialSlotRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CredentialSlotRef {
    pub(super) connection_id: ConnectionId,
    pub(super) profile_name: String,
    pub(super) kind: CredentialKind,
    pub(super) credential_id: CredentialId,
}

#[derive(Deserialize)]
pub(super) struct ConfigVersionProbe {
    #[serde(default)]
    pub(super) schema_version: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct RestoreVersionProbe {
    #[serde(default)]
    pub(super) journal_version: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct CredentialTransactionVersionProbe {
    #[serde(default)]
    pub(super) journal_version: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct AuthOperationIntentVersionProbe {
    #[serde(default)]
    pub(super) journal_version: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RestoreState {
    Initial,
    BackupWritten,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CredentialTransactionState {
    Initial,
    BackupWritten,
    Committed,
    Cleanup,
}

pub(super) enum AuthIntentState {
    Source(Box<CredentialProfileAnchor>),
    LoginSource,
    Candidate,
    TargetRemoved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(feature = "session"), allow(dead_code))]
pub(crate) enum AuthOperationRecoveryDisposition {
    NoIntent,
    SourceRevoked,
    LoginAbandoned,
    CandidatePreserved,
    TargetRemoved,
}
