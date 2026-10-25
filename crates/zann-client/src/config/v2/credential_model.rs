use super::*;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct AuthenticatedSessionOutcome {
    pub(super) transaction: CredentialTransactionOutcome,
    pub(super) connection_id: ConnectionId,
    pub(super) storage_id: Option<String>,
    pub(super) profile_name: String,
}

#[allow(dead_code)]
impl AuthenticatedSessionOutcome {
    pub fn transaction(&self) -> &CredentialTransactionOutcome {
        &self.transaction
    }

    pub fn snapshot(&self) -> &ConfigSnapshot {
        self.transaction.snapshot()
    }

    pub fn warnings(&self) -> &[CredentialTransactionWarning] {
        self.transaction.warnings()
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub fn storage_id(&self) -> Option<&str> {
        self.storage_id.as_deref()
    }

    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    pub fn into_transaction(self) -> CredentialTransactionOutcome {
        self.transaction
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialActivation {
    Preserve,
    MakeActive,
}

#[derive(Clone, Debug)]
pub enum CredentialTransactionWarning {
    CommitRecovered {
        reason: String,
    },
    CredentialDeleteFailed {
        credential_id: CredentialId,
        source: CredentialPortError,
    },
    CleanupDeferred {
        credential_ids: Vec<CredentialId>,
        reason: String,
    },
}

#[derive(Clone, Debug)]
pub struct CredentialTransactionOutcome {
    pub(super) snapshot: ConfigSnapshot,
    pub(super) warnings: Vec<CredentialTransactionWarning>,
}

impl CredentialTransactionOutcome {
    pub fn snapshot(&self) -> &ConfigSnapshot {
        &self.snapshot
    }

    pub fn warnings(&self) -> &[CredentialTransactionWarning] {
        &self.warnings
    }

    pub fn into_snapshot(self) -> ConfigSnapshot {
        self.snapshot
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LegacyCredentialLocator {
    pub connection_name: String,
    pub profile_name: String,
    pub kind: CredentialKind,
}

impl LegacyCredentialLocator {
    pub fn cli_keyring_account(&self) -> Option<String> {
        if self.connection_name.contains("::") || self.profile_name.contains("::") {
            return None;
        }
        let kind = match self.kind {
            CredentialKind::Access => "access",
            CredentialKind::ServiceAccount => "service",
            CredentialKind::Refresh => return None,
        };
        Some(format!(
            "{kind}::{}::{}",
            self.connection_name, self.profile_name
        ))
    }
}

/// Matching behavior of the historical credential backend.
///
/// Windows Credential Manager identifies generic credentials by a
/// case-insensitive target name. Other supported legacy backends use the
/// exact service/account tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyCredentialAccountSemantics {
    Exact,
    WindowsCaseInsensitive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialPortErrorKind {
    Cancelled,
    Unsupported,
    InvalidNamespace,
    SecretTooLarge { maximum_bytes: usize },
    Unavailable,
    Other,
}

#[derive(Clone, Debug, Error)]
#[error("{message}")]
pub struct CredentialPortError {
    pub(super) kind: CredentialPortErrorKind,
    pub(super) message: String,
}

impl CredentialPortError {
    pub fn new(message: impl Into<String>) -> Self {
        Self::with_kind(CredentialPortErrorKind::Other, message)
    }

    pub fn with_kind(kind: CredentialPortErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> &CredentialPortErrorKind {
        &self.kind
    }
}

pub trait CredentialStore: Send + Sync {
    fn validate(
        &self,
        _credential_id: &CredentialId,
        _secret: &CredentialSecret,
    ) -> Result<(), CredentialPortError> {
        Ok(())
    }

    fn put(
        &self,
        credential_id: &CredentialId,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialPortError>;

    fn get(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Option<CredentialSecret>, CredentialPortError>;

    /// Deletes a credential if present. Implementations must treat a missing id as success.
    fn delete(&self, credential_id: &CredentialId) -> Result<(), CredentialPortError>;
}

pub trait LegacyCredentialSource: Send + Sync {
    fn account_semantics(&self) -> LegacyCredentialAccountSemantics {
        LegacyCredentialAccountSemantics::Exact
    }

    /// Whether the source verifies that the physical entry it read retains
    /// the exact requested legacy target and account metadata.
    fn verifies_exact_account_identity(&self) -> bool {
        matches!(
            self.account_semantics(),
            LegacyCredentialAccountSemantics::Exact
        )
    }

    /// Validate a legacy locator without reading the credential backend.
    fn validate(&self, _locator: &LegacyCredentialLocator) -> Result<(), CredentialPortError> {
        Ok(())
    }

    fn get(
        &self,
        locator: &LegacyCredentialLocator,
    ) -> Result<Option<CredentialSecret>, CredentialPortError>;
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("malformed config at {path}: {source}")]
    Malformed {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("config at {path} has no valid schema_version")]
    MissingSchemaVersion { path: PathBuf },
    #[error("config schema {found} is newer than supported schema {supported}")]
    FutureSchema { found: u64, supported: u32 },
    #[error("unsupported config schema {found}; expected {supported}")]
    UnsupportedSchema { found: u64, supported: u32 },
    #[error("restore journal at {path} has no valid journal_version")]
    MissingRestoreJournalVersion { path: PathBuf },
    #[error("restore journal version {found} is newer than supported version {supported}")]
    FutureRestoreJournal { found: u64, supported: u32 },
    #[error("unsupported restore journal version {found}; expected {supported}")]
    UnsupportedRestoreJournal { found: u64, supported: u32 },
    #[error("malformed restore journal at {path}: {source}")]
    MalformedRestoreJournal {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("credential transaction journal at {path} has no valid journal_version")]
    MissingCredentialTransactionJournalVersion { path: PathBuf },
    #[error(
        "credential transaction journal version {found} is newer than supported version {supported}"
    )]
    FutureCredentialTransactionJournal { found: u64, supported: u32 },
    #[error("unsupported credential transaction journal version {found}; expected {supported}")]
    UnsupportedCredentialTransactionJournal { found: u64, supported: u32 },
    #[error("malformed credential transaction journal at {path}: {source}")]
    MalformedCredentialTransactionJournal {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("credential transaction journal at {path} conflicts with config state: {reason}")]
    CredentialTransactionJournalConflict { path: PathBuf, reason: String },
    #[error("credential recovery is required for pending transaction at {path}")]
    CredentialRecoveryRequired { path: PathBuf },
    #[error("authentication operation intent at {path} has no valid journal_version")]
    MissingAuthOperationIntentVersion { path: PathBuf },
    #[error(
        "authentication operation intent version {found} is newer than supported version {supported}"
    )]
    FutureAuthOperationIntent { found: u64, supported: u32 },
    #[error("unsupported authentication operation intent version {found}; expected {supported}")]
    UnsupportedAuthOperationIntent { found: u64, supported: u32 },
    #[error("malformed authentication operation intent at {path}: {source}")]
    MalformedAuthOperationIntent {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("authentication operation recovery is required for pending intent at {path}")]
    AuthOperationRecoveryRequired { path: PathBuf },
    #[error("authentication operation intent at {path} conflicts with config state: {reason}")]
    AuthOperationIntentConflict { path: PathBuf, reason: String },
    #[error("authentication operation intent belongs to a different config repository")]
    AuthOperationIntentRepositoryMismatch,
    #[error("restore journal at {path} conflicts with current config state: {reason}")]
    RestoreJournalConflict { path: PathBuf, reason: String },
    #[error("config does not exist at {path}")]
    MissingConfig { path: PathBuf },
    #[error("config backup does not exist at {path}")]
    MissingBackup { path: PathBuf },
    #[error("unsafe config path {path}: {reason}")]
    UnsafePath { path: PathBuf, reason: String },
    #[error("config input at {path} exceeds the {max_bytes}-byte limit")]
    ConfigTooLarge { path: PathBuf, max_bytes: u64 },
    #[error("valid config backup at {path} requires explicit recovery from revision {revision}")]
    RecoveryRequired { path: PathBuf, revision: u64 },
    #[error("config is busy: lock {path} was not acquired within {timeout_ms}ms")]
    Busy { path: PathBuf, timeout_ms: u64 },
    #[error("legacy config changed after migration (expected {expected}, found {actual})")]
    LegacyDiverged { expected: String, actual: String },
    #[error("unsafe secret-like legacy field at {path}")]
    UnsafeLegacyField { path: String },
    #[error("reserved extension key {key} at {path}")]
    ReservedExtension { path: String, key: String },
    #[error("unknown legacy credential field at {path}")]
    UnknownLegacyCredentialField { path: String },
    #[error("invalid config at {path}: {reason}")]
    InvalidConfig { path: String, reason: String },
    #[error(
        "trust conflict for {address}: config has {config_fingerprint}, known_hosts has {known_hosts_fingerprint}"
    )]
    TrustConflict {
        address: String,
        config_fingerprint: String,
        known_hosts_fingerprint: String,
    },
    #[error("legacy credential source failed for {locator:?}: {source}")]
    CredentialSource {
        locator: LegacyCredentialLocator,
        #[source]
        source: CredentialPortError,
    },
    #[error("invalid credential secret for {locator:?}: {source}")]
    InvalidCredentialSecret {
        locator: LegacyCredentialLocator,
        #[source]
        source: CredentialSecretError,
    },
    #[error("credential store {operation} failed for {credential_id}: {source}")]
    CredentialStore {
        operation: &'static str,
        credential_id: CredentialId,
        #[source]
        source: CredentialPortError,
    },
    #[error("inline and external credentials disagree for {locator:?}")]
    CredentialConflict { locator: LegacyCredentialLocator },
    #[error(
        "legacy credential locators {first:?} and {second:?} collide on keyring account {account}"
    )]
    LegacyCredentialAccountConflict {
        account: String,
        first: Box<LegacyCredentialLocator>,
        second: Box<LegacyCredentialLocator>,
    },
    #[error(
        "legacy credential locator cannot be represented safely in the CLI keyring: {locator:?}"
    )]
    AmbiguousLegacyCredentialAccount { locator: LegacyCredentialLocator },
    #[error("credential id {credential_id} already contains a different secret")]
    CredentialIdConflict { credential_id: CredentialId },
    #[error("credential store did not verify credential {credential_id}")]
    CredentialVerification { credential_id: CredentialId },
    #[error("credential store rejected {kind:?} secret: {source}")]
    CredentialValidation {
        kind: CredentialKind,
        #[source]
        source: CredentialPortError,
    },
    #[error("credential transaction failed and cleanup was incomplete: {source}")]
    CredentialTransactionCleanup {
        #[source]
        source: Box<ConfigError>,
        warnings: Vec<CredentialTransactionWarning>,
    },
    #[error("legacy credential profile {profile_name} in {connection_name} has no resolvable credential")]
    MissingCredential {
        connection_name: String,
        profile_name: String,
    },
    #[error("invalid {kind} identifier: {value}")]
    InvalidIdentifier { kind: &'static str, value: String },
    #[error("connection not found: {connection_id}")]
    MissingConnection { connection_id: ConnectionId },
    #[error("credential profile {profile_name} does not exist on connection {connection_id}")]
    MissingCredentialProfile {
        connection_id: ConnectionId,
        profile_name: String,
    },
    #[error("credential profile anchor belongs to a different config repository")]
    CredentialProfileAnchorRepositoryMismatch,
    #[error(
        "credential profile anchor conflict for {profile_name} on connection {connection_id}: {field} changed"
    )]
    CredentialProfileAnchorConflict {
        connection_id: ConnectionId,
        profile_name: String,
        field: &'static str,
    },
    #[error("master-key fingerprint must be exactly 12 lowercase hexadecimal characters")]
    InvalidMasterKeyFingerprint,
    #[error(
        "connection {connection_id} already has a different master-key fingerprint binding; explicit rebind is required"
    )]
    MasterKeyFingerprintRebindRequired { connection_id: ConnectionId },
    #[error("credential profile {profile_name} is active on connection {connection_id}")]
    ActiveCredentialRemoval {
        connection_id: ConnectionId,
        profile_name: String,
    },
    #[error(
        "fallback credential profile {profile_name} does not exist on connection {connection_id}"
    )]
    MissingFallbackCredentialProfile {
        connection_id: ConnectionId,
        profile_name: String,
    },
    #[error("authenticated binding conflict for connection {connection_id}: {reason}")]
    AuthenticatedBindingConflict {
        connection_id: ConnectionId,
        reason: String,
    },
    #[error("authenticated endpoint aliases connection {connection_id} by {field}")]
    AuthenticatedEndpointAlias {
        connection_id: ConnectionId,
        field: &'static str,
    },
    #[error("authenticated identity conflict: {reason}")]
    AuthenticatedIdentityConflict { reason: String },
    #[error("storage id {storage_id} is already bound to connection {connection_id}")]
    StorageBindingConflict {
        storage_id: String,
        connection_id: ConnectionId,
    },
    #[error(
        "connection {connection_id} binding field {field} requires an explicit verified rebind"
    )]
    BindingChangeRequiresRebind {
        connection_id: ConnectionId,
        field: &'static str,
    },
    #[error("config revision overflow")]
    RevisionOverflow,
    #[error("config revision conflict: expected {expected}, found {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("config contents changed without advancing revision {revision}")]
    ConfigContentConflict { revision: u64 },
    #[error(
        "credential commit outcome for candidate revision {candidate_revision} is ambiguous: {reason}"
    )]
    CredentialCommitAmbiguous {
        candidate_revision: u64,
        reason: String,
    },
    #[error("failed to serialize config: {0}")]
    Serialization(#[source] serde_json::Error),
}
