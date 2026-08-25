use std::cell::Cell;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use data_encoding::HEXLOWER;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

use zann_core::api::auth::KdfParams;
use zann_core::AuthMethod;

#[cfg(feature = "session")]
use super::locking::lock_order_allows;
use super::locking::{
    ensure_config_root, validate_regular_file_if_exists, ConfigFileLockGuard, FileLockGuard,
    LockKind,
};

pub use super::locking::{
    CONFIG_LOCK_FILENAME, CREDENTIAL_OPERATION_LOCK_FILENAME, SYNC_COMMIT_LOCK_FILENAME,
};

pub const CONFIG_SCHEMA_VERSION: u32 = 2;
pub const CONFIG_V2_FILENAME: &str = "client-config.json";
pub const CONFIG_BACKUP_FILENAME: &str = "client-config.backup.json";
pub const CONFIG_RESTORE_JOURNAL_FILENAME: &str = "client-config.restore.json";
pub const CREDENTIAL_TRANSACTION_JOURNAL_FILENAME: &str = "client-config.credential-intent.json";
pub(crate) const AUTH_OPERATION_INTENT_FILENAME: &str = "client-auth.intent.json";
pub const LEGACY_CONFIG_FILENAME: &str = "config.json";
pub const LEGACY_KNOWN_HOSTS_FILENAME: &str = "known_hosts.json";
pub const LOCAL_DB_FILENAME: &str = "local.sqlite";
pub const DESKTOP_SETTINGS_FILENAME: &str = "desktop.json";
pub const REMEMBERED_UNLOCK_FILENAME: &str = "unlock.json";

const CONNECTION_ID_PREFIX: &str = "conn_";
const CREDENTIAL_ID_PREFIX: &str = "cred_";
const LIFECYCLE_CREDENTIAL_ID_PREFIX: &str = "credl_";
const LIFECYCLE_NONCE_HEX_LEN: usize = 32;
const LIFECYCLE_TAG_HEX_LEN: usize = 64;
const RESTORE_JOURNAL_VERSION: u32 = 1;
const CREDENTIAL_TRANSACTION_JOURNAL_VERSION: u32 = 2;
const CREDENTIAL_TRANSACTION_JOURNAL_V1: u32 = 1;
const AUTH_OPERATION_INTENT_V1: u32 = 1;
const AUTH_OPERATION_INTENT_VERSION: u32 = 2;
const LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const CONFIG_MAX_BYTES: u64 = 4 * 1024 * 1024;
const RESTORE_JOURNAL_MAX_BYTES: u64 = 12 * 1024 * 1024;
const CREDENTIAL_TRANSACTION_JOURNAL_MAX_BYTES: u64 = 16 * 1024 * 1024;
const AUTH_OPERATION_INTENT_MAX_BYTES: u64 = 64 * 1024;
const JSON_NODE_LIMIT: usize = 50_000;
const RESTORE_JOURNAL_NODE_LIMIT: usize = 100_000;
const CREDENTIAL_TRANSACTION_JOURNAL_NODE_LIMIT: usize = 175_000;
const AUTH_OPERATION_INTENT_NODE_LIMIT: usize = 256;
const MAX_CONNECTIONS: usize = 256;
const MAX_CLIENTS: usize = 32;
const MAX_PROFILES_TOTAL: usize = 128;
const MAX_CREDENTIAL_SLOTS: usize = 384;
const MAX_KNOWN_HOSTS: usize = 1_024;
const MAX_DEFERRED_FIELDS: usize = 1_024;
const MAX_LEGACY_NAME_LEN: usize = 128;
const MAX_ADDRESS_LEN: usize = 2_048;
const MAX_METADATA_VALUE_LEN: usize = 2_048;
const MAX_CREDENTIAL_SECRET_LEN: usize = 64 * 1024;
const MAX_DEFERRED_PATH_LEN: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientPaths {
    root: PathBuf,
    local_db: PathBuf,
}

impl ClientPaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let local_db = root.join(LOCAL_DB_FILENAME);
        Self { root, local_db }
    }

    pub fn with_local_db(root: impl Into<PathBuf>, local_db: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            local_db: local_db.into(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config(&self) -> PathBuf {
        self.root.join(CONFIG_V2_FILENAME)
    }

    pub fn lock(&self) -> PathBuf {
        LockKind::Config.path_in(&self.root)
    }

    pub fn backup(&self) -> PathBuf {
        self.root.join(CONFIG_BACKUP_FILENAME)
    }

    pub fn restore_journal(&self) -> PathBuf {
        self.root.join(CONFIG_RESTORE_JOURNAL_FILENAME)
    }

    pub fn credential_transaction_journal(&self) -> PathBuf {
        self.root.join(CREDENTIAL_TRANSACTION_JOURNAL_FILENAME)
    }

    pub(crate) fn auth_operation_intent(&self) -> PathBuf {
        self.root.join(AUTH_OPERATION_INTENT_FILENAME)
    }

    pub fn credential_operation_lock(&self) -> PathBuf {
        LockKind::CredentialOperation.path_in(&self.root)
    }

    pub fn sync_commit_lock(&self) -> PathBuf {
        LockKind::SyncCommit.path_in(&self.root)
    }

    #[allow(dead_code)] // Consumed by the auth/session capability.
    pub(crate) fn auth_operation_lock(&self) -> PathBuf {
        LockKind::AuthOperation.path_in(&self.root)
    }

    pub fn legacy_config(&self) -> PathBuf {
        self.root.join(LEGACY_CONFIG_FILENAME)
    }

    pub fn legacy_known_hosts(&self) -> PathBuf {
        self.root.join(LEGACY_KNOWN_HOSTS_FILENAME)
    }

    pub fn local_db(&self) -> PathBuf {
        self.local_db.clone()
    }

    pub fn desktop_settings(&self) -> PathBuf {
        self.root.join(DESKTOP_SETTINGS_FILENAME)
    }

    pub fn remembered_unlock(&self) -> PathBuf {
        self.root.join(REMEMBERED_UNLOCK_FILENAME)
    }
}

macro_rules! string_id {
    ($name:ident, $label:literal, $validator:expr) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ConfigError> {
                let value = value.into();
                if !$validator(&value) {
                    return Err(ConfigError::InvalidIdentifier {
                        kind: $label,
                        value,
                    });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

fn valid_client_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_generated_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 64 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

string_id!(ClientId, "client", valid_client_id);
string_id!(ConnectionId, "connection", |value: &str| {
    valid_generated_id(value, CONNECTION_ID_PREFIX)
});
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CredentialId(String);

impl CredentialId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_serialized(value: String) -> Result<Self, ConfigError> {
        let valid_legacy = valid_generated_id(&value, CREDENTIAL_ID_PREFIX);
        let valid_lifecycle = value
            .strip_prefix(LIFECYCLE_CREDENTIAL_ID_PREFIX)
            .is_some_and(|suffix| {
                suffix.len() == LIFECYCLE_NONCE_HEX_LEN + LIFECYCLE_TAG_HEX_LEN
                    && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
        if !valid_legacy && !valid_lifecycle {
            return Err(ConfigError::InvalidIdentifier {
                kind: "credential",
                value,
            });
        }
        Ok(Self(value))
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl<'de> Deserialize<'de> for CredentialId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_serialized(value).map_err(serde::de::Error::custom)
    }
}

impl ConnectionId {
    pub fn deterministic(legacy_name: &str, address: &str) -> Self {
        Self(format!(
            "{CONNECTION_ID_PREFIX}{}",
            stable_hash(&[b"connection-v2", legacy_name.as_bytes(), address.as_bytes()])
        ))
    }
}

impl CredentialId {
    fn deterministic(
        repository_binding: &[u8],
        source_digest: &str,
        connection_id: &ConnectionId,
        profile_name: &str,
        kind: CredentialKind,
    ) -> Self {
        Self(format!(
            "{CREDENTIAL_ID_PREFIX}{}",
            stable_hash(&[
                b"credential-v2-repository-bound",
                repository_binding,
                source_digest.as_bytes(),
                connection_id.as_str().as_bytes(),
                profile_name.as_bytes(),
                kind.as_str().as_bytes(),
            ])
        ))
    }

    fn fresh(
        repository_root: &Path,
        connection_id: &ConnectionId,
        profile_name: &str,
        kind: CredentialKind,
    ) -> Result<Self, ConfigError> {
        let repository_binding = repository_binding(repository_root)?;
        let nonce_file = tempfile::Builder::new()
            .prefix(".credential-id-")
            .rand_bytes(32)
            .tempfile_in(repository_root)
            .map_err(|source| ConfigError::Io {
                operation: "create credential id nonce",
                path: repository_root.to_path_buf(),
                source,
            })?;
        let nonce_material = nonce_file
            .path()
            .file_name()
            .ok_or_else(|| ConfigError::InvalidConfig {
                path: "$.credentials".to_string(),
                reason: "credential nonce path has no file name".to_string(),
            })?
            .to_string_lossy();
        let nonce_hash = stable_hash(&[
            b"credential-lifecycle-nonce-v1",
            &repository_binding,
            nonce_material.as_bytes(),
        ]);
        let nonce = &nonce_hash[..LIFECYCLE_NONCE_HEX_LEN];
        let tag = lifecycle_credential_tag(
            &repository_binding,
            connection_id,
            profile_name,
            kind,
            nonce,
        );
        Ok(Self(format!(
            "{LIFECYCLE_CREDENTIAL_ID_PREFIX}{nonce}{tag}"
        )))
    }

    fn lifecycle_nonce_and_tag(&self) -> Option<(&str, &str)> {
        let suffix = self.0.strip_prefix(LIFECYCLE_CREDENTIAL_ID_PREFIX)?;
        let (nonce, tag) = suffix.split_at(LIFECYCLE_NONCE_HEX_LEN);
        Some((nonce, tag))
    }

    fn is_bound_lifecycle(
        &self,
        repository_binding: &[u8],
        connection_id: &ConnectionId,
        profile_name: &str,
        kind: CredentialKind,
    ) -> bool {
        let Some((nonce, tag)) = self.lifecycle_nonce_and_tag() else {
            return false;
        };
        lifecycle_credential_tag(repository_binding, connection_id, profile_name, kind, nonce)
            == tag
    }
}

fn lifecycle_credential_tag(
    repository_binding: &[u8],
    connection_id: &ConnectionId,
    profile_name: &str,
    kind: CredentialKind,
    nonce: &str,
) -> String {
    stable_hash(&[
        b"credential-lifecycle-v1",
        repository_binding,
        connection_id.as_str().as_bytes(),
        profile_name.as_bytes(),
        kind.as_str().as_bytes(),
        nonce.as_bytes(),
    ])
}

fn stable_hash(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    HEXLOWER.encode(&hasher.finalize())
}

fn repository_binding(root: &Path) -> Result<Vec<u8>, ConfigError> {
    let canonical = fs::canonicalize(root).map_err(|source| ConfigError::Io {
        operation: "canonicalize config root",
        path: root.to_path_buf(),
        source,
    })?;
    Ok(repository_path_bytes(&canonical))
}

fn credential_profile_anchor_repository_binding(root: &Path) -> Result<String, ConfigError> {
    let repository_binding = repository_binding(root)?;
    Ok(stable_hash(&[
        b"credential-profile-anchor-repository-v1",
        &repository_binding,
    ]))
}

#[cfg(unix)]
fn repository_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn repository_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn repository_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().to_string_lossy().into_owned().into_bytes()
}

fn byte_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", HEXLOWER.encode(&hasher.finalize()))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Access,
    Refresh,
    ServiceAccount,
}

impl CredentialKind {
    fn as_str(self) -> &'static str {
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
    fn empty() -> Self {
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
struct RestoreJournal {
    journal_version: u32,
    source_primary_digest: String,
    source_backup_digest: String,
    target_primary: ConfigV2,
    target_backup: ConfigV2,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialTransactionJournal {
    journal_version: u32,
    source_primary: CredentialGeneration,
    source_backup: Option<CredentialGeneration>,
    candidate: CredentialGeneration,
    new_ids: BTreeSet<CredentialId>,
    retired_slots: BTreeSet<CredentialSlotRef>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    carried_retired_slots: BTreeSet<CredentialSlotRef>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    settled_retired_ids: BTreeSet<CredentialId>,
    #[serde(default)]
    aborted: bool,
    #[serde(default)]
    aborted_after_backup_write: bool,
}

/// A durable, secret-free record of a refresh or logout which may already
/// have changed server state. It deliberately records credential identifiers
/// and config digests only; neither secrets nor secret-derived hashes belong
/// in this file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthOperationIntent {
    journal_version: u32,
    operation_id: String,
    operation: AuthOperationKind,
    state: AuthOperationIntentState,
    repository_binding_digest: String,
    connection_id: ConnectionId,
    profile_name: String,
    endpoint: AuthIntentEndpoint,
    source: AuthIntentSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    candidate_rotation: Option<AuthIntentRotationCandidate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_id: Option<ClientId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reserved_login: Option<AuthIntentLoginReservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    candidate_login: Option<AuthIntentLoginCandidate>,
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
enum AuthOperationIntentState {
    Armed,
    CandidatePrepared,
}

/// Live-process ownership proof for one exact durable auth intent.
///
/// It is intentionally non-`Clone`; transitions verify the digest of the
/// journal bytes before they may replace or clear that journal.
pub(crate) struct AuthOperationIntentPermit {
    anchor: CredentialProfileAnchor,
    operation_id: String,
    operation: AuthOperationKind,
    journal_bytes_digest: String,
}

/// Live-process ownership proof for one exact password-login intent.
///
/// The source may intentionally have no profile, so it cannot reuse the
/// refresh/logout profile permit. Like that permit this value is non-`Clone`
/// and every transition checks the digest of the exact durable bytes.
pub(crate) struct PasswordLoginIntentPermit {
    anchor: PasswordLoginAnchor,
    identity: ConfigIdentity,
    reservation: AuthIntentLoginReservation,
    operation_id: String,
    journal_bytes_digest: String,
    candidate: Option<AuthIntentLoginCandidate>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthIntentEndpoint {
    address: String,
    server_id: String,
    server_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    storage_id: Option<String>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthIntentSource {
    revision: u64,
    raw_digest: String,
    /// Stable authenticated account binding. Older v1 journals omit it and
    /// therefore remain readable but cannot authorize sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_method: Option<AuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_expires_at: Option<String>,
    credentials: BTreeMap<CredentialKind, CredentialId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_active_connection: Option<ConnectionId>,
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
struct AuthIntentRotationCandidate {
    revision: u64,
    raw_digest: String,
    access_expires_at: String,
    access_credential_id: CredentialId,
    refresh_credential_id: CredentialId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthIntentLoginReservation {
    access_credential_id: CredentialId,
    refresh_credential_id: CredentialId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthIntentLoginCandidate {
    revision: u64,
    raw_digest: String,
    account_subject: String,
    auth_method: AuthMethod,
    access_expires_at: String,
    access_credential_id: CredentialId,
    refresh_credential_id: CredentialId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialGeneration {
    revision: u64,
    raw_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    migration_digest: Option<String>,
    slots: BTreeSet<CredentialSlotRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialSlotRef {
    connection_id: ConnectionId,
    profile_name: String,
    kind: CredentialKind,
    credential_id: CredentialId,
}

#[derive(Deserialize)]
struct ConfigVersionProbe {
    #[serde(default)]
    schema_version: Option<u64>,
}

#[derive(Deserialize)]
struct RestoreVersionProbe {
    #[serde(default)]
    journal_version: Option<u64>,
}

#[derive(Deserialize)]
struct CredentialTransactionVersionProbe {
    #[serde(default)]
    journal_version: Option<u64>,
}

#[derive(Deserialize)]
struct AuthOperationIntentVersionProbe {
    #[serde(default)]
    journal_version: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreState {
    Initial,
    BackupWritten,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialTransactionState {
    Initial,
    BackupWritten,
    Committed,
    Cleanup,
}

enum AuthIntentState {
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigIdentity {
    pub kdf_salt: String,
    pub kdf_params: ConfigKdfParams,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigKdfParams {
    pub algorithm: String,
    pub iterations: u32,
    pub memory_kb: u32,
    pub parallelism: u32,
}

impl From<KdfParams> for ConfigKdfParams {
    fn from(params: KdfParams) -> Self {
        Self {
            algorithm: params.algorithm,
            iterations: params.iterations,
            memory_kb: params.memory_kb,
            parallelism: params.parallelism,
        }
    }
}

impl From<ConfigKdfParams> for KdfParams {
    fn from(params: ConfigKdfParams) -> Self {
        Self {
            algorithm: params.algorithm,
            iterations: params.iterations,
            memory_kb: params.memory_kb,
            parallelism: params.parallelism,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_connection: Option<ConnectionId>,
    #[serde(default)]
    namespace: ClientNamespace,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            active_connection: None,
            namespace: ClientNamespace::Empty,
        }
    }
}

impl ClientConfig {
    pub fn active_connection(&self) -> Option<&ConnectionId> {
        self.active_connection.as_ref()
    }

    pub fn namespace(&self) -> &ClientNamespace {
        &self.namespace
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "settings",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ClientNamespace {
    #[default]
    Empty,
    CliV1(CliNamespace),
    DesktopV1(DesktopNamespace),
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CliNamespace {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub default_vault_by_connection: BTreeMap<ConnectionId, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopNamespace {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<DesktopBackupSettings>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopBackupSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_retention_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_max_count: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionConfig {
    metadata: ConnectionMetadata,
    #[serde(default)]
    credential_profiles: BTreeMap<String, CredentialProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_credential: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionMetadata {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub needs_salt_update: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_master_key_fp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_id: Option<String>,
}

impl ConnectionMetadata {
    pub fn new(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            address: address.into(),
            needs_salt_update: false,
            server_id: None,
            server_fingerprint: None,
            expected_master_key_fp: None,
            storage_id: None,
        }
    }
}

fn changed_binding_field(
    previous: &ConnectionMetadata,
    next: &ConnectionMetadata,
) -> Option<&'static str> {
    if previous.address != next.address {
        Some("address")
    } else if previous.server_id != next.server_id {
        Some("server_id")
    } else if previous.server_fingerprint != next.server_fingerprint {
        Some("server_fingerprint")
    } else if previous.expected_master_key_fp != next.expected_master_key_fp {
        Some("expected_master_key_fp")
    } else if previous.storage_id != next.storage_id {
        Some("storage_id")
    } else {
        None
    }
}

fn validate_master_key_fingerprint(target: &str) -> Result<(), ConfigError> {
    if target.len() == 12
        && target
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ConfigError::InvalidMasterKeyFingerprint)
    }
}

// Dormant until the authenticated transport/session owner calls this crate-private foundation.
#[allow(dead_code)]
fn apply_identity_commit(
    config: &mut ConfigV2,
    commit: &IdentityCommit,
) -> Result<(), ConfigError> {
    match commit {
        IdentityCommit::InitializeOrMatch(observed) => match config.identity.as_mut() {
            None => config.identity = Some(observed.clone()),
            Some(stored) => {
                if stored.kdf_salt != observed.kdf_salt || stored.kdf_params != observed.kdf_params
                {
                    return Err(ConfigError::AuthenticatedIdentityConflict {
                        reason: "KDF identity does not match the stored identity".to_string(),
                    });
                }
                enrich_identity_field(
                    "salt_fingerprint",
                    &mut stored.salt_fingerprint,
                    &observed.salt_fingerprint,
                )?;
                enrich_identity_field(
                    "first_seen_at",
                    &mut stored.first_seen_at,
                    &observed.first_seen_at,
                )?;
                enrich_identity_field("email", &mut stored.email, &observed.email)?;
            }
        },
        IdentityCommit::ReplaceExact {
            expected,
            replacement,
        } => {
            let stored = config.identity.as_ref().ok_or_else(|| {
                ConfigError::AuthenticatedIdentityConflict {
                    reason: "cannot replace a missing identity".to_string(),
                }
            })?;
            if stored != expected {
                return Err(ConfigError::AuthenticatedIdentityConflict {
                    reason: "stored identity does not match the expected replacement source"
                        .to_string(),
                });
            }
            config.identity = Some(replacement.clone());
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn enrich_identity_field(
    field: &'static str,
    stored: &mut Option<String>,
    observed: &Option<String>,
) -> Result<(), ConfigError> {
    match (stored.as_ref(), observed.as_ref()) {
        (Some(stored), Some(observed)) if stored != observed => {
            Err(ConfigError::AuthenticatedIdentityConflict {
                reason: format!("identity field {field} does not match"),
            })
        }
        (None, Some(observed)) => {
            *stored = Some(observed.clone());
            Ok(())
        }
        _ => Ok(()),
    }
}

#[allow(dead_code)]
fn apply_authenticated_connection_target(
    config: &mut ConfigV2,
    resolved_connection_id: &ConnectionId,
    target: &AuthenticatedConnectionTarget,
    endpoint: &VerifiedEndpointBinding,
    storage_id: Option<&str>,
) -> Result<(), ConfigError> {
    match target {
        AuthenticatedConnectionTarget::ReplaceFingerprint { expected, .. } => {
            ensure_authenticated_known_host_fingerprint(
                config,
                resolved_connection_id,
                endpoint.address(),
                expected.server_fingerprint(),
            )?;
        }
        _ => ensure_authenticated_known_host_fingerprint(
            config,
            resolved_connection_id,
            endpoint.address(),
            Some(endpoint.server_fingerprint()),
        )?,
    }
    match target {
        AuthenticatedConnectionTarget::Create { connection_name } => {
            ensure_authenticated_endpoint_unique(config, None, endpoint)?;
            if let Some(storage_id) = storage_id {
                ensure_storage_unique(config, None, storage_id)?;
            }
            if config.connections.contains_key(resolved_connection_id) {
                return Err(ConfigError::AuthenticatedEndpointAlias {
                    connection_id: resolved_connection_id.clone(),
                    field: "connection_id",
                });
            }
            let mut metadata = ConnectionMetadata::new(connection_name, endpoint.address());
            metadata.server_id = Some(endpoint.server_id().to_string());
            metadata.server_fingerprint = Some(endpoint.server_fingerprint().to_string());
            metadata.storage_id = storage_id.map(str::to_string);
            config.connections.insert(
                resolved_connection_id.clone(),
                ConnectionConfig::from_metadata(metadata),
            );
            consume_authenticated_known_hosts(config, endpoint.address())?;
            return Ok(());
        }
        AuthenticatedConnectionTarget::UseExisting {
            connection_id,
            expected,
        }
        | AuthenticatedConnectionTarget::PinExisting {
            connection_id,
            expected,
        }
        | AuthenticatedConnectionTarget::ReplaceFingerprint {
            connection_id,
            expected,
        }
        | AuthenticatedConnectionTarget::RelocateEndpoint {
            connection_id,
            expected,
        } => {
            if connection_id != resolved_connection_id {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: resolved_connection_id.clone(),
                    reason: "resolved connection id changed during planning".to_string(),
                });
            }
            let connection = config.connections.get(connection_id).ok_or_else(|| {
                ConfigError::MissingConnection {
                    connection_id: connection_id.clone(),
                }
            })?;
            if StoredConnectionBinding::from_metadata(&connection.metadata) != *expected {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: connection_id.clone(),
                    reason: "stored binding does not match the expected binding".to_string(),
                });
            }
        }
    }

    ensure_authenticated_endpoint_unique(config, Some(resolved_connection_id), endpoint)?;
    if let Some(storage_id) = storage_id {
        ensure_storage_unique(config, Some(resolved_connection_id), storage_id)?;
    }
    let connection = config
        .connections
        .get_mut(resolved_connection_id)
        .ok_or_else(|| ConfigError::MissingConnection {
            connection_id: resolved_connection_id.clone(),
        })?;
    let metadata = &mut connection.metadata;
    let stored_address = normalize_address(
        &metadata.address,
        &format!("$.connections.{resolved_connection_id}.metadata.address"),
    )?;

    match target {
        AuthenticatedConnectionTarget::Create { .. } => unreachable!("create returned above"),
        AuthenticatedConnectionTarget::UseExisting { .. } => {
            require_authenticated_address(resolved_connection_id, &stored_address, endpoint)?;
            require_authenticated_server_id(resolved_connection_id, metadata, endpoint)?;
            if metadata.server_fingerprint.as_deref() != Some(endpoint.server_fingerprint()) {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: resolved_connection_id.clone(),
                    reason: "verified fingerprint does not exactly match the stored fingerprint"
                        .to_string(),
                });
            }
        }
        AuthenticatedConnectionTarget::PinExisting { .. } => {
            require_authenticated_address(resolved_connection_id, &stored_address, endpoint)?;
            if let Some(server_id) = metadata.server_id.as_deref() {
                if server_id != endpoint.server_id() {
                    return Err(ConfigError::AuthenticatedBindingConflict {
                        connection_id: resolved_connection_id.clone(),
                        reason: "pinning cannot replace server_id".to_string(),
                    });
                }
            } else {
                metadata.server_id = Some(endpoint.server_id().to_string());
            }
            if metadata.server_fingerprint.is_some() {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: resolved_connection_id.clone(),
                    reason: "pinning requires a missing stored fingerprint".to_string(),
                });
            }
            metadata.server_fingerprint = Some(endpoint.server_fingerprint().to_string());
        }
        AuthenticatedConnectionTarget::ReplaceFingerprint { .. } => {
            require_authenticated_address(resolved_connection_id, &stored_address, endpoint)?;
            require_authenticated_server_id(resolved_connection_id, metadata, endpoint)?;
            if metadata.server_fingerprint.is_none() {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: resolved_connection_id.clone(),
                    reason: "fingerprint replacement requires an existing fingerprint".to_string(),
                });
            }
            metadata.server_fingerprint = Some(endpoint.server_fingerprint().to_string());
        }
        AuthenticatedConnectionTarget::RelocateEndpoint { .. } => {
            require_authenticated_server_id(resolved_connection_id, metadata, endpoint)?;
            if stored_address == endpoint.address() {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: resolved_connection_id.clone(),
                    reason: "endpoint relocation requires a different canonical address"
                        .to_string(),
                });
            }
            metadata.address = endpoint.address().to_string();
            metadata.server_fingerprint = Some(endpoint.server_fingerprint().to_string());
        }
    }

    if let Some(storage_id) = storage_id {
        match metadata.storage_id.as_deref() {
            None => metadata.storage_id = Some(storage_id.to_string()),
            Some(stored) if stored == storage_id => {}
            Some(_) => {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: resolved_connection_id.clone(),
                    reason: "authenticated storage id does not match the stored binding"
                        .to_string(),
                });
            }
        }
    }
    consume_authenticated_known_hosts(config, endpoint.address())?;
    Ok(())
}

#[allow(dead_code)]
fn require_authenticated_address(
    connection_id: &ConnectionId,
    stored_address: &str,
    endpoint: &VerifiedEndpointBinding,
) -> Result<(), ConfigError> {
    if stored_address != endpoint.address() {
        return Err(ConfigError::AuthenticatedBindingConflict {
            connection_id: connection_id.clone(),
            reason: "verified endpoint address does not match the stored address".to_string(),
        });
    }
    Ok(())
}

#[allow(dead_code)]
fn require_authenticated_server_id(
    connection_id: &ConnectionId,
    metadata: &ConnectionMetadata,
    endpoint: &VerifiedEndpointBinding,
) -> Result<(), ConfigError> {
    if metadata.server_id.as_deref() != Some(endpoint.server_id()) {
        return Err(ConfigError::AuthenticatedBindingConflict {
            connection_id: connection_id.clone(),
            reason: "verified server_id does not exactly match the stored server_id".to_string(),
        });
    }
    Ok(())
}

#[allow(dead_code)]
fn ensure_authenticated_endpoint_unique(
    config: &ConfigV2,
    except: Option<&ConnectionId>,
    endpoint: &VerifiedEndpointBinding,
) -> Result<(), ConfigError> {
    for (connection_id, connection) in &config.connections {
        if except == Some(connection_id) {
            continue;
        }
        let normalized = normalize_address(
            &connection.metadata.address,
            &format!("$.connections.{connection_id}.metadata.address"),
        )?;
        if normalized == endpoint.address() {
            return Err(ConfigError::AuthenticatedEndpointAlias {
                connection_id: connection_id.clone(),
                field: "address",
            });
        }
        if connection.metadata.server_id.as_deref() == Some(endpoint.server_id()) {
            return Err(ConfigError::AuthenticatedEndpointAlias {
                connection_id: connection_id.clone(),
                field: "server_id",
            });
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn ensure_storage_unique(
    config: &ConfigV2,
    except: Option<&ConnectionId>,
    storage_id: &str,
) -> Result<(), ConfigError> {
    for (connection_id, connection) in &config.connections {
        if except != Some(connection_id)
            && connection.metadata.storage_id.as_deref() == Some(storage_id)
        {
            return Err(ConfigError::StorageBindingConflict {
                storage_id: storage_id.to_string(),
                connection_id: connection_id.clone(),
            });
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn ensure_authenticated_known_host_fingerprint(
    config: &ConfigV2,
    connection_id: &ConnectionId,
    endpoint_address: &str,
    expected_fingerprint: Option<&str>,
) -> Result<(), ConfigError> {
    for (address, fingerprint) in &config.legacy_known_hosts {
        let normalized = normalize_address(address, &format!("$.legacy_known_hosts.{address}"))?;
        if normalized == endpoint_address && Some(fingerprint.as_str()) != expected_fingerprint {
            return Err(ConfigError::AuthenticatedBindingConflict {
                connection_id: connection_id.clone(),
                reason: "authenticated trust CAS conflicts with the retained known-host pin"
                    .to_string(),
            });
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn consume_authenticated_known_hosts(
    config: &mut ConfigV2,
    endpoint_address: &str,
) -> Result<(), ConfigError> {
    let matching: Vec<_> = config
        .legacy_known_hosts
        .keys()
        .map(|address| {
            normalize_address(address, &format!("$.legacy_known_hosts.{address}"))
                .map(|normalized| (address.clone(), normalized))
        })
        .collect::<Result<_, _>>()?;
    for (address, normalized) in matching {
        if normalized == endpoint_address {
            config.legacy_known_hosts.remove(&address);
        }
    }
    Ok(())
}

impl ConnectionConfig {
    fn from_metadata(metadata: ConnectionMetadata) -> Self {
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
    account_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_method: Option<AuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_expires_at: Option<String>,
    #[serde(default)]
    credentials: BTreeMap<CredentialKind, CredentialId>,
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
    repository_binding_digest: String,
    source_revision: u64,
    source_digest: String,
    connection_id: ConnectionId,
    profile_name: String,
    normalized_address: String,
    server_id: Option<String>,
    server_fingerprint: Option<String>,
    storage_id: Option<String>,
    expected_master_key_fp: Option<String>,
    master_key_binding_observed: bool,
    account_subject: Option<String>,
    auth_method: Option<AuthMethod>,
    access_expires_at: Option<String>,
    credentials: BTreeMap<CredentialKind, CredentialId>,
}

/// Secret-free, repository-bound source captured before password login.
///
/// Unlike [`CredentialProfileAnchor`], this permits an absent target profile.
/// The connection itself must already exist and carry a complete pinned
/// endpoint binding.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PasswordLoginAnchor {
    repository_binding_digest: String,
    source_revision: u64,
    source_digest: String,
    connection_id: ConnectionId,
    profile_name: String,
    normalized_address: String,
    server_id: String,
    server_fingerprint: String,
    storage_id: Option<String>,
    profile: Option<CredentialProfile>,
    active_profile: Option<String>,
    client_id: ClientId,
    client_present: bool,
    client_active_connection: Option<ConnectionId>,
    identity: Option<ConfigIdentity>,
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

fn resolve_credential_profile_anchor_from_config(
    repository_binding_digest: String,
    source_digest: String,
    config: &ConfigV2,
    connection_id: &ConnectionId,
    profile_name: &str,
) -> Result<CredentialProfileAnchor, ConfigError> {
    let connection =
        config
            .connections
            .get(connection_id)
            .ok_or_else(|| ConfigError::MissingConnection {
                connection_id: connection_id.clone(),
            })?;
    let profile = connection
        .credential_profiles
        .get(profile_name)
        .ok_or_else(|| ConfigError::MissingCredentialProfile {
            connection_id: connection_id.clone(),
            profile_name: profile_name.to_string(),
        })?;
    let normalized_address = normalize_address(
        &connection.metadata.address,
        &format!("$.connections.{connection_id}.metadata.address"),
    )?;
    Ok(CredentialProfileAnchor {
        repository_binding_digest,
        source_revision: config.revision,
        source_digest,
        connection_id: connection_id.clone(),
        profile_name: profile_name.to_string(),
        normalized_address,
        server_id: connection.metadata.server_id.clone(),
        server_fingerprint: connection.metadata.server_fingerprint.clone(),
        storage_id: connection.metadata.storage_id.clone(),
        expected_master_key_fp: connection.metadata.expected_master_key_fp.clone(),
        master_key_binding_observed: true,
        account_subject: profile.account_subject.clone(),
        auth_method: profile.auth_method,
        access_expires_at: profile.access_expires_at.clone(),
        credentials: profile.credentials.clone(),
    })
}

fn resolve_password_login_anchor_from_config(
    repository_binding_digest: String,
    source_digest: String,
    config: &ConfigV2,
    connection_id: &ConnectionId,
    profile_name: &str,
    client_id: &ClientId,
) -> Result<PasswordLoginAnchor, ConfigError> {
    let connection =
        config
            .connections
            .get(connection_id)
            .ok_or_else(|| ConfigError::MissingConnection {
                connection_id: connection_id.clone(),
            })?;
    let normalized_address = normalize_address(
        &connection.metadata.address,
        &format!("$.connections.{connection_id}.metadata.address"),
    )?;
    let server_id =
        connection
            .metadata
            .server_id
            .clone()
            .ok_or_else(|| ConfigError::InvalidConfig {
                path: format!("$.connections.{connection_id}.metadata.server_id"),
                reason: "password login requires an already pinned server id".to_string(),
            })?;
    let server_fingerprint = connection
        .metadata
        .server_fingerprint
        .clone()
        .ok_or_else(|| ConfigError::InvalidConfig {
            path: format!("$.connections.{connection_id}.metadata.server_fingerprint"),
            reason: "password login requires an already pinned server fingerprint".to_string(),
        })?;
    let client = config.clients.get(client_id);
    Ok(PasswordLoginAnchor {
        repository_binding_digest,
        source_revision: config.revision,
        source_digest,
        connection_id: connection_id.clone(),
        profile_name: profile_name.to_string(),
        normalized_address,
        server_id,
        server_fingerprint,
        storage_id: connection.metadata.storage_id.clone(),
        profile: connection.credential_profiles.get(profile_name).cloned(),
        active_profile: connection.active_credential.clone(),
        client_id: client_id.clone(),
        client_present: client.is_some(),
        client_active_connection: client.and_then(|client| client.active_connection.clone()),
        identity: config.identity.clone(),
    })
}

fn ensure_password_login_anchor_matches(
    anchor: &PasswordLoginAnchor,
    expected_repository_binding: &str,
    config: &ConfigV2,
    source_digest: &str,
) -> Result<(), ConfigError> {
    let conflict = |field: &'static str| ConfigError::AuthOperationIntentConflict {
        path: PathBuf::from(AUTH_OPERATION_INTENT_FILENAME),
        reason: format!("password-login source field {field} changed"),
    };
    if anchor.repository_binding_digest != expected_repository_binding {
        return Err(ConfigError::AuthOperationIntentRepositoryMismatch);
    }
    if config.revision < anchor.source_revision {
        return Err(ConfigError::RevisionConflict {
            expected: anchor.source_revision,
            actual: config.revision,
        });
    }
    if config.revision == anchor.source_revision && source_digest != anchor.source_digest {
        return Err(ConfigError::ConfigContentConflict {
            revision: anchor.source_revision,
        });
    }
    let connection = config
        .connections
        .get(&anchor.connection_id)
        .ok_or_else(|| conflict("connection"))?;
    let normalized_address = normalize_address(
        &connection.metadata.address,
        &format!("$.connections.{}.metadata.address", anchor.connection_id),
    )?;
    if normalized_address != anchor.normalized_address {
        return Err(conflict("address"));
    }
    if connection.metadata.server_id.as_deref() != Some(anchor.server_id.as_str()) {
        return Err(conflict("server_id"));
    }
    if connection.metadata.server_fingerprint.as_deref() != Some(anchor.server_fingerprint.as_str())
    {
        return Err(conflict("server_fingerprint"));
    }
    if connection.metadata.storage_id != anchor.storage_id {
        return Err(conflict("storage_id"));
    }
    if connection.credential_profiles.get(&anchor.profile_name) != anchor.profile.as_ref() {
        return Err(conflict("profile"));
    }
    if connection.active_credential != anchor.active_profile {
        return Err(conflict("active_profile"));
    }
    let client = config.clients.get(&anchor.client_id);
    if client.is_some() != anchor.client_present
        || client.and_then(|client| client.active_connection.as_ref())
            != anchor.client_active_connection.as_ref()
    {
        return Err(conflict("client_active_connection"));
    }
    if config.identity != anchor.identity {
        return Err(conflict("identity"));
    }
    Ok(())
}

fn auth_intent_source_anchor(intent: &AuthOperationIntent) -> CredentialProfileAnchor {
    CredentialProfileAnchor {
        repository_binding_digest: intent.repository_binding_digest.clone(),
        source_revision: intent.source.revision,
        source_digest: intent.source.raw_digest.clone(),
        connection_id: intent.connection_id.clone(),
        profile_name: intent.profile_name.clone(),
        normalized_address: intent.endpoint.address.clone(),
        server_id: Some(intent.endpoint.server_id.clone()),
        server_fingerprint: Some(intent.endpoint.server_fingerprint.clone()),
        storage_id: intent.endpoint.storage_id.clone(),
        // Auth intent v1/v2 deliberately does not carry this local
        // cache binding. Reconstructed auth anchors are never accepted by the
        // master-key binder; that method requires a freshly resolved anchor.
        expected_master_key_fp: None,
        master_key_binding_observed: false,
        account_subject: intent.source.account_subject.clone(),
        auth_method: intent.source.auth_method,
        access_expires_at: intent.source.access_expires_at.clone(),
        credentials: intent.source.credentials.clone(),
    }
}

fn credential_profile_anchor_conflict(
    anchor: &CredentialProfileAnchor,
    field: &'static str,
) -> ConfigError {
    ConfigError::CredentialProfileAnchorConflict {
        connection_id: anchor.connection_id.clone(),
        profile_name: anchor.profile_name.clone(),
        field,
    }
}

fn ensure_credential_profile_anchor_matches(
    anchor: &CredentialProfileAnchor,
    repository_binding_digest: &str,
    config: &ConfigV2,
    source_digest: &str,
) -> Result<(), ConfigError> {
    if anchor.repository_binding_digest != repository_binding_digest {
        return Err(ConfigError::CredentialProfileAnchorRepositoryMismatch);
    }
    if config.revision < anchor.source_revision {
        return Err(ConfigError::RevisionConflict {
            expected: anchor.source_revision,
            actual: config.revision,
        });
    }
    if config.revision == anchor.source_revision && source_digest != anchor.source_digest {
        return Err(ConfigError::ConfigContentConflict {
            revision: anchor.source_revision,
        });
    }
    let connection = config
        .connections
        .get(&anchor.connection_id)
        .ok_or_else(|| credential_profile_anchor_conflict(anchor, "connection"))?;
    let normalized_address = normalize_address(
        &connection.metadata.address,
        &format!("$.connections.{}.metadata.address", anchor.connection_id),
    )?;
    if normalized_address != anchor.normalized_address {
        return Err(credential_profile_anchor_conflict(anchor, "address"));
    }
    if connection.metadata.server_id != anchor.server_id {
        return Err(credential_profile_anchor_conflict(anchor, "server_id"));
    }
    if connection.metadata.server_fingerprint != anchor.server_fingerprint {
        return Err(credential_profile_anchor_conflict(
            anchor,
            "server_fingerprint",
        ));
    }
    if connection.metadata.storage_id != anchor.storage_id {
        return Err(credential_profile_anchor_conflict(anchor, "storage_id"));
    }
    let profile = connection
        .credential_profiles
        .get(&anchor.profile_name)
        .ok_or_else(|| credential_profile_anchor_conflict(anchor, "profile"))?;
    if profile.credentials != anchor.credentials {
        return Err(credential_profile_anchor_conflict(anchor, "credentials"));
    }
    if profile.account_subject != anchor.account_subject {
        return Err(credential_profile_anchor_conflict(
            anchor,
            "account_subject",
        ));
    }
    if profile.auth_method != anchor.auth_method {
        return Err(credential_profile_anchor_conflict(anchor, "auth_method"));
    }
    if profile.access_expires_at != anchor.access_expires_at {
        return Err(credential_profile_anchor_conflict(
            anchor,
            "access_expires_at",
        ));
    }
    Ok(())
}

fn apply_credential_bundle_replacement(
    config: &mut ConfigV2,
    connection_id: &ConnectionId,
    profile_name: &str,
    access_expires_at: Option<String>,
    credential_ids: &BTreeMap<CredentialKind, CredentialId>,
    activation: CredentialActivation,
) -> Result<(), ConfigError> {
    let connection = config.connections.get_mut(connection_id).ok_or_else(|| {
        ConfigError::MissingConnection {
            connection_id: connection_id.clone(),
        }
    })?;
    connection.credential_profiles.insert(
        profile_name.to_string(),
        CredentialProfile {
            account_subject: None,
            auth_method: None,
            access_expires_at,
            credentials: credential_ids.clone(),
        },
    );
    if activation == CredentialActivation::MakeActive {
        connection.active_credential = Some(profile_name.to_string());
    }
    Ok(())
}

fn apply_session_credential_rotation(
    config: &mut ConfigV2,
    connection_id: &ConnectionId,
    profile_name: &str,
    access_expires_at: String,
    credential_ids: &BTreeMap<CredentialKind, CredentialId>,
) -> Result<(), ConfigError> {
    if credential_ids.len() != 2
        || !credential_ids.contains_key(&CredentialKind::Access)
        || !credential_ids.contains_key(&CredentialKind::Refresh)
    {
        return Err(ConfigError::InvalidConfig {
            path: "$.session_refresh".to_string(),
            reason: "session rotation must allocate exactly access and refresh credentials"
                .to_string(),
        });
    }
    let connection = config.connections.get_mut(connection_id).ok_or_else(|| {
        ConfigError::MissingConnection {
            connection_id: connection_id.clone(),
        }
    })?;
    let profile = connection
        .credential_profiles
        .get_mut(profile_name)
        .ok_or_else(|| ConfigError::MissingCredentialProfile {
            connection_id: connection_id.clone(),
            profile_name: profile_name.to_string(),
        })?;
    for (kind, credential_id) in credential_ids {
        profile.credentials.insert(*kind, credential_id.clone());
    }
    profile.access_expires_at = Some(access_expires_at);
    Ok(())
}

fn apply_password_login_candidate(
    config: &mut ConfigV2,
    anchor: &PasswordLoginAnchor,
    identity: &ConfigIdentity,
    account_subject: &str,
    access_expires_at: &str,
    credential_ids: &BTreeMap<CredentialKind, CredentialId>,
) -> Result<(), ConfigError> {
    if credential_ids.len() != 2
        || !credential_ids.contains_key(&CredentialKind::Access)
        || !credential_ids.contains_key(&CredentialKind::Refresh)
    {
        return Err(ConfigError::InvalidConfig {
            path: "$.password_login.credentials".to_string(),
            reason: "password login must allocate exactly access and refresh credentials"
                .to_string(),
        });
    }
    validate_required_metadata("$.password_login.account_subject", account_subject)?;
    validate_required_metadata("$.password_login.access_expires_at", access_expires_at)?;
    apply_identity_commit(config, &IdentityCommit::InitializeOrMatch(identity.clone()))?;
    let connection = config
        .connections
        .get_mut(&anchor.connection_id)
        .ok_or_else(|| ConfigError::MissingConnection {
            connection_id: anchor.connection_id.clone(),
        })?;
    let mut credentials = anchor
        .profile
        .as_ref()
        .map(|profile| profile.credentials.clone())
        .unwrap_or_default();
    credentials.insert(
        CredentialKind::Access,
        credential_ids[&CredentialKind::Access].clone(),
    );
    credentials.insert(
        CredentialKind::Refresh,
        credential_ids[&CredentialKind::Refresh].clone(),
    );
    connection.credential_profiles.insert(
        anchor.profile_name.clone(),
        CredentialProfile {
            account_subject: Some(account_subject.to_string()),
            auth_method: Some(AuthMethod::Password),
            access_expires_at: Some(access_expires_at.to_string()),
            credentials,
        },
    );
    connection.active_credential = Some(anchor.profile_name.clone());
    client_entry(config, &anchor.client_id).active_connection = Some(anchor.connection_id.clone());
    Ok(())
}

fn apply_credential_profile_removal(
    config: &mut ConfigV2,
    connection_id: &ConnectionId,
    profile_name: &str,
    active_after: &ActiveCredentialAfterRemoval,
) -> Result<(), ConfigError> {
    let connection = config.connections.get_mut(connection_id).ok_or_else(|| {
        ConfigError::MissingConnection {
            connection_id: connection_id.clone(),
        }
    })?;
    if !connection.credential_profiles.contains_key(profile_name) {
        return Err(ConfigError::MissingCredentialProfile {
            connection_id: connection_id.clone(),
            profile_name: profile_name.to_string(),
        });
    }
    match active_after {
        ActiveCredentialAfterRemoval::RequireInactive => {
            if connection.active_credential.as_deref() == Some(profile_name) {
                return Err(ConfigError::ActiveCredentialRemoval {
                    connection_id: connection_id.clone(),
                    profile_name: profile_name.to_string(),
                });
            }
        }
        ActiveCredentialAfterRemoval::Clear => {
            // A profile selection is intentionally not part of the refresh
            // anchor. If the user selected a different profile while a
            // refresh was in flight, revoking the stale target must preserve
            // that newer selection.
            if connection.active_credential.as_deref() == Some(profile_name) {
                connection.active_credential = None;
            }
        }
        ActiveCredentialAfterRemoval::Activate(fallback) => {
            if fallback == profile_name || !connection.credential_profiles.contains_key(fallback) {
                return Err(ConfigError::MissingFallbackCredentialProfile {
                    connection_id: connection_id.clone(),
                    profile_name: fallback.clone(),
                });
            }
            connection.active_credential = Some(fallback.clone());
        }
    }
    connection.credential_profiles.remove(profile_name);
    Ok(())
}

pub struct CredentialSecret(Zeroizing<String>);

#[derive(Clone, Debug, Error)]
pub enum CredentialSecretError {
    #[error("credential secret must not be empty")]
    Empty,
    #[error("credential secret exceeds the {maximum_bytes}-byte limit")]
    TooLarge { maximum_bytes: usize },
}

impl CredentialSecret {
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialSecretError> {
        let mut value = value.into();
        if value.is_empty() {
            value.zeroize();
            return Err(CredentialSecretError::Empty);
        }
        if value.len() > MAX_CREDENTIAL_SECRET_LEN {
            value.zeroize();
            return Err(CredentialSecretError::TooLarge {
                maximum_bytes: MAX_CREDENTIAL_SECRET_LEN,
            });
        }
        Ok(Self(Zeroizing::new(value)))
    }

    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

pub struct CredentialBundle {
    access: Option<CredentialSecret>,
    refresh: Option<CredentialSecret>,
    service_account: Option<CredentialSecret>,
    access_expires_at: Option<String>,
}

impl CredentialBundle {
    pub fn new(
        access: Option<CredentialSecret>,
        refresh: Option<CredentialSecret>,
        service_account: Option<CredentialSecret>,
    ) -> Self {
        Self {
            access,
            refresh,
            service_account,
            access_expires_at: None,
        }
    }

    pub fn with_access_expires_at(mut self, access_expires_at: Option<String>) -> Self {
        self.access_expires_at = access_expires_at;
        self
    }

    fn slots(&self) -> [(CredentialKind, Option<&CredentialSecret>); 3] {
        [
            (CredentialKind::Access, self.access.as_ref()),
            (CredentialKind::Refresh, self.refresh.as_ref()),
            (
                CredentialKind::ServiceAccount,
                self.service_account.as_ref(),
            ),
        ]
    }

    fn secret(&self, kind: CredentialKind) -> Option<&CredentialSecret> {
        match kind {
            CredentialKind::Access => self.access.as_ref(),
            CredentialKind::Refresh => self.refresh.as_ref(),
            CredentialKind::ServiceAccount => self.service_account.as_ref(),
        }
    }
}

/// Endpoint identity observed by the shared trust transport.
///
/// Construction canonicalizes the endpoint address. The v1 server signature authenticates the
/// server id and timestamp; the fingerprint is unsigned TOFU metadata protected in transit by the
/// shared transport policy and then compared exactly by the repository. Production construction
/// is owned by `remote::trust`; callers must carry its sealed `VerifiedSystemInfo` proof.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct VerifiedEndpointBinding {
    address: String,
    server_id: String,
    server_fingerprint: String,
}

#[allow(dead_code)]
impl VerifiedEndpointBinding {
    pub(crate) fn new(
        address: impl Into<String>,
        server_id: impl Into<String>,
        server_fingerprint: impl Into<String>,
    ) -> Result<Self, ConfigError> {
        let address = address.into();
        let address = normalize_address(&address, "$.authenticated_session.endpoint.address")?;
        let server_id = server_id.into();
        let server_fingerprint = server_fingerprint.into();
        validate_required_metadata("$.authenticated_session.endpoint.server_id", &server_id)?;
        validate_required_metadata(
            "$.authenticated_session.endpoint.server_fingerprint",
            &server_fingerprint,
        )?;
        Ok(Self {
            address,
            server_id,
            server_fingerprint,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        address: impl Into<String>,
        server_id: impl Into<String>,
        server_fingerprint: impl Into<String>,
    ) -> Result<Self, ConfigError> {
        Self::new(address, server_id, server_fingerprint)
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn server_fingerprint(&self) -> &str {
        &self.server_fingerprint
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct StoredConnectionBinding {
    address: String,
    server_id: Option<String>,
    server_fingerprint: Option<String>,
    storage_id: Option<String>,
}

#[allow(dead_code)]
impl StoredConnectionBinding {
    pub(crate) fn new(
        address: impl Into<String>,
        server_id: Option<String>,
        server_fingerprint: Option<String>,
        storage_id: Option<String>,
    ) -> Self {
        Self {
            address: address.into(),
            server_id,
            server_fingerprint,
            storage_id,
        }
    }

    fn from_metadata(metadata: &ConnectionMetadata) -> Self {
        Self {
            address: metadata.address.clone(),
            server_id: metadata.server_id.clone(),
            server_fingerprint: metadata.server_fingerprint.clone(),
            storage_id: metadata.storage_id.clone(),
        }
    }

    pub fn address(&self) -> &str {
        &self.address
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum AuthenticatedConnectionTarget {
    Create {
        connection_name: String,
    },
    UseExisting {
        connection_id: ConnectionId,
        expected: StoredConnectionBinding,
    },
    PinExisting {
        connection_id: ConnectionId,
        expected: StoredConnectionBinding,
    },
    ReplaceFingerprint {
        connection_id: ConnectionId,
        expected: StoredConnectionBinding,
    },
    RelocateEndpoint {
        connection_id: ConnectionId,
        expected: StoredConnectionBinding,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum IdentityCommit {
    InitializeOrMatch(ConfigIdentity),
    ReplaceExact {
        expected: ConfigIdentity,
        replacement: ConfigIdentity,
    },
}

#[allow(dead_code)]
pub(crate) struct AuthenticatedSessionCommit {
    endpoint: VerifiedEndpointBinding,
    storage_id: Option<String>,
    target: AuthenticatedConnectionTarget,
    identity: IdentityCommit,
    client_id: ClientId,
    profile_name: String,
    bundle: CredentialBundle,
    account_binding: Option<(String, AuthMethod)>,
}

#[allow(dead_code)]
impl AuthenticatedSessionCommit {
    pub(crate) fn new(
        endpoint: VerifiedEndpointBinding,
        storage_id: Option<String>,
        target: AuthenticatedConnectionTarget,
        identity: IdentityCommit,
        client_id: ClientId,
        profile_name: impl Into<String>,
        bundle: CredentialBundle,
    ) -> Self {
        Self {
            endpoint,
            storage_id,
            target,
            identity,
            client_id,
            profile_name: profile_name.into(),
            bundle,
            account_binding: None,
        }
    }

    pub(crate) fn with_account_binding(
        mut self,
        account_subject: impl Into<String>,
        auth_method: AuthMethod,
    ) -> Self {
        self.account_binding = Some((account_subject.into(), auth_method));
        self
    }

    pub fn endpoint(&self) -> &VerifiedEndpointBinding {
        &self.endpoint
    }

    pub fn storage_id(&self) -> Option<&str> {
        self.storage_id.as_deref()
    }

    pub fn target(&self) -> &AuthenticatedConnectionTarget {
        &self.target
    }

    pub fn identity(&self) -> &IdentityCommit {
        &self.identity
    }

    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActiveCredentialAfterRemoval {
    RequireInactive,
    Clear,
    Activate(String),
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct AuthenticatedSessionOutcome {
    transaction: CredentialTransactionOutcome,
    connection_id: ConnectionId,
    storage_id: Option<String>,
    profile_name: String,
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
    snapshot: ConfigSnapshot,
    warnings: Vec<CredentialTransactionWarning>,
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
    kind: CredentialPortErrorKind,
    message: String,
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

#[derive(Clone, Debug)]
pub struct ConfigSnapshot {
    config: ConfigV2,
}

impl ConfigSnapshot {
    pub fn config(&self) -> &ConfigV2 {
        &self.config
    }

    pub fn revision(&self) -> u64 {
        self.config.revision
    }

    pub fn into_config(self) -> ConfigV2 {
        self.config
    }
}

/// Opaque, secret-free proof of the exact config generation which authorized
/// one session target.
///
/// The stable target fingerprint deliberately excludes rotating credential
/// ids and access expiry. The anchor and content fingerprints still bind
/// those fields, the exact raw config bytes, and the repository in which they
/// were observed. Callers cannot construct this capability themselves.
#[derive(Eq, PartialEq)]
pub struct AuthorizedTargetGeneration {
    repository_fingerprint: [u8; 32],
    anchor_fingerprint: [u8; 32],
    stable_target_fingerprint: [u8; 32],
    revision_be: [u8; 8],
    content_fingerprint: [u8; 32],
    repository_binding_digest: String,
    source_digest: String,
    connection_id: ConnectionId,
    profile_name: String,
    display_name: String,
    normalized_address: String,
    server_id: Option<String>,
    server_fingerprint: Option<String>,
    storage_id: Option<String>,
    expected_master_key_fp: Option<String>,
    account_subject: Option<String>,
    auth_method: Option<AuthMethod>,
    single_target_topology: bool,
}

impl AuthorizedTargetGeneration {
    pub fn repository_fingerprint(&self) -> &[u8; 32] {
        &self.repository_fingerprint
    }

    pub fn anchor_fingerprint(&self) -> &[u8; 32] {
        &self.anchor_fingerprint
    }

    pub fn stable_target_fingerprint(&self) -> &[u8; 32] {
        &self.stable_target_fingerprint
    }

    pub fn revision(&self) -> u64 {
        u64::from_be_bytes(self.revision_be)
    }

    pub fn revision_be(&self) -> &[u8; 8] {
        &self.revision_be
    }

    pub fn content_fingerprint(&self) -> &[u8; 32] {
        &self.content_fingerprint
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
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

    pub fn expected_master_key_fingerprint(&self) -> Option<&str> {
        self.expected_master_key_fp.as_deref()
    }

    pub fn account_subject(&self) -> Option<&str> {
        self.account_subject.as_deref()
    }

    pub fn auth_method(&self) -> Option<AuthMethod> {
        self.auth_method
    }

    /// Whether this generation proved the temporary single-connection,
    /// single-profile topology required by the global-UUID SQLite schema.
    pub fn single_target_topology(&self) -> bool {
        self.single_target_topology
    }

    #[cfg(all(test, feature = "sync"))]
    pub(crate) fn for_sync_test(
        target: &crate::session::SessionTarget,
        display_name: &str,
        address: &str,
        server_fingerprint: &str,
        storage_id: Option<String>,
        account_subject: Option<String>,
        auth_method: Option<AuthMethod>,
    ) -> Arc<Self> {
        Arc::new(Self {
            repository_fingerprint: [1; 32],
            anchor_fingerprint: [2; 32],
            stable_target_fingerprint: [3; 32],
            revision_be: 1_u64.to_be_bytes(),
            content_fingerprint: [4; 32],
            repository_binding_digest: "sync-test-repository".to_string(),
            source_digest: "sha256:sync-test".to_string(),
            connection_id: target.connection_id().clone(),
            profile_name: target.profile_name().to_string(),
            display_name: display_name.to_string(),
            normalized_address: address.to_string(),
            server_id: Some("sync-test-server".to_string()),
            server_fingerprint: Some(server_fingerprint.to_string()),
            storage_id,
            expected_master_key_fp: Some("000000000000".to_string()),
            account_subject,
            auth_method,
            single_target_topology: true,
        })
    }
}

impl fmt::Debug for AuthorizedTargetGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedTargetGeneration")
            .field("proof", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Non-clone lease which keeps config writers out of one exact local sync
/// commit. The config lock is released after validation; the shared sync gate
/// remains held until this value is dropped.
pub struct SyncCommitLease {
    generation: Arc<AuthorizedTargetGeneration>,
    _sync_commit: FileLockGuard,
}

impl SyncCommitLease {
    pub fn generation(&self) -> &AuthorizedTargetGeneration {
        &self.generation
    }
}

impl fmt::Debug for SyncCommitLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncCommitLease")
            .field("generation", &"<redacted>")
            .finish_non_exhaustive()
    }
}

struct GenerationFingerprint(Sha256);

impl GenerationFingerprint {
    fn new(domain: &'static [u8]) -> Self {
        let mut fingerprint = Self(Sha256::new());
        fingerprint.part(b"domain", domain);
        fingerprint
    }

    fn part(&mut self, label: &'static [u8], value: &[u8]) {
        for part in [label, value] {
            self.0.update(
                u64::try_from(part.len())
                    .expect("generation fingerprint input length fits u64")
                    .to_be_bytes(),
            );
            self.0.update(part);
        }
    }

    fn optional_part(&mut self, label: &'static [u8], value: Option<&str>) {
        match value {
            Some(value) => {
                self.part(label, b"present");
                self.part(b"value", value.as_bytes());
            }
            None => self.part(label, b"absent"),
        }
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

fn authorized_target_generation(
    repository_binding_digest: String,
    source_digest: String,
    raw_config: &[u8],
    config: &ConfigV2,
    connection_id: &ConnectionId,
    profile_name: &str,
) -> Result<AuthorizedTargetGeneration, ConfigError> {
    let anchor = resolve_credential_profile_anchor_from_config(
        repository_binding_digest.clone(),
        source_digest.clone(),
        config,
        connection_id,
        profile_name,
    )?;
    let connection =
        config
            .connections
            .get(connection_id)
            .ok_or_else(|| ConfigError::MissingConnection {
                connection_id: connection_id.clone(),
            })?;
    let single_target_topology =
        config.connections.len() == 1 && connection.credential_profiles().len() == 1;

    let mut repository = GenerationFingerprint::new(b"zann.authorized-target.repository.v1");
    repository.part(b"repository_binding", repository_binding_digest.as_bytes());

    let mut stable = GenerationFingerprint::new(b"zann.authorized-target.stable.v1");
    stable.part(b"connection_id", anchor.connection_id.as_str().as_bytes());
    stable.part(b"profile_name", anchor.profile_name.as_bytes());
    stable.part(b"display_name", connection.metadata.name.as_bytes());
    stable.part(b"address", anchor.normalized_address.as_bytes());
    stable.optional_part(b"server_id", anchor.server_id.as_deref());
    stable.optional_part(b"server_fingerprint", anchor.server_fingerprint.as_deref());
    stable.optional_part(b"storage_id", anchor.storage_id.as_deref());
    stable.optional_part(
        b"expected_master_key_fp",
        anchor.expected_master_key_fp.as_deref(),
    );
    stable.optional_part(b"account_subject", anchor.account_subject.as_deref());
    let auth_method = anchor
        .auth_method
        .map(|method| method.as_i32().to_be_bytes());
    match auth_method.as_ref() {
        Some(method) => {
            stable.part(b"auth_method", b"present");
            stable.part(b"auth_method_value", method);
        }
        None => stable.part(b"auth_method", b"absent"),
    }
    stable.part(
        b"single_target_topology",
        if single_target_topology {
            b"true"
        } else {
            b"false"
        },
    );
    let stable_target_fingerprint = stable.finish();

    let mut content = GenerationFingerprint::new(b"zann.authorized-target.content.v1");
    content.part(b"raw_config", raw_config);
    let content_fingerprint = content.finish();

    let mut exact = GenerationFingerprint::new(b"zann.authorized-target.anchor.v1");
    exact.part(b"stable_target_fingerprint", &stable_target_fingerprint);
    exact.part(b"revision_be", &config.revision.to_be_bytes());
    exact.part(b"content_fingerprint", &content_fingerprint);
    exact.part(
        b"master_key_binding_observed",
        if anchor.master_key_binding_observed {
            b"true"
        } else {
            b"false"
        },
    );
    exact.part(
        b"single_target_topology",
        if single_target_topology {
            b"true"
        } else {
            b"false"
        },
    );
    exact.optional_part(b"access_expires_at", anchor.access_expires_at.as_deref());
    exact.part(
        b"credential_count",
        &u64::try_from(anchor.credentials.len())
            .expect("bounded credential count fits u64")
            .to_be_bytes(),
    );
    for (kind, credential_id) in &anchor.credentials {
        exact.part(b"credential_kind", kind.as_str().as_bytes());
        exact.part(b"credential_id", credential_id.as_str().as_bytes());
    }

    Ok(AuthorizedTargetGeneration {
        repository_fingerprint: repository.finish(),
        anchor_fingerprint: exact.finish(),
        stable_target_fingerprint,
        revision_be: config.revision.to_be_bytes(),
        content_fingerprint,
        repository_binding_digest,
        source_digest,
        connection_id: anchor.connection_id,
        profile_name: anchor.profile_name,
        display_name: connection.metadata.name.clone(),
        normalized_address: anchor.normalized_address,
        server_id: anchor.server_id,
        server_fingerprint: anchor.server_fingerprint,
        storage_id: anchor.storage_id,
        expected_master_key_fp: anchor.expected_master_key_fp,
        account_subject: anchor.account_subject,
        auth_method: anchor.auth_method,
        single_target_topology,
    })
}

/// Result of binding one connection to the master key observed by a resolved profile.
///
/// Both variants carry the exact config generation checked under the repository lock. An
/// idempotent result performs no filesystem write and does not advance the revision.
#[derive(Clone, Debug)]
pub enum MasterKeyFingerprintBindingOutcome {
    Bound(ConfigSnapshot),
    AlreadyBound(ConfigSnapshot),
}

impl MasterKeyFingerprintBindingOutcome {
    pub fn snapshot(&self) -> &ConfigSnapshot {
        match self {
            Self::Bound(snapshot) | Self::AlreadyBound(snapshot) => snapshot,
        }
    }

    pub fn into_snapshot(self) -> ConfigSnapshot {
        match self {
            Self::Bound(snapshot) | Self::AlreadyBound(snapshot) => snapshot,
        }
    }

    pub fn changed(&self) -> bool {
        matches!(self, Self::Bound(_))
    }
}

#[derive(Clone, Debug)]
pub struct ConfigRepository {
    paths: ClientPaths,
}

struct CredentialTransactionPlan {
    journal: CredentialTransactionJournal,
    journal_bytes: Vec<u8>,
    candidate_config: ConfigV2,
    source_primary_bytes: Vec<u8>,
    candidate_bytes: Vec<u8>,
    credential_ids: BTreeMap<CredentialKind, CredentialId>,
    predecessor_journal_bytes: Option<Vec<u8>>,
}

struct CredentialTransactionSource {
    config: ConfigV2,
    source_primary_bytes: Vec<u8>,
    source_backup: Option<(ConfigV2, String)>,
    carried_retired_slots: BTreeSet<CredentialSlotRef>,
    predecessor_journal_bytes: Option<Vec<u8>>,
}

struct CredentialWriteSpec<'a> {
    connection_id: &'a ConnectionId,
    profile_name: &'a str,
    bundle: &'a CredentialBundle,
}

fn ensure_password_login_transaction_source(
    intent: &AuthOperationIntent,
    source: &CredentialTransactionSource,
) -> Result<(), ConfigError> {
    if intent.operation != AuthOperationKind::PasswordLogin
        || source.config.revision != intent.source.revision
        || byte_digest(&source.source_primary_bytes) != intent.source.raw_digest
    {
        return Err(ConfigError::AuthOperationIntentConflict {
            path: PathBuf::from(AUTH_OPERATION_INTENT_FILENAME),
            reason: "password-login credential transaction is not based on its exact armed source"
                .to_string(),
        });
    }
    Ok(())
}

impl ConfigRepository {
    pub fn new(paths: ClientPaths) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &ClientPaths {
        &self.paths
    }

    pub fn initialize(
        &self,
        legacy_client: &ClientId,
        credential_store: &dyn CredentialStore,
        legacy_credentials: &dyn LegacyCredentialSource,
    ) -> Result<ConfigSnapshot, ConfigError> {
        ensure_config_root(self.paths.root())?;
        if validate_regular_file_if_exists(&self.paths.credential_transaction_journal())? {
            let _recovery = self.reconcile_credentials(credential_store)?;
        }
        // Initialization may migrate and publish credentials. Serialize that
        // entire read/port/publish window with every other credential writer;
        // the post-acquire auth-intent barrier is enforced by this helper.
        let _credential_operation = self.credential_operation_lock()?;
        let config_path = self.paths.config();
        let legacy = {
            let _lock = self.exclusive_lock()?;
            if let Some(snapshot) = self.existing_snapshot_for_client(legacy_client)? {
                return Ok(snapshot);
            }
            self.ensure_no_pending_auth_operation_locked()?;
            self.ensure_no_unrecovered_backup()?;
            LegacyInput::read(&self.paths)?
        };

        // Credential backends may prompt the user or cross a process boundary. Do that work
        // without holding the filesystem lock. Deterministic credential ids make an interrupted
        // attempt safe to retry; the v2 file is not published until every secret is read back.
        let mut config = if legacy.has_sources() {
            migrate_legacy(
                &legacy,
                legacy_client,
                credential_store,
                legacy_credentials,
                &self.paths,
            )?
        } else {
            let mut config = ConfigV2::empty();
            config.migration = Some(MigrationStamp {
                source_format: "legacy-v1".to_string(),
                source_digest: legacy.digest.clone(),
                claimed_clients: BTreeSet::from([legacy_client.clone()]),
                deferred_legacy_fields: BTreeSet::new(),
            });
            config
        };

        let _lock = self.exclusive_lock()?;
        if let Some(snapshot) = self.existing_snapshot_for_client(legacy_client)? {
            return Ok(snapshot);
        }
        self.ensure_no_pending_auth_operation_locked()?;
        self.ensure_no_unrecovered_backup()?;
        let actual_digest = LegacyInput::read(&self.paths)?.digest;
        if legacy.digest != actual_digest {
            return Err(ConfigError::LegacyDiverged {
                expected: legacy.digest,
                actual: actual_digest,
            });
        }

        config.revision = 0;
        let bytes = serialize_config(&config)?;
        atomic_write(&config_path, &bytes)?;
        Ok(ConfigSnapshot { config })
    }

    fn existing_snapshot_for_client(
        &self,
        legacy_client: &ClientId,
    ) -> Result<Option<ConfigSnapshot>, ConfigError> {
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Ok(None);
        }
        let previous_bytes = read_file(&primary_path, "read config")?;
        let mut config = parse_config(&primary_path, &previous_bytes)?;
        let should_claim = config
            .migration
            .as_ref()
            .is_some_and(|migration| !migration.claimed_clients.contains(legacy_client));
        if !should_claim {
            self.ensure_legacy_unchanged(&config)?;
            return Ok(Some(ConfigSnapshot { config }));
        }
        self.ensure_no_pending_auth_operation_locked()?;

        let legacy = LegacyInput::read(&self.paths)?;
        let expected_digest = config
            .migration
            .as_ref()
            .map(|migration| migration.source_digest.clone())
            .ok_or_else(|| ConfigError::InvalidConfig {
                path: "$.migration".to_string(),
                reason: "migration stamp disappeared during client claim".to_string(),
            })?;
        if expected_digest != legacy.digest {
            return Err(ConfigError::LegacyDiverged {
                expected: expected_digest,
                actual: legacy.digest,
            });
        }

        if config
            .clients
            .get(legacy_client)
            .and_then(|client| client.active_connection.as_ref())
            .is_none()
        {
            if let Some(active_connection) = legacy.active_connection_id(&self.paths)? {
                if !config.connections.contains_key(&active_connection) {
                    return Err(ConfigError::MissingConnection {
                        connection_id: active_connection,
                    });
                }
                client_entry(&mut config, legacy_client).active_connection =
                    Some(active_connection);
            }
        }
        if let Some(migration) = config.migration.as_mut() {
            migration.claimed_clients.insert(legacy_client.clone());
        }
        config.revision = config
            .revision
            .checked_add(1)
            .ok_or(ConfigError::RevisionOverflow)?;
        let next_bytes = serialize_config(&config)?;
        atomic_write(&self.paths.backup(), &previous_bytes)?;
        atomic_write(&primary_path, &next_bytes)?;
        Ok(Some(ConfigSnapshot { config }))
    }

    fn ensure_no_unrecovered_backup(&self) -> Result<(), ConfigError> {
        let backup_path = self.paths.backup();
        if !validate_regular_file_if_exists(&backup_path)? {
            return Ok(());
        }
        let bytes = read_file(&backup_path, "read config backup")?;
        let backup = parse_config(&backup_path, &bytes)?;
        Err(ConfigError::RecoveryRequired {
            path: backup_path,
            revision: backup.revision,
        })
    }

    pub fn snapshot(&self) -> Result<ConfigSnapshot, ConfigError> {
        let _lock = self.exclusive_lock()?;
        let config = self.read_primary()?;
        self.ensure_legacy_unchanged(&config)?;
        Ok(ConfigSnapshot { config })
    }

    /// Resolves a repository-bound, secret-free CAS anchor for a specific profile.
    ///
    /// Callers may use the credential ids to perform a network refresh, then submit the anchor to
    /// [`Self::replace_credential_bundle_if_profile_matches`]. Unrelated config mutations may
    /// advance the global revision while the network request is in flight.
    pub fn resolve_credential_profile_anchor(
        &self,
        connection_id: &ConnectionId,
        profile_name: impl Into<String>,
    ) -> Result<CredentialProfileAnchor, ConfigError> {
        let profile_name = profile_name.into();
        validate_string_len(
            "$.connections.*.credential_profiles.<name>",
            &profile_name,
            MAX_LEGACY_NAME_LEN,
        )?;
        let _lock = self.exclusive_lock()?;
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Err(ConfigError::MissingConfig { path: primary_path });
        }
        let source_primary_bytes = read_file(&primary_path, "read config for profile anchor")?;
        let config = parse_config(&primary_path, &source_primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        resolve_credential_profile_anchor_from_config(
            credential_profile_anchor_repository_binding(self.paths.root())?,
            byte_digest(&source_primary_bytes),
            &config,
            connection_id,
            &profile_name,
        )
    }

    /// Captures an authorization proof from the exact, unre-based source
    /// anchor used to read a stored credential.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn authorized_target_generation_from_anchor(
        &self,
        anchor: &CredentialProfileAnchor,
    ) -> Result<Arc<AuthorizedTargetGeneration>, ConfigError> {
        let _lock = self.exclusive_lock()?;
        self.ensure_no_pending_sync_generation_recovery_locked()?;
        let primary_path = self.paths.config();
        let primary_bytes = read_file(&primary_path, "authorize stored session generation")?;
        let config = parse_config(&primary_path, &primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        let repository_binding = credential_profile_anchor_repository_binding(self.paths.root())?;
        let source_digest = byte_digest(&primary_bytes);
        if config.revision != anchor.source_revision {
            return Err(ConfigError::RevisionConflict {
                expected: anchor.source_revision,
                actual: config.revision,
            });
        }
        if source_digest != anchor.source_digest {
            return Err(ConfigError::ConfigContentConflict {
                revision: anchor.source_revision,
            });
        }
        ensure_credential_profile_anchor_matches(
            anchor,
            &repository_binding,
            &config,
            &source_digest,
        )?;
        Ok(Arc::new(authorized_target_generation(
            repository_binding,
            source_digest,
            &primary_bytes,
            &config,
            &anchor.connection_id,
            &anchor.profile_name,
        )?))
    }

    /// Captures an authorization proof from the exact config candidate
    /// returned by a credential transaction or its recovery.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn authorized_target_generation_from_snapshot(
        &self,
        snapshot: &ConfigSnapshot,
        connection_id: &ConnectionId,
        profile_name: &str,
    ) -> Result<Arc<AuthorizedTargetGeneration>, ConfigError> {
        let expected_bytes = serialize_config(snapshot.config())?;
        let _lock = self.exclusive_lock()?;
        self.ensure_no_pending_sync_generation_recovery_locked()?;
        let primary_path = self.paths.config();
        let primary_bytes = read_file(&primary_path, "authorize credential candidate generation")?;
        if primary_bytes != expected_bytes {
            let actual = parse_config(&primary_path, &primary_bytes)?;
            if actual.revision != snapshot.revision() {
                return Err(ConfigError::RevisionConflict {
                    expected: snapshot.revision(),
                    actual: actual.revision,
                });
            }
            return Err(ConfigError::ConfigContentConflict {
                revision: snapshot.revision(),
            });
        }
        let config = parse_config(&primary_path, &primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        let repository_binding = credential_profile_anchor_repository_binding(self.paths.root())?;
        let source_digest = byte_digest(&primary_bytes);
        Ok(Arc::new(authorized_target_generation(
            repository_binding,
            source_digest,
            &primary_bytes,
            &config,
            connection_id,
            profile_name,
        )?))
    }

    /// Acquires the shared sync gate and validates an exact authorization
    /// generation under the config lock. The returned non-clone lease keeps
    /// config writers blocked while a local transaction commits.
    #[cfg(feature = "session")]
    pub async fn acquire_sync_commit_lease(
        &self,
        generation: &Arc<AuthorizedTargetGeneration>,
    ) -> Result<SyncCommitLease, ConfigError> {
        debug_assert!(lock_order_allows(LockKind::SyncCommit, LockKind::Config));
        let sync_commit = LockKind::SyncCommit
            .pending_at(self.paths.root())?
            .acquire_async(LOCK_TIMEOUT)
            .await?;
        let config_lock = match LockKind::Config
            .pending_at(self.paths.root())?
            .acquire_async(LOCK_TIMEOUT)
            .await
        {
            Ok(lock) => lock,
            Err(error) => {
                drop(sync_commit);
                return Err(error);
            }
        };

        let validation = (|| {
            self.ensure_no_pending_sync_generation_recovery_locked()?;
            let primary_path = self.paths.config();
            let primary_bytes = read_file(&primary_path, "validate sync commit generation")?;
            let config = parse_config(&primary_path, &primary_bytes)?;
            self.ensure_legacy_unchanged(&config)?;
            let repository_binding =
                credential_profile_anchor_repository_binding(self.paths.root())?;
            if repository_binding != generation.repository_binding_digest {
                return Err(ConfigError::CredentialProfileAnchorRepositoryMismatch);
            }
            if config.revision != generation.revision() {
                return Err(ConfigError::RevisionConflict {
                    expected: generation.revision(),
                    actual: config.revision,
                });
            }
            let source_digest = byte_digest(&primary_bytes);
            if source_digest != generation.source_digest {
                return Err(ConfigError::ConfigContentConflict {
                    revision: generation.revision(),
                });
            }
            let current = authorized_target_generation(
                repository_binding,
                source_digest,
                &primary_bytes,
                &config,
                &generation.connection_id,
                &generation.profile_name,
            )?;
            if current != **generation {
                return Err(ConfigError::CredentialProfileAnchorConflict {
                    connection_id: generation.connection_id.clone(),
                    profile_name: generation.profile_name.clone(),
                    field: "authorized_generation",
                });
            }
            self.ensure_no_pending_sync_generation_recovery_locked()
        })();
        drop(config_lock);
        if let Err(error) = validation {
            drop(sync_commit);
            return Err(error);
        }
        Ok(SyncCommitLease {
            generation: Arc::clone(generation),
            _sync_commit: sync_commit,
        })
    }

    /// Binds the anchored connection to one exact local master-key fingerprint.
    ///
    /// This is a metadata-only compare-and-swap. It performs no credential-store or network
    /// operation, rebases over unrelated higher revisions, and refuses to replace any existing
    /// different binding. A caller that intentionally changes master keys must use a separate,
    /// explicit rebind/reset workflow.
    pub fn bind_expected_master_key_fingerprint_if_profile_matches(
        &self,
        anchor: &CredentialProfileAnchor,
        target_fp: impl Into<String>,
    ) -> Result<MasterKeyFingerprintBindingOutcome, ConfigError> {
        let target_fp = target_fp.into();
        validate_master_key_fingerprint(&target_fp)?;

        let _lock = self.exclusive_lock()?;
        self.ensure_no_pending_auth_operation_locked()?;
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Err(ConfigError::MissingConfig { path: primary_path });
        }
        let source_primary_bytes =
            read_file(&primary_path, "read config for master-key fingerprint bind")?;
        let mut config = parse_config(&primary_path, &source_primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        ensure_credential_profile_anchor_matches(
            anchor,
            &credential_profile_anchor_repository_binding(self.paths.root())?,
            &config,
            &byte_digest(&source_primary_bytes),
        )?;
        if !anchor.master_key_binding_observed {
            return Err(credential_profile_anchor_conflict(
                anchor,
                "expected_master_key_fp",
            ));
        }

        let current_fp = config
            .connections
            .get(&anchor.connection_id)
            .ok_or_else(|| credential_profile_anchor_conflict(anchor, "connection"))?
            .metadata
            .expected_master_key_fp
            .clone();
        if current_fp != anchor.expected_master_key_fp {
            return Err(credential_profile_anchor_conflict(
                anchor,
                "expected_master_key_fp",
            ));
        }

        match current_fp {
            Some(current) if current == target_fp => Ok(
                MasterKeyFingerprintBindingOutcome::AlreadyBound(ConfigSnapshot { config }),
            ),
            Some(_) => Err(ConfigError::MasterKeyFingerprintRebindRequired {
                connection_id: anchor.connection_id.clone(),
            }),
            None => {
                config
                    .connections
                    .get_mut(&anchor.connection_id)
                    .expect("anchored connection was checked above")
                    .metadata
                    .expected_master_key_fp = Some(target_fp);
                config.revision = config
                    .revision
                    .checked_add(1)
                    .ok_or(ConfigError::RevisionOverflow)?;
                let candidate_bytes = serialize_config(&config)?;
                atomic_write(&self.paths.backup(), &source_primary_bytes)?;
                atomic_write(&primary_path, &candidate_bytes)?;
                Ok(MasterKeyFingerprintBindingOutcome::Bound(ConfigSnapshot {
                    config,
                }))
            }
        }
    }

    /// Resolves the existing pinned target for a password-login flow.
    ///
    /// The connection must already exist and be fully pinned. The named
    /// credential profile may be present or absent; this API never creates,
    /// pins, relocates or rebinds a connection.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn resolve_password_login_anchor(
        &self,
        connection_id: &ConnectionId,
        profile_name: impl Into<String>,
        client_id: &ClientId,
    ) -> Result<PasswordLoginAnchor, ConfigError> {
        let profile_name = profile_name.into();
        validate_string_len(
            "$.connections.*.credential_profiles.<name>",
            &profile_name,
            MAX_LEGACY_NAME_LEN,
        )?;
        if profile_name.is_empty() {
            return Err(ConfigError::InvalidConfig {
                path: "$.password_login.profile_name".to_string(),
                reason: "password-login profile name must not be empty".to_string(),
            });
        }
        let _lock = self.exclusive_lock()?;
        self.ensure_no_pending_auth_operation_locked()?;
        let primary_path = self.paths.config();
        let primary_bytes = read_file(&primary_path, "read config for password-login anchor")?;
        let config = parse_config(&primary_path, &primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        resolve_password_login_anchor_from_config(
            credential_profile_anchor_repository_binding(self.paths.root())?,
            byte_digest(&primary_bytes),
            &config,
            connection_id,
            &profile_name,
            client_id,
        )
    }

    /// Reserves a fresh credential pair and durably arms exactly one password
    /// login dispatch. The caller holds auth then credential operation locks.
    /// No credential-store call occurs while the config lock is held.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn prepare_password_login_intent_with_operation_locks(
        &self,
        anchor: &PasswordLoginAnchor,
        endpoint: &VerifiedEndpointBinding,
        identity: ConfigIdentity,
        operation_id: &str,
        credential_store: &dyn CredentialStore,
    ) -> Result<PasswordLoginIntentPermit, ConfigError> {
        validate_string_len("$.authentication_intent.operation_id", operation_id, 128)?;
        if operation_id.is_empty() {
            return Err(ConfigError::InvalidConfig {
                path: "$.authentication_intent.operation_id".to_string(),
                reason: "authentication operation id must not be empty".to_string(),
            });
        }
        if endpoint.address() != anchor.normalized_address
            || endpoint.server_id() != anchor.server_id
            || endpoint.server_fingerprint() != anchor.server_fingerprint
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "verified endpoint does not match the pinned login target".to_string(),
            });
        }

        let reservation = AuthIntentLoginReservation {
            access_credential_id: CredentialId::fresh(
                self.paths.root(),
                &anchor.connection_id,
                &anchor.profile_name,
                CredentialKind::Access,
            )?,
            refresh_credential_id: CredentialId::fresh(
                self.paths.root(),
                &anchor.connection_id,
                &anchor.profile_name,
                CredentialKind::Refresh,
            )?,
        };
        let reserved_ids = BTreeMap::from([
            (
                CredentialKind::Access,
                reservation.access_credential_id.clone(),
            ),
            (
                CredentialKind::Refresh,
                reservation.refresh_credential_id.clone(),
            ),
        ]);
        preflight_credential_slots(credential_store, &reserved_ids)?;

        let _lock = self.exclusive_lock()?;
        let path = self.paths.auth_operation_intent();
        if validate_regular_file_if_exists(&path)? {
            return Err(ConfigError::AuthOperationRecoveryRequired { path });
        }
        let primary_path = self.paths.config();
        let primary_bytes = read_file(&primary_path, "rebase password-login source")?;
        let config = parse_config(&primary_path, &primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        let repository_binding = credential_profile_anchor_repository_binding(self.paths.root())?;
        ensure_password_login_anchor_matches(
            anchor,
            &repository_binding,
            &config,
            &byte_digest(&primary_bytes),
        )?;
        let source_anchor = resolve_password_login_anchor_from_config(
            repository_binding.clone(),
            byte_digest(&primary_bytes),
            &config,
            &anchor.connection_id,
            &anchor.profile_name,
            &anchor.client_id,
        )?;
        let mut identity_candidate = config.clone();
        apply_identity_commit(
            &mut identity_candidate,
            &IdentityCommit::InitializeOrMatch(identity.clone()),
        )?;
        let source_profile = source_anchor.profile.as_ref();
        let intent = AuthOperationIntent {
            journal_version: AUTH_OPERATION_INTENT_VERSION,
            operation_id: operation_id.to_string(),
            operation: AuthOperationKind::PasswordLogin,
            state: AuthOperationIntentState::Armed,
            repository_binding_digest: repository_binding,
            connection_id: source_anchor.connection_id.clone(),
            profile_name: source_anchor.profile_name.clone(),
            endpoint: AuthIntentEndpoint {
                address: source_anchor.normalized_address.clone(),
                server_id: source_anchor.server_id.clone(),
                server_fingerprint: source_anchor.server_fingerprint.clone(),
                storage_id: source_anchor.storage_id.clone(),
            },
            source: AuthIntentSource {
                revision: source_anchor.source_revision,
                raw_digest: source_anchor.source_digest.clone(),
                account_subject: source_profile.and_then(|profile| profile.account_subject.clone()),
                auth_method: source_profile.and_then(|profile| profile.auth_method),
                access_expires_at: source_profile
                    .and_then(|profile| profile.access_expires_at.clone()),
                credentials: source_profile
                    .map(|profile| profile.credentials.clone())
                    .unwrap_or_default(),
                profile_present: Some(source_profile.is_some()),
                client_present: Some(source_anchor.client_present),
                active_profile: source_anchor.active_profile.clone(),
                client_active_connection: source_anchor.client_active_connection.clone(),
            },
            candidate_rotation: None,
            client_id: Some(source_anchor.client_id.clone()),
            reserved_login: Some(reservation.clone()),
            candidate_login: None,
        };
        let bytes = serialize_auth_operation_intent(&intent, self.paths.root())?;
        atomic_write(&path, &bytes)?;
        Ok(PasswordLoginIntentPermit {
            anchor: source_anchor,
            identity,
            reservation,
            operation_id: operation_id.to_string(),
            journal_bytes_digest: byte_digest(&bytes),
            candidate: None,
        })
    }

    /// Durably records that a refresh or logout may be dispatched next.
    ///
    /// The caller must already hold the repository's authentication and
    /// credential operation locks, in that order. The returned anchor is the
    /// exact source generation captured by the durable intent and must replace
    /// any older, equivalent anchor held by the caller.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn prepare_auth_operation_intent_with_operation_locks(
        &self,
        anchor: &CredentialProfileAnchor,
        operation: AuthOperationKind,
        operation_id: &str,
    ) -> Result<AuthOperationIntentPermit, ConfigError> {
        validate_string_len("$.authentication_intent.operation_id", operation_id, 128)?;
        if operation_id.is_empty() {
            return Err(ConfigError::InvalidConfig {
                path: "$.authentication_intent.operation_id".to_string(),
                reason: "authentication operation id must not be empty".to_string(),
            });
        }
        let _lock = self.exclusive_lock()?;
        let path = self.paths.auth_operation_intent();
        if validate_regular_file_if_exists(&path)? {
            return Err(ConfigError::AuthOperationRecoveryRequired { path });
        }
        let primary_path = self.paths.config();
        let primary_bytes = read_file(&primary_path, "read config for authentication intent")?;
        let config = parse_config(&primary_path, &primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        let source_digest = byte_digest(&primary_bytes);
        ensure_credential_profile_anchor_matches(
            anchor,
            &credential_profile_anchor_repository_binding(self.paths.root())?,
            &config,
            &source_digest,
        )?;
        let source_anchor = resolve_credential_profile_anchor_from_config(
            credential_profile_anchor_repository_binding(self.paths.root())?,
            source_digest.clone(),
            &config,
            &anchor.connection_id,
            &anchor.profile_name,
        )?;
        let server_id =
            source_anchor
                .server_id
                .clone()
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: "$.authentication_intent.endpoint.server_id".to_string(),
                    reason: "authenticated operation requires a pinned server id".to_string(),
                })?;
        let server_fingerprint =
            source_anchor
                .server_fingerprint
                .clone()
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: "$.authentication_intent.endpoint.server_fingerprint".to_string(),
                    reason: "authenticated operation requires a pinned server fingerprint"
                        .to_string(),
                })?;
        if operation == AuthOperationKind::Refresh
            && !source_anchor
                .credentials
                .contains_key(&CredentialKind::Refresh)
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.authentication_intent.source.credentials.refresh".to_string(),
                reason: "refresh operation requires a refresh credential".to_string(),
            });
        }
        let intent = AuthOperationIntent {
            journal_version: AUTH_OPERATION_INTENT_V1,
            operation_id: operation_id.to_string(),
            operation,
            state: AuthOperationIntentState::Armed,
            repository_binding_digest: source_anchor.repository_binding_digest.clone(),
            connection_id: source_anchor.connection_id.clone(),
            profile_name: source_anchor.profile_name.clone(),
            endpoint: AuthIntentEndpoint {
                address: source_anchor.normalized_address.clone(),
                server_id,
                server_fingerprint,
                storage_id: source_anchor.storage_id.clone(),
            },
            source: AuthIntentSource {
                revision: source_anchor.source_revision,
                raw_digest: source_digest,
                account_subject: source_anchor.account_subject.clone(),
                auth_method: source_anchor.auth_method,
                access_expires_at: source_anchor.access_expires_at.clone(),
                credentials: source_anchor.credentials.clone(),
                profile_present: None,
                client_present: None,
                active_profile: None,
                client_active_connection: None,
            },
            candidate_rotation: None,
            client_id: None,
            reserved_login: None,
            candidate_login: None,
        };
        let bytes = serialize_auth_operation_intent(&intent, self.paths.root())?;
        atomic_write(&path, &bytes)?;
        Ok(AuthOperationIntentPermit {
            // The auth-intent wire format intentionally predates the
            // local master-key binding. Normalize the in-process permit to the
            // exact anchor that can be reconstructed from that durable wire
            // document; the master-key binder only accepts freshly resolved
            // public anchors and performs its own exact field check.
            anchor: auth_intent_source_anchor(&intent),
            operation_id: operation_id.to_string(),
            operation,
            journal_bytes_digest: byte_digest(&bytes),
        })
    }

    /// Reconciles a possibly interrupted auth operation while the caller holds
    /// authentication then credential operation locks.
    ///
    /// Credential-journal recovery always runs first. An exact committed
    /// rotation is preserved, an already-removed target is accepted, and an
    /// exact source is revoked through the normal journaled credential path.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn reconcile_auth_operation_with_operation_locks(
        &self,
        credential_store: &dyn CredentialStore,
    ) -> Result<
        (
            CredentialTransactionOutcome,
            AuthOperationRecoveryDisposition,
        ),
        ConfigError,
    > {
        // Validate and repository-bind the auth intent before credential
        // recovery is allowed to touch the store. Malformed, future or copied
        // intents therefore fail closed with zero credential-port calls.
        let preflight_intent_bytes = {
            let _lock = self.exclusive_lock_allow_credential_journal()?;
            self.pending_auth_operation_intent_locked()?
                .map(|(_, bytes)| bytes)
        };
        let mut reconciled = self.reconcile_credentials_with_operation_lock(credential_store)?;
        let classification = {
            let _lock = self.exclusive_lock_allow_credential_journal()?;
            let Some((intent, bytes)) = self.pending_auth_operation_intent_locked()? else {
                if preflight_intent_bytes.is_some() {
                    return Err(ConfigError::AuthOperationIntentConflict {
                        path: self.paths.auth_operation_intent(),
                        reason: "authentication intent disappeared during credential recovery"
                            .to_string(),
                    });
                }
                return Ok((reconciled, AuthOperationRecoveryDisposition::NoIntent));
            };
            if preflight_intent_bytes.as_deref() != Some(bytes.as_slice()) {
                return Err(ConfigError::AuthOperationIntentConflict {
                    path: self.paths.auth_operation_intent(),
                    reason: "authentication intent changed during credential recovery".to_string(),
                });
            }
            self.classify_auth_operation_intent_locked(&intent)?
        };

        match classification {
            AuthIntentState::Source(anchor) => {
                let permit = {
                    let _lock = self.exclusive_lock_allow_credential_journal()?;
                    let Some((intent, bytes)) = self.pending_auth_operation_intent_locked()? else {
                        return Ok((reconciled, AuthOperationRecoveryDisposition::NoIntent));
                    };
                    if !matches!(
                        self.classify_auth_operation_intent_locked(&intent)?,
                        AuthIntentState::Source(current) if current == anchor
                    ) {
                        return Err(ConfigError::AuthOperationIntentConflict {
                            path: self.paths.auth_operation_intent(),
                            reason: "authentication source changed during recovery".to_string(),
                        });
                    }
                    AuthOperationIntentPermit {
                        anchor: (*anchor).clone(),
                        operation_id: intent.operation_id,
                        operation: intent.operation,
                        journal_bytes_digest: byte_digest(&bytes),
                    }
                };
                let mut revoked = self
                    .remove_credential_profile_after_auth_intent_with_operation_locks(
                        &permit,
                        ActiveCredentialAfterRemoval::Clear,
                        credential_store,
                    )?;
                let mut warnings = std::mem::take(&mut reconciled.warnings);
                warnings.append(&mut revoked.warnings);
                revoked.warnings = warnings;
                Ok((revoked, AuthOperationRecoveryDisposition::SourceRevoked))
            }
            AuthIntentState::LoginSource => {
                let _lock = self.exclusive_lock_allow_credential_journal()?;
                let Some((intent, bytes)) = self.pending_auth_operation_intent_locked()? else {
                    return Err(ConfigError::AuthOperationIntentConflict {
                        path: self.paths.auth_operation_intent(),
                        reason: "password-login intent disappeared before abandonment".to_string(),
                    });
                };
                if !matches!(
                    self.classify_auth_operation_intent_locked(&intent)?,
                    AuthIntentState::LoginSource
                ) {
                    return Err(ConfigError::AuthOperationIntentConflict {
                        path: self.paths.auth_operation_intent(),
                        reason: "password-login source changed during abandonment".to_string(),
                    });
                }
                self.remove_auth_operation_intent_locked(&bytes)?;
                Ok((reconciled, AuthOperationRecoveryDisposition::LoginAbandoned))
            }
            state @ (AuthIntentState::Candidate | AuthIntentState::TargetRemoved) => {
                let disposition = match state {
                    AuthIntentState::Candidate => {
                        AuthOperationRecoveryDisposition::CandidatePreserved
                    }
                    AuthIntentState::TargetRemoved => {
                        AuthOperationRecoveryDisposition::TargetRemoved
                    }
                    AuthIntentState::Source(_) | AuthIntentState::LoginSource => {
                        unreachable!("matched above")
                    }
                };
                let _lock = self.exclusive_lock_allow_credential_journal()?;
                let Some((intent, bytes)) = self.pending_auth_operation_intent_locked()? else {
                    return Err(ConfigError::AuthOperationIntentConflict {
                        path: self.paths.auth_operation_intent(),
                        reason: "authentication intent disappeared before durable completion"
                            .to_string(),
                    });
                };
                let current = self.classify_auth_operation_intent_locked(&intent)?;
                if !matches!(
                    current,
                    AuthIntentState::Candidate | AuthIntentState::TargetRemoved
                ) {
                    return Err(ConfigError::AuthOperationIntentConflict {
                        path: self.paths.auth_operation_intent(),
                        reason: "authentication state changed during recovery".to_string(),
                    });
                }
                self.remove_auth_operation_intent_locked(&bytes)?;
                Ok((reconciled, disposition))
            }
        }
    }

    pub fn reconcile_credentials(
        &self,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let _operation = self.credential_operation_lock()?;
        self.reconcile_credentials_with_operation_lock(credential_store)
    }

    pub(crate) fn reconcile_credentials_with_operation_lock(
        &self,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let (_journal, state, journal_bytes, targets, delete_ids) = {
            let _lock = self.exclusive_lock_allow_credential_journal()?;
            let Some((journal, state, journal_bytes)) =
                self.pending_credential_transaction_locked()?
            else {
                let config = self.read_primary()?;
                self.ensure_legacy_unchanged(&config)?;
                return Ok(CredentialTransactionOutcome {
                    snapshot: ConfigSnapshot { config },
                    warnings: Vec::new(),
                });
            };
            // A prior atomic replace may have become visible before its directory sync failed.
            // Durably accept the exact state we just classified before deleting any secret or
            // weakening the recovery intent.
            sync_parent(self.paths.root())?;
            let targets = credential_cleanup_targets(&journal, state);
            let durable_refs = self.durable_referenced_credential_ids_locked()?;
            let delete_ids: BTreeSet<_> = targets.difference(&durable_refs).cloned().collect();
            (journal, state, journal_bytes, targets, delete_ids)
        };

        let mut delete_failures = BTreeMap::new();
        for credential_id in &delete_ids {
            if let Err(source) = credential_store.delete(credential_id) {
                delete_failures.insert(credential_id.clone(), source);
            }
        }

        let _lock = self.exclusive_lock_allow_credential_journal()?;
        let Some((mut current, current_state, current_bytes)) =
            self.pending_credential_transaction_locked()?
        else {
            let config = self.read_primary()?;
            self.ensure_legacy_unchanged(&config)?;
            return Ok(CredentialTransactionOutcome {
                snapshot: ConfigSnapshot { config },
                warnings: Vec::new(),
            });
        };
        if current_bytes != journal_bytes || current_state != state {
            return Err(ConfigError::CredentialTransactionJournalConflict {
                path: self.paths.credential_transaction_journal(),
                reason: "credential intent changed while cleanup ran".to_string(),
            });
        }
        sync_parent(self.paths.root())?;
        let durable_refs = self.durable_referenced_credential_ids_locked()?;
        let deleted_successfully: BTreeSet<_> = delete_ids
            .iter()
            .filter(|credential_id| !delete_failures.contains_key(*credential_id))
            .cloned()
            .collect();
        if let Some(republished) = deleted_successfully.intersection(&durable_refs).next() {
            return Err(ConfigError::CredentialTransactionJournalConflict {
                path: self.paths.credential_transaction_journal(),
                reason: format!(
                    "credential {republished} became durable while cleanup was in progress"
                ),
            });
        }

        let mut warnings = Vec::new();
        for (credential_id, source) in delete_failures {
            warnings.push(CredentialTransactionWarning::CredentialDeleteFailed {
                credential_id,
                source,
            });
        }
        let reachable: Vec<_> = targets.intersection(&durable_refs).cloned().collect();
        if !reachable.is_empty() {
            warnings.push(CredentialTransactionWarning::CleanupDeferred {
                credential_ids: reachable,
                reason: "credential ids remain referenced by a durable config generation"
                    .to_string(),
            });
        }

        let mut reconcile_again = false;
        match state {
            CredentialTransactionState::Initial | CredentialTransactionState::BackupWritten => {
                if warnings.iter().any(|warning| {
                    matches!(
                        warning,
                        CredentialTransactionWarning::CredentialDeleteFailed { .. }
                    )
                }) {
                    // The source intent remains the durable cleanup authority for a retry.
                } else {
                    current.aborted = true;
                    current.aborted_after_backup_write =
                        state == CredentialTransactionState::BackupWritten;
                    let mut retained = current.carried_retired_slots.clone();
                    if let Some(old_backup) = &current.source_backup {
                        retained.extend(
                            old_backup
                                .slots
                                .difference(&current.source_primary.slots)
                                .cloned(),
                        );
                    }
                    current.retired_slots = retained;
                    current.settled_retired_ids.retain(|credential_id| {
                        current
                            .retired_slots
                            .iter()
                            .any(|slot| &slot.credential_id == credential_id)
                    });
                    if current.retired_slots.is_empty() {
                        self.remove_credential_transaction_journal_locked()?;
                    } else {
                        let bytes = serialize_credential_transaction_journal(&current)?;
                        atomic_write(&self.paths.credential_transaction_journal(), &bytes)?;
                        reconcile_again = true;
                    }
                }
            }
            CredentialTransactionState::Committed | CredentialTransactionState::Cleanup => {
                current
                    .settled_retired_ids
                    .extend(deleted_successfully.iter().cloned());
                let remaining = credential_cleanup_targets(&current, current_state);
                if remaining.is_empty() {
                    self.remove_credential_transaction_journal_locked()?;
                } else if !deleted_successfully.is_empty() {
                    let bytes = serialize_credential_transaction_journal(&current)?;
                    atomic_write(&self.paths.credential_transaction_journal(), &bytes)?;
                }
            }
        }
        if reconcile_again {
            drop(_lock);
            let mut followup = self.reconcile_credentials_with_operation_lock(credential_store)?;
            warnings.append(&mut followup.warnings);
            return Ok(CredentialTransactionOutcome {
                snapshot: followup.snapshot,
                warnings,
            });
        }
        let config = self.read_primary()?;
        self.ensure_legacy_unchanged(&config)?;
        Ok(CredentialTransactionOutcome {
            snapshot: ConfigSnapshot { config },
            warnings,
        })
    }

    fn execute_credential_transaction<F>(
        &self,
        expected_revision: u64,
        write: Option<CredentialWriteSpec<'_>>,
        credential_store: &dyn CredentialStore,
        mutate: F,
    ) -> Result<CredentialTransactionOutcome, ConfigError>
    where
        F: FnOnce(
            &mut ConfigV2,
            &BTreeMap<CredentialKind, CredentialId>,
        ) -> Result<(), ConfigError>,
    {
        let _operation = self.credential_operation_lock()?;
        let plan = {
            let _lock = self.exclusive_lock()?;
            let source = self.load_credential_transaction_source(expected_revision)?;
            self.plan_credential_transaction(source, write.as_ref(), None, mutate)?
        };
        self.execute_credential_transaction_plan(
            expected_revision,
            write.as_ref().map(|write| write.bundle),
            plan,
            credential_store,
        )
    }

    pub fn replace_credential_bundle(
        &self,
        expected_revision: u64,
        connection_id: &ConnectionId,
        profile_name: impl Into<String>,
        bundle: CredentialBundle,
        activation: CredentialActivation,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let profile_name = profile_name.into();
        validate_string_len(
            "$.connections.*.credential_profiles.<name>",
            &profile_name,
            MAX_LEGACY_NAME_LEN,
        )?;
        validate_credential_bundle_input(
            &format!("$.connections.{connection_id}.credential_profiles.{profile_name}"),
            &bundle,
        )?;
        let write = CredentialWriteSpec {
            connection_id,
            profile_name: &profile_name,
            bundle: &bundle,
        };
        self.execute_credential_transaction(
            expected_revision,
            Some(write),
            credential_store,
            |config, credential_ids| {
                apply_credential_bundle_replacement(
                    config,
                    connection_id,
                    &profile_name,
                    bundle.access_expires_at.clone(),
                    credential_ids,
                    activation,
                )
            },
        )
    }

    /// Replaces an explicitly anchored profile after an out-of-lock network operation.
    ///
    /// The global config revision may advance while the caller refreshes a token. This operation
    /// rebases onto the latest source generation when the anchored repository, endpoint trust and
    /// exact profile state still match. Credential ids are preflighted once, then reused when the
    /// candidate is rebuilt under the final config lock; no credential port is called while that
    /// lock is held.
    pub fn replace_credential_bundle_if_profile_matches(
        &self,
        anchor: &CredentialProfileAnchor,
        bundle: CredentialBundle,
        activation: CredentialActivation,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        validate_credential_bundle_input(
            &format!(
                "$.connections.{}.credential_profiles.{}",
                anchor.connection_id, anchor.profile_name
            ),
            &bundle,
        )?;
        let _operation = self.credential_operation_lock()?;
        let access_expires_at = bundle.access_expires_at.clone();
        self.execute_anchored_credential_write_with_operation_lock(
            anchor,
            &bundle,
            credential_store,
            None,
            |config, credential_ids| {
                apply_credential_bundle_replacement(
                    config,
                    &anchor.connection_id,
                    &anchor.profile_name,
                    access_expires_at.clone(),
                    credential_ids,
                    activation,
                )
            },
        )
    }

    /// Rotates only the access/refresh pair for an anchored session profile.
    ///
    /// Any service-account credential in the same profile retains its exact
    /// credential id and secret. This avoids turning a token refresh into a
    /// destructive full-profile replacement.
    pub fn rotate_session_credentials_if_profile_matches(
        &self,
        anchor: &CredentialProfileAnchor,
        access: CredentialSecret,
        refresh: CredentialSecret,
        access_expires_at: String,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let _operation = self.credential_operation_lock()?;
        self.rotate_session_credentials_if_profile_matches_with_operation_lock(
            anchor,
            access,
            refresh,
            access_expires_at,
            credential_store,
        )
    }

    pub(crate) fn rotate_session_credentials_if_profile_matches_with_operation_lock(
        &self,
        anchor: &CredentialProfileAnchor,
        access: CredentialSecret,
        refresh: CredentialSecret,
        access_expires_at: String,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        if !anchor.credentials.contains_key(&CredentialKind::Refresh) {
            return Err(ConfigError::InvalidConfig {
                path: "$.session_refresh".to_string(),
                reason: "session profile has no refresh credential".to_string(),
            });
        }
        let bundle = CredentialBundle::new(Some(access), Some(refresh), None)
            .with_access_expires_at(Some(access_expires_at.clone()));
        validate_credential_bundle_input(
            &format!(
                "$.connections.{}.credential_profiles.{}",
                anchor.connection_id, anchor.profile_name
            ),
            &bundle,
        )?;
        self.execute_anchored_credential_write_with_operation_lock(
            anchor,
            &bundle,
            credential_store,
            None,
            |config, credential_ids| {
                apply_session_credential_rotation(
                    config,
                    &anchor.connection_id,
                    &anchor.profile_name,
                    access_expires_at.clone(),
                    credential_ids,
                )
            },
        )
    }

    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn rotate_session_credentials_after_auth_intent_with_operation_locks(
        &self,
        permit: &mut AuthOperationIntentPermit,
        access: CredentialSecret,
        refresh: CredentialSecret,
        access_expires_at: String,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        if permit.operation != AuthOperationKind::Refresh {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "logout ownership token cannot publish a refresh candidate".to_string(),
            });
        }
        let anchor = permit.anchor.clone();
        let bundle = CredentialBundle::new(Some(access), Some(refresh), None)
            .with_access_expires_at(Some(access_expires_at.clone()));
        validate_credential_bundle_input(
            &format!(
                "$.connections.{}.credential_profiles.{}",
                anchor.connection_id, anchor.profile_name
            ),
            &bundle,
        )?;
        self.execute_anchored_credential_write_with_operation_lock(
            &anchor,
            &bundle,
            credential_store,
            Some(permit),
            |config, credential_ids| {
                apply_session_credential_rotation(
                    config,
                    &anchor.connection_id,
                    &anchor.profile_name,
                    access_expires_at.clone(),
                    credential_ids,
                )
            },
        )
    }

    /// Publishes the exact password-login candidate represented by a v2 auth
    /// intent. The caller continues to hold auth then credential locks.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_password_login_after_auth_intent_with_operation_locks<F>(
        &self,
        permit: &mut PasswordLoginIntentPermit,
        account_subject: &str,
        authenticated_identity: ConfigIdentity,
        access: CredentialSecret,
        refresh: CredentialSecret,
        access_expires_at: String,
        credential_store: &dyn CredentialStore,
        abort_before_candidate: F,
    ) -> Result<CredentialTransactionOutcome, ConfigError>
    where
        F: Fn() -> bool,
    {
        validate_required_metadata("$.password_login.account_subject", account_subject)?;
        let authenticated_email = authenticated_identity.email.as_deref().ok_or_else(|| {
            ConfigError::AuthenticatedIdentityConflict {
                reason: "authenticated password login identity has no canonical email".to_string(),
            }
        })?;
        if authenticated_email.is_empty() || authenticated_email.trim() != authenticated_email {
            return Err(ConfigError::AuthenticatedIdentityConflict {
                reason: "authenticated password login identity has a noncanonical email"
                    .to_string(),
            });
        }
        validate_string_len("$.password_login.identity.email", authenticated_email, 320)?;
        let anchor = permit.anchor.clone();
        let identity = authenticated_identity;
        let bundle = CredentialBundle::new(Some(access), Some(refresh), None)
            .with_access_expires_at(Some(access_expires_at.clone()));
        validate_credential_bundle_input("$.password_login.bundle", &bundle)?;
        let prepared_ids = BTreeMap::from([
            (
                CredentialKind::Access,
                permit.reservation.access_credential_id.clone(),
            ),
            (
                CredentialKind::Refresh,
                permit.reservation.refresh_credential_id.clone(),
            ),
        ]);
        let apply = |config: &mut ConfigV2,
                     credential_ids: &BTreeMap<CredentialKind, CredentialId>| {
            apply_password_login_candidate(
                config,
                &anchor,
                &identity,
                account_subject,
                &access_expires_at,
                credential_ids,
            )
        };

        let initial_plan = {
            let _lock = self.exclusive_lock()?;
            let (intent, _) = self.ensure_owned_password_login_intent_locked(permit)?;
            if permit.identity.kdf_salt != identity.kdf_salt
                || permit.identity.kdf_params != identity.kdf_params
                || permit.identity.salt_fingerprint != identity.salt_fingerprint
            {
                return Err(ConfigError::AuthenticatedIdentityConflict {
                    reason: "post-authentication KDF identity differs from prelogin".to_string(),
                });
            }
            let source = self.load_latest_credential_transaction_source()?;
            ensure_password_login_transaction_source(&intent, &source)?;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle: &bundle,
            };
            self.plan_credential_transaction(source, Some(&write), Some(&prepared_ids), apply)?
        };
        self.preflight_credential_transaction_plan(Some(&bundle), &initial_plan, credential_store)?;
        if abort_before_candidate() {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password login was cancelled before candidate preparation".to_string(),
            });
        }

        let (expected_revision, plan) = {
            let _lock = self.exclusive_lock()?;
            let (intent, _) = self.ensure_owned_password_login_intent_locked(permit)?;
            let source = self.load_latest_credential_transaction_source()?;
            ensure_password_login_transaction_source(&intent, &source)?;
            let expected_revision = source.config.revision;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle: &bundle,
            };
            let plan = self.plan_credential_transaction(
                source,
                Some(&write),
                Some(&prepared_ids),
                |config, credential_ids| {
                    apply_password_login_candidate(
                        config,
                        &anchor,
                        &identity,
                        account_subject,
                        &access_expires_at,
                        credential_ids,
                    )
                },
            )?;
            if abort_before_candidate() {
                return Err(ConfigError::AuthOperationIntentConflict {
                    path: self.paths.auth_operation_intent(),
                    reason: "password login was cancelled before candidate preparation".to_string(),
                });
            }
            self.install_password_login_candidate_locked(permit, &plan, account_subject)?;
            self.install_credential_transaction_intent_locked(expected_revision, &plan)?;
            (expected_revision, plan)
        };
        let outcome = self.execute_installed_credential_transaction_plan(
            expected_revision,
            Some(&bundle),
            plan,
            credential_store,
        )?;
        let _lock = self.exclusive_lock_allow_credential_journal()?;
        self.accept_owned_password_login_locked(permit)?;
        Ok(outcome)
    }

    /// Proves that a candidate whose intent unlink became visible is the exact
    /// locally published password-login session. This performs no store I/O.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn password_login_candidate_is_published_with_operation_locks(
        &self,
        permit: &PasswordLoginIntentPermit,
    ) -> Result<Option<ConfigSnapshot>, ConfigError> {
        let Some(candidate) = permit.candidate.as_ref() else {
            return Ok(None);
        };
        let _lock = self.exclusive_lock_allow_credential_journal()?;
        if validate_regular_file_if_exists(&self.paths.auth_operation_intent())? {
            return Ok(None);
        }
        let primary_path = self.paths.config();
        let primary_bytes = read_file(&primary_path, "verify password-login candidate")?;
        let config = parse_config(&primary_path, &primary_bytes)?;
        if config.revision != candidate.revision
            || byte_digest(&primary_bytes) != candidate.raw_digest
        {
            return Ok(None);
        }
        let Some(connection) = config.connections.get(&permit.anchor.connection_id) else {
            return Ok(None);
        };
        let Some(profile) = connection
            .credential_profiles
            .get(&permit.anchor.profile_name)
        else {
            return Ok(None);
        };
        let mut expected_credentials = permit
            .anchor
            .profile
            .as_ref()
            .map(|profile| profile.credentials.clone())
            .unwrap_or_default();
        expected_credentials.insert(
            CredentialKind::Access,
            candidate.access_credential_id.clone(),
        );
        expected_credentials.insert(
            CredentialKind::Refresh,
            candidate.refresh_credential_id.clone(),
        );
        let normalized_address = normalize_address(
            &connection.metadata.address,
            &format!(
                "$.connections.{}.metadata.address",
                permit.anchor.connection_id
            ),
        )?;
        let published = normalized_address == permit.anchor.normalized_address
            && connection.metadata.server_id.as_deref() == Some(permit.anchor.server_id.as_str())
            && connection.metadata.server_fingerprint.as_deref()
                == Some(permit.anchor.server_fingerprint.as_str())
            && connection.metadata.storage_id == permit.anchor.storage_id
            && connection.active_credential.as_deref() == Some(permit.anchor.profile_name.as_str())
            && config
                .clients
                .get(&permit.anchor.client_id)
                .and_then(|client| client.active_connection.as_ref())
                == Some(&permit.anchor.connection_id)
            && profile.credentials == expected_credentials
            && profile.account_subject.as_deref() == Some(candidate.account_subject.as_str())
            && profile.auth_method == Some(AuthMethod::Password)
            && profile.access_expires_at.as_deref() == Some(candidate.access_expires_at.as_str());
        Ok(published.then_some(ConfigSnapshot { config }))
    }

    #[cfg(test)]
    fn install_auth_rotation_candidate_without_credential_journal_for_test(
        &self,
        permit: &mut AuthOperationIntentPermit,
        access: CredentialSecret,
        refresh: CredentialSecret,
        access_expires_at: String,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionPlan, ConfigError> {
        let anchor = permit.anchor.clone();
        let bundle = CredentialBundle::new(Some(access), Some(refresh), None)
            .with_access_expires_at(Some(access_expires_at.clone()));
        let apply = |config: &mut ConfigV2,
                     credential_ids: &BTreeMap<CredentialKind, CredentialId>| {
            apply_session_credential_rotation(
                config,
                &anchor.connection_id,
                &anchor.profile_name,
                access_expires_at.clone(),
                credential_ids,
            )
        };
        let initial_plan = {
            let _lock = self.exclusive_lock()?;
            self.ensure_owned_auth_operation_intent_locked(permit)?;
            let source = self.load_latest_credential_transaction_source()?;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle: &bundle,
            };
            self.plan_credential_transaction(source, Some(&write), None, apply)?
        };
        self.preflight_credential_transaction_plan(Some(&bundle), &initial_plan, credential_store)?;
        let prepared_ids = initial_plan.credential_ids;
        let plan = {
            let _lock = self.exclusive_lock()?;
            self.ensure_owned_auth_operation_intent_locked(permit)?;
            let source = self.load_latest_credential_transaction_source()?;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle: &bundle,
            };
            let plan =
                self.plan_credential_transaction(source, Some(&write), Some(&prepared_ids), apply)?;
            self.install_auth_rotation_candidate_locked(permit, &plan)?;
            plan
        };
        Ok(plan)
    }

    #[cfg(test)]
    fn install_password_login_candidate_without_credential_journal_for_test(
        &self,
        permit: &mut PasswordLoginIntentPermit,
        account_subject: &str,
        bundle: &CredentialBundle,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionPlan, ConfigError> {
        let anchor = permit.anchor.clone();
        let identity = permit.identity.clone();
        let access_expires_at =
            bundle
                .access_expires_at
                .clone()
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: "$.password_login.bundle.access_expires_at".to_string(),
                    reason: "password-login test candidate requires an expiry".to_string(),
                })?;
        let prepared_ids = BTreeMap::from([
            (
                CredentialKind::Access,
                permit.reservation.access_credential_id.clone(),
            ),
            (
                CredentialKind::Refresh,
                permit.reservation.refresh_credential_id.clone(),
            ),
        ]);
        let initial_plan = {
            let _lock = self.exclusive_lock()?;
            let (intent, _) = self.ensure_owned_password_login_intent_locked(permit)?;
            let source = self.load_latest_credential_transaction_source()?;
            ensure_password_login_transaction_source(&intent, &source)?;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle,
            };
            self.plan_credential_transaction(
                source,
                Some(&write),
                Some(&prepared_ids),
                |config, ids| {
                    apply_password_login_candidate(
                        config,
                        &anchor,
                        &identity,
                        account_subject,
                        &access_expires_at,
                        ids,
                    )
                },
            )?
        };
        self.preflight_credential_transaction_plan(Some(bundle), &initial_plan, credential_store)?;
        let _lock = self.exclusive_lock()?;
        let (intent, _) = self.ensure_owned_password_login_intent_locked(permit)?;
        let source = self.load_latest_credential_transaction_source()?;
        ensure_password_login_transaction_source(&intent, &source)?;
        let write = CredentialWriteSpec {
            connection_id: &anchor.connection_id,
            profile_name: &anchor.profile_name,
            bundle,
        };
        let plan = self.plan_credential_transaction(
            source,
            Some(&write),
            Some(&prepared_ids),
            |config, ids| {
                apply_password_login_candidate(
                    config,
                    &anchor,
                    &identity,
                    account_subject,
                    &access_expires_at,
                    ids,
                )
            },
        )?;
        self.install_password_login_candidate_locked(permit, &plan, account_subject)?;
        Ok(plan)
    }

    fn execute_anchored_credential_write_with_operation_lock<F>(
        &self,
        anchor: &CredentialProfileAnchor,
        bundle: &CredentialBundle,
        credential_store: &dyn CredentialStore,
        mut auth_permit: Option<&mut AuthOperationIntentPermit>,
        apply: F,
    ) -> Result<CredentialTransactionOutcome, ConfigError>
    where
        F: Fn(&mut ConfigV2, &BTreeMap<CredentialKind, CredentialId>) -> Result<(), ConfigError>,
    {
        let initial_plan = {
            let _lock = self.exclusive_lock()?;
            if let Some(permit) = auth_permit.as_deref() {
                self.ensure_owned_auth_operation_intent_locked(permit)?;
            }
            let source = self.load_latest_credential_transaction_source()?;
            ensure_credential_profile_anchor_matches(
                anchor,
                &credential_profile_anchor_repository_binding(self.paths.root())?,
                &source.config,
                &byte_digest(&source.source_primary_bytes),
            )?;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle,
            };
            self.plan_credential_transaction(
                source,
                Some(&write),
                None,
                |config, credential_ids| apply(config, credential_ids),
            )?
        };
        self.preflight_credential_transaction_plan(Some(bundle), &initial_plan, credential_store)?;
        let prepared_credential_ids = initial_plan.credential_ids;

        let (expected_revision, plan) = {
            let _lock = self.exclusive_lock()?;
            if let Some(permit) = auth_permit.as_deref() {
                self.ensure_owned_auth_operation_intent_locked(permit)?;
            }
            let source = self.load_latest_credential_transaction_source()?;
            ensure_credential_profile_anchor_matches(
                anchor,
                &credential_profile_anchor_repository_binding(self.paths.root())?,
                &source.config,
                &byte_digest(&source.source_primary_bytes),
            )?;
            let expected_revision = source.config.revision;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle,
            };
            let plan = self.plan_credential_transaction(
                source,
                Some(&write),
                Some(&prepared_credential_ids),
                |config, credential_ids| apply(config, credential_ids),
            )?;
            if let Some(permit) = auth_permit.as_deref_mut() {
                self.install_auth_rotation_candidate_locked(permit, &plan)?;
            }
            self.install_credential_transaction_intent_locked(expected_revision, &plan)?;
            (expected_revision, plan)
        };
        debug_assert_eq!(
            expected_revision.checked_add(1),
            Some(plan.candidate_config.revision)
        );
        let outcome = self.execute_installed_credential_transaction_plan(
            expected_revision,
            Some(bundle),
            plan,
            credential_store,
        )?;
        if let Some(permit) = auth_permit {
            let _lock = self.exclusive_lock_allow_credential_journal()?;
            self.accept_owned_auth_rotation_locked(permit)?;
        }
        Ok(outcome)
    }

    #[allow(dead_code)]
    pub(crate) fn commit_authenticated_session(
        &self,
        expected_revision: u64,
        input: AuthenticatedSessionCommit,
        credential_store: &dyn CredentialStore,
    ) -> Result<AuthenticatedSessionOutcome, ConfigError> {
        let AuthenticatedSessionCommit {
            endpoint,
            storage_id,
            target,
            identity,
            client_id,
            profile_name,
            bundle,
            account_binding,
        } = input;
        if let Some(storage_id) = &storage_id {
            validate_required_metadata("$.authenticated_session.storage_id", storage_id)?;
        }
        validate_string_len(
            "$.authenticated_session.profile_name",
            &profile_name,
            MAX_LEGACY_NAME_LEN,
        )?;
        validate_credential_bundle_input("$.authenticated_session.bundle", &bundle)?;
        let connection_id = match &target {
            AuthenticatedConnectionTarget::Create { connection_name } => {
                validate_string_len(
                    "$.authenticated_session.target.connection_name",
                    connection_name,
                    MAX_LEGACY_NAME_LEN,
                )?;
                ConnectionId::deterministic(connection_name, endpoint.address())
            }
            AuthenticatedConnectionTarget::UseExisting { connection_id, .. }
            | AuthenticatedConnectionTarget::PinExisting { connection_id, .. }
            | AuthenticatedConnectionTarget::ReplaceFingerprint { connection_id, .. }
            | AuthenticatedConnectionTarget::RelocateEndpoint { connection_id, .. } => {
                connection_id.clone()
            }
        };
        let write = CredentialWriteSpec {
            connection_id: &connection_id,
            profile_name: &profile_name,
            bundle: &bundle,
        };
        let transaction = self.execute_credential_transaction(
            expected_revision,
            Some(write),
            credential_store,
            |config, credential_ids| {
                apply_identity_commit(config, &identity)?;
                apply_authenticated_connection_target(
                    config,
                    &connection_id,
                    &target,
                    &endpoint,
                    storage_id.as_deref(),
                )?;
                apply_credential_bundle_replacement(
                    config,
                    &connection_id,
                    &profile_name,
                    bundle.access_expires_at.clone(),
                    credential_ids,
                    CredentialActivation::MakeActive,
                )?;
                if let Some((account_subject, auth_method)) = &account_binding {
                    validate_required_metadata(
                        "$.authenticated_session.account_subject",
                        account_subject,
                    )?;
                    let profile = config
                        .connections
                        .get_mut(&connection_id)
                        .and_then(|connection| {
                            connection.credential_profiles.get_mut(&profile_name)
                        })
                        .ok_or_else(|| ConfigError::MissingCredentialProfile {
                            connection_id: connection_id.clone(),
                            profile_name: profile_name.clone(),
                        })?;
                    profile.account_subject = Some(account_subject.clone());
                    profile.auth_method = Some(*auth_method);
                }
                client_entry(config, &client_id).active_connection = Some(connection_id.clone());
                Ok(())
            },
        )?;
        let actual_storage_id = transaction
            .snapshot()
            .config()
            .connections
            .get(&connection_id)
            .and_then(|connection| connection.metadata.storage_id.clone());
        debug_assert!(
            transaction
                .snapshot()
                .config()
                .connections
                .contains_key(&connection_id),
            "authenticated session candidate must contain its resolved connection"
        );
        Ok(AuthenticatedSessionOutcome {
            transaction,
            connection_id,
            storage_id: actual_storage_id,
            profile_name,
        })
    }

    pub fn remove_credential_profile(
        &self,
        expected_revision: u64,
        connection_id: &ConnectionId,
        profile_name: impl Into<String>,
        active_after: ActiveCredentialAfterRemoval,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let profile_name = profile_name.into();
        validate_string_len(
            "$.connections.*.credential_profiles.<name>",
            &profile_name,
            MAX_LEGACY_NAME_LEN,
        )?;
        if let ActiveCredentialAfterRemoval::Activate(fallback) = &active_after {
            validate_string_len(
                "$.credential_removal.active_after",
                fallback,
                MAX_LEGACY_NAME_LEN,
            )?;
        }
        self.execute_credential_transaction(
            expected_revision,
            None,
            credential_store,
            |config, credential_ids| {
                if !credential_ids.is_empty() {
                    return Err(ConfigError::InvalidConfig {
                        path: "$.credential_removal".to_string(),
                        reason: "credential removal must not allocate credential ids".to_string(),
                    });
                }
                apply_credential_profile_removal(
                    config,
                    connection_id,
                    &profile_name,
                    &active_after,
                )
            },
        )
    }

    /// Removes a profile only when its repository-bound refresh anchor still
    /// matches, rebasing over unrelated config revisions.
    ///
    /// This is the inverse of
    /// [`Self::replace_credential_bundle_if_profile_matches`]. It is used for
    /// a definitive refresh rejection so a concurrent update to another
    /// client namespace or active-profile selection cannot either block
    /// revocation or delete a newer credential generation.
    pub fn remove_credential_profile_if_matches(
        &self,
        anchor: &CredentialProfileAnchor,
        active_after: ActiveCredentialAfterRemoval,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let _operation = self.credential_operation_lock()?;
        self.remove_credential_profile_if_matches_with_operation_lock(
            anchor,
            active_after,
            credential_store,
        )
    }

    pub(crate) fn remove_credential_profile_if_matches_with_operation_lock(
        &self,
        anchor: &CredentialProfileAnchor,
        active_after: ActiveCredentialAfterRemoval,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        self.remove_credential_profile_if_matches_with_optional_auth_intent(
            anchor,
            active_after,
            credential_store,
            None,
        )
    }

    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn remove_credential_profile_after_auth_intent_with_operation_locks(
        &self,
        permit: &AuthOperationIntentPermit,
        active_after: ActiveCredentialAfterRemoval,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let anchor = permit.anchor.clone();
        self.remove_credential_profile_if_matches_with_optional_auth_intent(
            &anchor,
            active_after,
            credential_store,
            Some(permit),
        )
    }

    fn remove_credential_profile_if_matches_with_optional_auth_intent(
        &self,
        anchor: &CredentialProfileAnchor,
        active_after: ActiveCredentialAfterRemoval,
        credential_store: &dyn CredentialStore,
        auth_permit: Option<&AuthOperationIntentPermit>,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        if let ActiveCredentialAfterRemoval::Activate(fallback) = &active_after {
            validate_string_len(
                "$.credential_removal.active_after",
                fallback,
                MAX_LEGACY_NAME_LEN,
            )?;
        }
        let (expected_revision, plan) = {
            let _lock = self.exclusive_lock()?;
            if let Some(permit) = auth_permit {
                let (intent, _) = self.ensure_owned_auth_operation_intent_locked(permit)?;
                if !matches!(
                    self.classify_auth_operation_intent_locked(&intent)?,
                    AuthIntentState::Source(current) if *current == *anchor
                ) {
                    return Err(ConfigError::AuthOperationIntentConflict {
                        path: self.paths.auth_operation_intent(),
                        reason:
                            "owned authentication intent is not anchored to the exact revoke source"
                                .to_string(),
                    });
                }
            }
            let source = self.load_latest_credential_transaction_source()?;
            ensure_credential_profile_anchor_matches(
                anchor,
                &credential_profile_anchor_repository_binding(self.paths.root())?,
                &source.config,
                &byte_digest(&source.source_primary_bytes),
            )?;
            let expected_revision = source.config.revision;
            let plan =
                self.plan_credential_transaction(source, None, None, |config, credential_ids| {
                    if !credential_ids.is_empty() {
                        return Err(ConfigError::InvalidConfig {
                            path: "$.credential_removal".to_string(),
                            reason: "credential removal must not allocate credential ids"
                                .to_string(),
                        });
                    }
                    apply_credential_profile_removal(
                        config,
                        &anchor.connection_id,
                        &anchor.profile_name,
                        &active_after,
                    )
                })?;
            self.install_credential_transaction_intent_locked(expected_revision, &plan)?;
            (expected_revision, plan)
        };
        let outcome = self.execute_installed_credential_transaction_plan(
            expected_revision,
            None,
            plan,
            credential_store,
        )?;
        if let Some(permit) = auth_permit {
            let _lock = self.exclusive_lock_allow_credential_journal()?;
            let (intent, bytes) = self.ensure_owned_auth_operation_intent_locked(permit)?;
            if !matches!(
                self.classify_auth_operation_intent_locked(&intent)?,
                AuthIntentState::TargetRemoved
            ) {
                return Err(ConfigError::AuthOperationIntentConflict {
                    path: self.paths.auth_operation_intent(),
                    reason: "journaled revoke did not remove the intended profile".to_string(),
                });
            }
            self.remove_auth_operation_intent_locked(&bytes)?;
        }
        Ok(outcome)
    }

    fn execute_credential_transaction_plan(
        &self,
        expected_revision: u64,
        bundle: Option<&CredentialBundle>,
        plan: CredentialTransactionPlan,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        self.preflight_credential_transaction_plan(bundle, &plan, credential_store)?;
        {
            let _lock = self.exclusive_lock()?;
            self.install_credential_transaction_intent_locked(expected_revision, &plan)?;
        }
        self.execute_installed_credential_transaction_plan(
            expected_revision,
            bundle,
            plan,
            credential_store,
        )
    }

    fn preflight_credential_transaction_plan(
        &self,
        bundle: Option<&CredentialBundle>,
        plan: &CredentialTransactionPlan,
        credential_store: &dyn CredentialStore,
    ) -> Result<(), ConfigError> {
        if let Some(bundle) = bundle {
            for (kind, secret) in bundle.slots() {
                if let Some(secret) = secret {
                    let credential_id = plan.credential_ids.get(&kind).ok_or_else(|| {
                        ConfigError::InvalidConfig {
                            path: "$.credential_transaction".to_string(),
                            reason: format!("planned {kind:?} credential has no id"),
                        }
                    })?;
                    credential_store
                        .validate(credential_id, secret)
                        .map_err(|source| ConfigError::CredentialValidation { kind, source })?;
                }
            }
            preflight_credential_slots(credential_store, &plan.credential_ids)?;
        }
        Ok(())
    }

    fn install_credential_transaction_intent_locked(
        &self,
        expected_revision: u64,
        plan: &CredentialTransactionPlan,
    ) -> Result<(), ConfigError> {
        let current_predecessor = self.pending_credential_transaction_locked()?;
        match (&plan.predecessor_journal_bytes, current_predecessor) {
            (None, None) => {}
            (Some(expected), Some((_, state, actual)))
                if matches!(
                    state,
                    CredentialTransactionState::Committed | CredentialTransactionState::Cleanup
                ) && expected == &actual => {}
            _ => {
                return Err(ConfigError::CredentialTransactionJournalConflict {
                    path: self.paths.credential_transaction_journal(),
                    reason: "credential cleanup intent changed during backend preflight"
                        .to_string(),
                });
            }
        }
        let current_primary = read_file(
            &self.paths.config(),
            "recheck config before credential intent",
        )?;
        let current_config = parse_config(&self.paths.config(), &current_primary)?;
        self.ensure_legacy_unchanged(&current_config)?;
        if byte_digest(&current_primary) != plan.journal.source_primary.raw_digest {
            let actual = current_config.revision;
            return Err(if actual == expected_revision {
                ConfigError::ConfigContentConflict {
                    revision: expected_revision,
                }
            } else {
                ConfigError::RevisionConflict {
                    expected: expected_revision,
                    actual,
                }
            });
        }
        let current_backup_digest = self
            .read_optional_durable_config_with_digest(&self.paths.backup())?
            .map(|(_, digest)| digest);
        let expected_backup_digest = plan
            .journal
            .source_backup
            .as_ref()
            .map(|generation| generation.raw_digest.clone());
        if current_backup_digest != expected_backup_digest {
            return Err(ConfigError::ConfigContentConflict {
                revision: expected_revision,
            });
        }
        atomic_write(
            &self.paths.credential_transaction_journal(),
            &plan.journal_bytes,
        )
    }

    fn execute_installed_credential_transaction_plan(
        &self,
        expected_revision: u64,
        bundle: Option<&CredentialBundle>,
        plan: CredentialTransactionPlan,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let mut created_ids = BTreeSet::new();
        if let Some(bundle) = bundle {
            if let Err(error) = prepare_credential_slots(
                credential_store,
                bundle,
                &plan.credential_ids,
                &mut created_ids,
            ) {
                let warnings = self
                    .reconcile_failed_credential_intent(credential_store, &plan.journal.new_ids);
                return Err(with_cleanup_warnings(error, warnings));
            }
        }

        let lock = match self.exclusive_lock_allow_credential_journal() {
            Ok(lock) => lock,
            Err(error) => {
                let warnings = self
                    .reconcile_failed_credential_intent(credential_store, &plan.journal.new_ids);
                return Err(with_cleanup_warnings(error, warnings));
            }
        };
        let mut backup_write_attempted = false;
        let mut primary_write_attempted = false;
        let commit_result = (|| {
            let (_, current_state, current_journal_bytes) = self
                .pending_credential_transaction_locked()?
                .ok_or_else(|| ConfigError::CredentialTransactionJournalConflict {
                    path: self.paths.credential_transaction_journal(),
                    reason: "credential transaction journal disappeared".to_string(),
                })?;
            if current_journal_bytes != plan.journal_bytes {
                return Err(ConfigError::CredentialTransactionJournalConflict {
                    path: self.paths.credential_transaction_journal(),
                    reason: "credential transaction journal changed during store I/O".to_string(),
                });
            }
            if !matches!(
                current_state,
                CredentialTransactionState::Initial | CredentialTransactionState::BackupWritten
            ) {
                return Err(ConfigError::CredentialTransactionJournalConflict {
                    path: self.paths.credential_transaction_journal(),
                    reason: "credential intent is no longer in a pre-commit state".to_string(),
                });
            }
            let primary_path = self.paths.config();
            if !validate_regular_file_if_exists(&primary_path)? {
                return Err(ConfigError::MissingConfig { path: primary_path });
            }
            let previous_bytes = read_file(&primary_path, "read config")?;
            let latest = parse_config(&primary_path, &previous_bytes)?;
            self.ensure_legacy_unchanged(&latest)?;
            if latest.revision != expected_revision {
                return Err(ConfigError::RevisionConflict {
                    expected: expected_revision,
                    actual: latest.revision,
                });
            }
            if byte_digest(&previous_bytes) != plan.journal.source_primary.raw_digest {
                return Err(ConfigError::ConfigContentConflict {
                    revision: expected_revision,
                });
            }
            backup_write_attempted = true;
            atomic_write(&self.paths.backup(), &previous_bytes)?;
            primary_write_attempted = true;
            atomic_write(&primary_path, &plan.candidate_bytes)
        })();

        let mut warnings = Vec::new();
        let mut skip_postcommit_cleanup = false;
        if let Err(error) = commit_result {
            let commit_reason = error.to_string();
            let published = if primary_write_attempted {
                match self.resolve_credential_commit_outcome_locked(&plan) {
                    Ok(published) => published,
                    Err(ambiguous) => {
                        drop(lock);
                        return Err(ambiguous);
                    }
                }
            } else {
                if backup_write_attempted {
                    if let Err(ambiguous) = self.repair_aborted_credential_state_locked(&plan) {
                        drop(lock);
                        return Err(ambiguous);
                    }
                }
                false
            };
            if published {
                warnings.push(CredentialTransactionWarning::CommitRecovered {
                    reason: commit_reason,
                });
                let owns_journal = read_file(
                    &self.paths.credential_transaction_journal(),
                    "verify recovered credential intent ownership",
                )
                .is_ok_and(|bytes| bytes == plan.journal_bytes);
                if !owns_journal {
                    skip_postcommit_cleanup = true;
                    warnings.push(CredentialTransactionWarning::CleanupDeferred {
                        credential_ids: credential_ids_from_slots(
                            &plan.journal.retired_slots,
                        )
                        .into_iter()
                        .collect(),
                        reason: "credential commit is published but its cleanup intent changed; preserving it for explicit recovery"
                            .to_string(),
                    });
                }
            } else {
                let owns_precommit_intent =
                    self.pending_credential_transaction_locked()
                        .is_ok_and(|pending| {
                            pending.is_some_and(|(_, state, bytes)| {
                                matches!(
                                    state,
                                    CredentialTransactionState::Initial
                                        | CredentialTransactionState::BackupWritten
                                ) && bytes == plan.journal_bytes
                            })
                        });
                drop(lock);
                let cleanup_warnings = if owns_precommit_intent {
                    self.reconcile_failed_credential_intent(credential_store, &created_ids)
                } else {
                    vec![CredentialTransactionWarning::CleanupDeferred {
                        credential_ids: created_ids.iter().cloned().collect(),
                        reason: "credential intent or config changed before commit; published-id safety requires explicit recovery"
                            .to_string(),
                    }]
                };
                return Err(with_cleanup_warnings(error, cleanup_warnings));
            }
        }
        drop(lock);

        if !skip_postcommit_cleanup {
            match self.reconcile_credentials_with_operation_lock(credential_store) {
                Ok(reconciled) => warnings.extend(reconciled.warnings),
                Err(error) => warnings.push(CredentialTransactionWarning::CleanupDeferred {
                    credential_ids: credential_ids_from_slots(&plan.journal.retired_slots)
                        .into_iter()
                        .collect(),
                    reason: error.to_string(),
                }),
            }
        }
        Ok(CredentialTransactionOutcome {
            snapshot: ConfigSnapshot {
                config: plan.candidate_config,
            },
            warnings,
        })
    }

    fn resolve_credential_commit_outcome_locked(
        &self,
        plan: &CredentialTransactionPlan,
    ) -> Result<bool, ConfigError> {
        let candidate_revision = plan.journal.candidate.revision;
        let primary_bytes = read_file(
            &self.paths.config(),
            "resolve ambiguous credential primary write",
        )
        .map_err(|error| ConfigError::CredentialCommitAmbiguous {
            candidate_revision,
            reason: error.to_string(),
        })?;
        let backup_bytes = read_file(
            &self.paths.backup(),
            "resolve ambiguous credential backup write",
        )
        .map_err(|error| ConfigError::CredentialCommitAmbiguous {
            candidate_revision,
            reason: error.to_string(),
        })?;
        if primary_bytes == plan.candidate_bytes
            && byte_digest(&backup_bytes) == plan.journal.source_primary.raw_digest
        {
            self.repair_published_credential_state_locked(plan)?;
            return Ok(true);
        }

        let primary = parse_config(&self.paths.config(), &primary_bytes).map_err(|error| {
            ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: error.to_string(),
            }
        })?;
        parse_config(&self.paths.backup(), &backup_bytes).map_err(|error| {
            ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: error.to_string(),
            }
        })?;
        if !plan
            .journal
            .new_ids
            .is_disjoint(&referenced_credential_ids(&primary))
        {
            return Err(ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: "live primary references one or more freshly written credential ids"
                    .to_string(),
            });
        }
        Ok(false)
    }

    fn repair_published_credential_state_locked(
        &self,
        plan: &CredentialTransactionPlan,
    ) -> Result<(), ConfigError> {
        let candidate_revision = plan.journal.candidate.revision;
        atomic_write(&self.paths.backup(), &plan.source_primary_bytes).map_err(|error| {
            ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: format!("failed to durably repair committed backup: {error}"),
            }
        })?;
        atomic_write(&self.paths.config(), &plan.candidate_bytes).map_err(|error| {
            ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: format!("failed to durably repair committed primary: {error}"),
            }
        })
    }

    fn repair_aborted_credential_state_locked(
        &self,
        plan: &CredentialTransactionPlan,
    ) -> Result<(), ConfigError> {
        let candidate_revision = plan.journal.candidate.revision;
        atomic_write(&self.paths.config(), &plan.source_primary_bytes).map_err(|error| {
            ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: format!("failed to durably repair aborted primary: {error}"),
            }
        })?;
        atomic_write(&self.paths.backup(), &plan.source_primary_bytes).map_err(|error| {
            ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: format!("failed to durably repair aborted backup: {error}"),
            }
        })
    }

    fn load_credential_transaction_source(
        &self,
        expected_revision: u64,
    ) -> Result<CredentialTransactionSource, ConfigError> {
        let source = self.load_latest_credential_transaction_source()?;
        if source.config.revision != expected_revision {
            return Err(ConfigError::RevisionConflict {
                expected: expected_revision,
                actual: source.config.revision,
            });
        }
        Ok(source)
    }

    fn load_latest_credential_transaction_source(
        &self,
    ) -> Result<CredentialTransactionSource, ConfigError> {
        let (carried_retired_slots, predecessor_journal_bytes) =
            match self.pending_credential_transaction_locked()? {
                None => (BTreeSet::new(), None),
                Some((
                    journal,
                    CredentialTransactionState::Committed | CredentialTransactionState::Cleanup,
                    bytes,
                )) => {
                    let carried = journal
                        .retired_slots
                        .iter()
                        .filter(|slot| !journal.settled_retired_ids.contains(&slot.credential_id))
                        .cloned()
                        .collect();
                    (carried, Some(bytes))
                }
                Some((
                    _,
                    CredentialTransactionState::Initial | CredentialTransactionState::BackupWritten,
                    _,
                )) => {
                    return Err(ConfigError::CredentialRecoveryRequired {
                        path: self.paths.credential_transaction_journal(),
                    });
                }
            };
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Err(ConfigError::MissingConfig { path: primary_path });
        }
        let source_primary_bytes = read_file(&primary_path, "read config")?;
        let config = parse_config(&primary_path, &source_primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        let source_backup = self.read_optional_durable_config_with_digest(&self.paths.backup())?;
        Ok(CredentialTransactionSource {
            config,
            source_primary_bytes,
            source_backup,
            carried_retired_slots,
            predecessor_journal_bytes,
        })
    }

    fn plan_credential_transaction<F>(
        &self,
        source: CredentialTransactionSource,
        write: Option<&CredentialWriteSpec<'_>>,
        prepared_credential_ids: Option<&BTreeMap<CredentialKind, CredentialId>>,
        mutate: F,
    ) -> Result<CredentialTransactionPlan, ConfigError>
    where
        F: FnOnce(
            &mut ConfigV2,
            &BTreeMap<CredentialKind, CredentialId>,
        ) -> Result<(), ConfigError>,
    {
        let CredentialTransactionSource {
            mut config,
            source_primary_bytes,
            source_backup,
            carried_retired_slots,
            predecessor_journal_bytes,
        } = source;
        let source_primary = config.clone();
        let expected_kinds: BTreeSet<_> = write
            .iter()
            .flat_map(|write| write.bundle.slots())
            .filter_map(|(kind, secret)| secret.is_some().then_some(kind))
            .collect();
        let mut credential_ids = prepared_credential_ids.cloned().unwrap_or_default();
        if prepared_credential_ids.is_some()
            && credential_ids.keys().copied().collect::<BTreeSet<_>>() != expected_kinds
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.credential_transaction.new_ids".to_string(),
                reason: "prepared credential ids must exactly match the bundle slots".to_string(),
            });
        }
        if prepared_credential_ids.is_none() {
            if let Some(write) = write {
                for kind in expected_kinds {
                    credential_ids.insert(
                        kind,
                        CredentialId::fresh(
                            self.paths.root(),
                            write.connection_id,
                            write.profile_name,
                            kind,
                        )?,
                    );
                }
            }
        }
        mutate(&mut config, &credential_ids)?;
        config.revision = config
            .revision
            .checked_add(1)
            .ok_or(ConfigError::RevisionOverflow)?;
        validate_repository_credential_ids(&config, self.paths.root())?;
        let candidate_bytes = serialize_config(&config)?;
        let source_ids = referenced_credential_ids(&source_primary);
        let candidate_ids = referenced_credential_ids(&config);
        let new_ids: BTreeSet<_> = candidate_ids.difference(&source_ids).cloned().collect();
        let expected_new_ids: BTreeSet<_> = credential_ids.values().cloned().collect();
        if new_ids != expected_new_ids {
            return Err(ConfigError::InvalidConfig {
                path: "$.credential_transaction.new_ids".to_string(),
                reason: "credential writes must exactly match candidate refs minus source refs"
                    .to_string(),
            });
        }
        if credential_ids.is_empty() && source_ids.is_subset(&candidate_ids) {
            return Err(ConfigError::InvalidConfig {
                path: "$.credential_transaction".to_string(),
                reason: "a zero-write credential transaction must retire durable references"
                    .to_string(),
            });
        }
        let source_slots = credential_slot_refs(&source_primary);
        let candidate_slots = credential_slot_refs(&config);
        let mut base_retired_slots: BTreeSet<_> =
            source_slots.difference(&candidate_slots).cloned().collect();
        let source_backup = match source_backup {
            Some((backup, digest)) => {
                let backup_slots = credential_slot_refs(&backup);
                base_retired_slots.extend(backup_slots.difference(&source_slots).cloned());
                Some(credential_generation(&backup, digest))
            }
            None => None,
        };
        let carried_retired_slots: BTreeSet<_> = carried_retired_slots
            .difference(&base_retired_slots)
            .cloned()
            .collect();
        let mut retired_slots = base_retired_slots;
        retired_slots.extend(carried_retired_slots.iter().cloned());
        let source_primary_generation =
            credential_generation(&source_primary, byte_digest(&source_primary_bytes));
        let candidate_generation = credential_generation(&config, byte_digest(&candidate_bytes));
        let journal = CredentialTransactionJournal {
            journal_version: CREDENTIAL_TRANSACTION_JOURNAL_VERSION,
            source_primary: source_primary_generation,
            source_backup,
            candidate: candidate_generation,
            new_ids,
            retired_slots,
            carried_retired_slots,
            settled_retired_ids: BTreeSet::new(),
            aborted: false,
            aborted_after_backup_write: false,
        };
        let journal_bytes = serialize_credential_transaction_journal(&journal)?;
        Ok(CredentialTransactionPlan {
            journal,
            journal_bytes,
            candidate_config: config,
            source_primary_bytes,
            candidate_bytes,
            credential_ids,
            predecessor_journal_bytes,
        })
    }

    pub fn upsert_connection(
        &self,
        connection_id: ConnectionId,
        metadata: ConnectionMetadata,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.upsert_connection_checked(None, connection_id, metadata)
    }

    /// Installs a server identity verified by the crate-owned signed probe.
    /// Existing bindings may only be completed, never silently replaced.
    #[cfg(feature = "app")]
    pub(crate) fn pin_verified_connection(
        &self,
        expected_revision: u64,
        connection_id: ConnectionId,
        name: String,
        endpoint: &VerifiedEndpointBinding,
        storage_id: String,
    ) -> Result<ConfigSnapshot, ConfigError> {
        validate_required_metadata("$.verified_connection.storage_id", &storage_id)?;
        self.mutate(Some(expected_revision), move |config| {
            match config.connections.get_mut(&connection_id) {
                Some(connection) => {
                    let metadata = &mut connection.metadata;
                    let normalized = normalize_address(
                        &metadata.address,
                        &format!("$.connections.{connection_id}.metadata.address"),
                    )?;
                    if normalized != endpoint.address
                        || metadata
                            .server_id
                            .as_deref()
                            .is_some_and(|value| value != endpoint.server_id)
                        || metadata
                            .server_fingerprint
                            .as_deref()
                            .is_some_and(|value| value != endpoint.server_fingerprint)
                        || metadata
                            .storage_id
                            .as_deref()
                            .is_some_and(|value| value != storage_id)
                    {
                        return Err(ConfigError::BindingChangeRequiresRebind {
                            connection_id,
                            field: "verified_endpoint",
                        });
                    }
                    metadata.name = name;
                    metadata.server_id = Some(endpoint.server_id.clone());
                    metadata.server_fingerprint = Some(endpoint.server_fingerprint.clone());
                    metadata.storage_id = Some(storage_id);
                }
                None => {
                    let mut metadata = ConnectionMetadata::new(name, endpoint.address.clone());
                    metadata.server_id = Some(endpoint.server_id.clone());
                    metadata.server_fingerprint = Some(endpoint.server_fingerprint.clone());
                    metadata.storage_id = Some(storage_id);
                    config
                        .connections
                        .insert(connection_id, ConnectionConfig::from_metadata(metadata));
                }
            }
            Ok(())
        })
    }

    /// Replaces exactly one user-confirmed fingerprint while preserving the
    /// endpoint, server id, storage binding and every credential profile.
    #[cfg(feature = "app")]
    pub(crate) fn replace_verified_fingerprint(
        &self,
        expected_revision: u64,
        connection_id: &ConnectionId,
        expected_old: &str,
        endpoint: &VerifiedEndpointBinding,
    ) -> Result<ConfigSnapshot, ConfigError> {
        let connection_id = connection_id.clone();
        let expected_old = expected_old.to_string();
        let endpoint = endpoint.clone();
        self.mutate(Some(expected_revision), move |config| {
            let connection = config.connections.get_mut(&connection_id).ok_or_else(|| {
                ConfigError::MissingConnection {
                    connection_id: connection_id.clone(),
                }
            })?;
            let normalized = normalize_address(
                &connection.metadata.address,
                &format!("$.connections.{connection_id}.metadata.address"),
            )?;
            if normalized != endpoint.address
                || connection.metadata.server_id.as_deref() != Some(endpoint.server_id())
                || connection.metadata.server_fingerprint.as_deref() != Some(expected_old.as_str())
            {
                return Err(ConfigError::BindingChangeRequiresRebind {
                    connection_id,
                    field: "server_fingerprint",
                });
            }
            connection.metadata.server_fingerprint = Some(endpoint.server_fingerprint);
            Ok(())
        })
    }

    pub fn upsert_connection_if_revision(
        &self,
        expected_revision: u64,
        connection_id: ConnectionId,
        metadata: ConnectionMetadata,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.upsert_connection_checked(Some(expected_revision), connection_id, metadata)
    }

    fn upsert_connection_checked(
        &self,
        expected_revision: Option<u64>,
        connection_id: ConnectionId,
        metadata: ConnectionMetadata,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.mutate(expected_revision, move |config| {
            match config.connections.get_mut(&connection_id) {
                Some(connection) => {
                    if let Some(field) = changed_binding_field(&connection.metadata, &metadata) {
                        return Err(ConfigError::BindingChangeRequiresRebind {
                            connection_id,
                            field,
                        });
                    }
                    connection.metadata = metadata;
                }
                None => {
                    config
                        .connections
                        .insert(connection_id, ConnectionConfig::from_metadata(metadata));
                }
            }
            Ok(())
        })
    }

    pub fn update_connection<F>(
        &self,
        connection_id: &ConnectionId,
        update: F,
    ) -> Result<ConfigSnapshot, ConfigError>
    where
        F: FnOnce(&mut ConnectionMetadata) -> Result<(), ConfigError>,
    {
        self.update_connection_checked(None, connection_id, update)
    }

    pub fn update_connection_if_revision<F>(
        &self,
        expected_revision: u64,
        connection_id: &ConnectionId,
        update: F,
    ) -> Result<ConfigSnapshot, ConfigError>
    where
        F: FnOnce(&mut ConnectionMetadata) -> Result<(), ConfigError>,
    {
        self.update_connection_checked(Some(expected_revision), connection_id, update)
    }

    fn update_connection_checked<F>(
        &self,
        expected_revision: Option<u64>,
        connection_id: &ConnectionId,
        update: F,
    ) -> Result<ConfigSnapshot, ConfigError>
    where
        F: FnOnce(&mut ConnectionMetadata) -> Result<(), ConfigError>,
    {
        let connection_id = connection_id.clone();
        self.mutate(expected_revision, move |config| {
            let connection = config.connections.get_mut(&connection_id).ok_or_else(|| {
                ConfigError::MissingConnection {
                    connection_id: connection_id.clone(),
                }
            })?;
            let previous = connection.metadata.clone();
            update(&mut connection.metadata)?;
            if let Some(field) = changed_binding_field(&previous, &connection.metadata) {
                return Err(ConfigError::BindingChangeRequiresRebind {
                    connection_id,
                    field,
                });
            }
            Ok(())
        })
    }

    pub fn set_active_connection(
        &self,
        client_id: &ClientId,
        connection_id: Option<ConnectionId>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_active_connection_checked(None, client_id, connection_id)
    }

    pub fn set_active_connection_if_revision(
        &self,
        expected_revision: u64,
        client_id: &ClientId,
        connection_id: Option<ConnectionId>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_active_connection_checked(Some(expected_revision), client_id, connection_id)
    }

    fn set_active_connection_checked(
        &self,
        expected_revision: Option<u64>,
        client_id: &ClientId,
        connection_id: Option<ConnectionId>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        let client_id = client_id.clone();
        self.mutate(expected_revision, move |config| {
            if let Some(candidate) = &connection_id {
                if !config.connections.contains_key(candidate) {
                    return Err(ConfigError::MissingConnection {
                        connection_id: candidate.clone(),
                    });
                }
            }
            client_entry(config, &client_id).active_connection = connection_id;
            Ok(())
        })
    }

    pub fn set_cli_default_vault(
        &self,
        connection_id: &ConnectionId,
        vault: String,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_cli_default_vault_checked(None, connection_id, Some(vault))
    }

    pub fn set_cli_default_vault_if_revision(
        &self,
        expected_revision: u64,
        connection_id: &ConnectionId,
        vault: String,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_cli_default_vault_checked(Some(expected_revision), connection_id, Some(vault))
    }

    pub fn remove_cli_default_vault(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_cli_default_vault_checked(None, connection_id, None)
    }

    fn set_cli_default_vault_checked(
        &self,
        expected_revision: Option<u64>,
        connection_id: &ConnectionId,
        vault: Option<String>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        let connection_id = connection_id.clone();
        self.mutate(expected_revision, move |config| {
            if !config.connections.contains_key(&connection_id) {
                return Err(ConfigError::MissingConnection {
                    connection_id: connection_id.clone(),
                });
            }
            let cli_id = ClientId("cli".to_string());
            let client = client_entry(config, &cli_id);
            let ClientNamespace::CliV1(namespace) = &mut client.namespace else {
                return Err(ConfigError::InvalidConfig {
                    path: "$.clients.cli.namespace".to_string(),
                    reason: "CLI namespace has the wrong schema".to_string(),
                });
            };
            match vault {
                Some(vault) => {
                    namespace
                        .default_vault_by_connection
                        .insert(connection_id, vault);
                }
                None => {
                    namespace.default_vault_by_connection.remove(&connection_id);
                }
            }
            Ok(())
        })
    }

    pub fn set_desktop_backup_settings(
        &self,
        settings: Option<DesktopBackupSettings>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_desktop_backup_settings_checked(None, settings)
    }

    pub fn set_desktop_backup_settings_if_revision(
        &self,
        expected_revision: u64,
        settings: Option<DesktopBackupSettings>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_desktop_backup_settings_checked(Some(expected_revision), settings)
    }

    fn set_desktop_backup_settings_checked(
        &self,
        expected_revision: Option<u64>,
        settings: Option<DesktopBackupSettings>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.mutate(expected_revision, move |config| {
            let desktop_id = ClientId("desktop".to_string());
            let client = client_entry(config, &desktop_id);
            let ClientNamespace::DesktopV1(namespace) = &mut client.namespace else {
                return Err(ConfigError::InvalidConfig {
                    path: "$.clients.desktop.namespace".to_string(),
                    reason: "desktop namespace has the wrong schema".to_string(),
                });
            };
            namespace.backup = settings;
            Ok(())
        })
    }

    pub fn restore_backup(&self) -> Result<ConfigSnapshot, ConfigError> {
        // Restore can replace the complete credential topology. Serialize it
        // with refresh/login/logout so a server-side token rotation cannot
        // finish against a generation that restore replaces underneath it.
        // Lock order remains auth operation -> config.
        let _auth_operation = LockKind::AuthOperation
            .pending_at(self.paths.root())?
            .acquire_blocking(LOCK_TIMEOUT)?;
        let _credential_operation = self.credential_operation_lock()?;
        let _lock = self.exclusive_lock()?;
        self.ensure_no_pending_auth_operation_locked()?;
        if self.pending_credential_transaction_locked()?.is_some() {
            return Err(ConfigError::CredentialRecoveryRequired {
                path: self.paths.credential_transaction_journal(),
            });
        }
        let backup_path = self.paths.backup();
        if !validate_regular_file_if_exists(&backup_path)? {
            return Err(ConfigError::MissingBackup { path: backup_path });
        }
        let backup_bytes = read_file(&backup_path, "read config backup")?;
        let mut restored = parse_config(&backup_path, &backup_bytes)?;
        self.ensure_legacy_unchanged(&restored)?;

        match read_file(&self.paths.config(), "read config") {
            Ok(bytes) => match parse_config(&self.paths.config(), &bytes) {
                Ok(current) => {
                    self.ensure_legacy_unchanged(&current)?;
                    restored.revision = current
                        .revision
                        .max(restored.revision)
                        .checked_add(1)
                        .ok_or(ConfigError::RevisionOverflow)?;
                    let journal = RestoreJournal {
                        journal_version: RESTORE_JOURNAL_VERSION,
                        source_primary_digest: byte_digest(&bytes),
                        source_backup_digest: byte_digest(&backup_bytes),
                        target_primary: restored.clone(),
                        target_backup: current,
                    };
                    let journal_bytes = serialize_restore_journal(&journal)?;
                    atomic_write(&self.paths.restore_journal(), &journal_bytes)?;
                    self.apply_restore_journal_locked(&journal)?;
                    return Ok(ConfigSnapshot { config: restored });
                }
                Err(ConfigError::FutureSchema { found, supported }) => {
                    return Err(ConfigError::FutureSchema { found, supported });
                }
                Err(_) => {
                    restored.revision = restored
                        .revision
                        .checked_add(2)
                        .ok_or(ConfigError::RevisionOverflow)?;
                }
            },
            Err(ConfigError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                restored.revision = restored
                    .revision
                    .checked_add(2)
                    .ok_or(ConfigError::RevisionOverflow)?;
            }
            Err(error) => return Err(error),
        }
        let bytes = serialize_config(&restored)?;
        atomic_write(&self.paths.config(), &bytes)?;
        Ok(ConfigSnapshot { config: restored })
    }

    fn mutate<F>(
        &self,
        expected_revision: Option<u64>,
        update: F,
    ) -> Result<ConfigSnapshot, ConfigError>
    where
        F: FnOnce(&mut ConfigV2) -> Result<(), ConfigError>,
    {
        let _lock = self.exclusive_lock()?;
        self.ensure_no_pending_auth_operation_locked()?;
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Err(ConfigError::MissingConfig { path: primary_path });
        }
        let previous_bytes = read_file(&primary_path, "read config")?;
        let mut config = parse_config(&primary_path, &previous_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        if let Some(expected) = expected_revision {
            if config.revision != expected {
                return Err(ConfigError::RevisionConflict {
                    expected,
                    actual: config.revision,
                });
            }
        }
        update(&mut config)?;
        config.revision = config
            .revision
            .checked_add(1)
            .ok_or(ConfigError::RevisionOverflow)?;
        let next_bytes = serialize_config(&config)?;

        atomic_write(&self.paths.backup(), &previous_bytes)?;
        atomic_write(&primary_path, &next_bytes)?;
        Ok(ConfigSnapshot { config })
    }

    fn reconcile_failed_credential_intent(
        &self,
        credential_store: &dyn CredentialStore,
        intended_ids: &BTreeSet<CredentialId>,
    ) -> Vec<CredentialTransactionWarning> {
        match self.reconcile_credentials_with_operation_lock(credential_store) {
            Ok(outcome) => outcome.warnings,
            Err(error) => vec![CredentialTransactionWarning::CleanupDeferred {
                credential_ids: intended_ids.iter().cloned().collect(),
                reason: error.to_string(),
            }],
        }
    }

    fn durable_referenced_credential_ids_locked(
        &self,
    ) -> Result<BTreeSet<CredentialId>, ConfigError> {
        let primary = self.read_primary()?;
        self.ensure_legacy_unchanged(&primary)?;
        let mut referenced = referenced_credential_ids(&primary);
        if let Some((backup, _)) =
            self.read_optional_durable_config_with_digest(&self.paths.backup())?
        {
            referenced.extend(referenced_credential_ids(&backup));
        }
        let restore_path = self.paths.restore_journal();
        if validate_regular_file_if_exists(&restore_path)? {
            let bytes = read_file(
                &restore_path,
                "read restore journal for credential reachability",
            )?;
            let restore = parse_restore_journal(&restore_path, &bytes)?;
            referenced.extend(referenced_credential_ids(&restore.target_primary));
            referenced.extend(referenced_credential_ids(&restore.target_backup));
        }
        Ok(referenced)
    }

    fn read_optional_durable_config_with_digest(
        &self,
        path: &Path,
    ) -> Result<Option<(ConfigV2, String)>, ConfigError> {
        if !validate_regular_file_if_exists(path)? {
            return Ok(None);
        }
        let bytes = read_file(path, "read durable config generation")?;
        let config = parse_config(path, &bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        Ok(Some((config, byte_digest(&bytes))))
    }

    fn read_primary(&self) -> Result<ConfigV2, ConfigError> {
        let path = self.paths.config();
        if !validate_regular_file_if_exists(&path)? {
            return Err(ConfigError::MissingConfig { path });
        }
        let bytes = read_file(&path, "read config")?;
        parse_config(&path, &bytes)
    }

    fn ensure_legacy_unchanged(&self, config: &ConfigV2) -> Result<(), ConfigError> {
        let Some(migration) = &config.migration else {
            return Ok(());
        };
        let actual = LegacyInput::read(&self.paths)?.digest;
        if migration.source_digest != actual {
            return Err(ConfigError::LegacyDiverged {
                expected: migration.source_digest.clone(),
                actual,
            });
        }
        Ok(())
    }

    fn complete_pending_restore_locked(&self) -> Result<(), ConfigError> {
        let journal_path = self.paths.restore_journal();
        if !validate_regular_file_if_exists(&journal_path)? {
            return Ok(());
        }
        let bytes = read_file(&journal_path, "read restore journal")?;
        let journal = parse_restore_journal(&journal_path, &bytes)?;
        self.apply_restore_journal_locked(&journal)
    }

    fn apply_restore_journal_locked(&self, journal: &RestoreJournal) -> Result<(), ConfigError> {
        let target_backup = serialize_config(&journal.target_backup)?;
        let target_primary = serialize_config(&journal.target_primary)?;
        let state = self.restore_state(journal, &target_primary, &target_backup)?;
        if state != RestoreState::Complete {
            atomic_write(&self.paths.backup(), &target_backup)?;
            atomic_write(&self.paths.config(), &target_primary)?;
        }
        let journal_path = self.paths.restore_journal();
        validate_regular_file_if_exists(&journal_path)?;
        fs::remove_file(&journal_path).map_err(|source| ConfigError::Io {
            operation: "remove completed restore journal",
            path: journal_path,
            source,
        })?;
        sync_parent(self.paths.root())
    }

    fn restore_state(
        &self,
        journal: &RestoreJournal,
        target_primary: &[u8],
        target_backup: &[u8],
    ) -> Result<RestoreState, ConfigError> {
        let primary_path = self.paths.config();
        let backup_path = self.paths.backup();
        let primary = self.read_restore_component(
            &primary_path,
            "read config for restore replay",
            "primary",
        )?;
        let backup = self.read_restore_component(
            &backup_path,
            "read config backup for restore replay",
            "backup",
        )?;

        if let Err(ConfigError::FutureSchema { found, supported }) =
            parse_config(&primary_path, &primary)
        {
            return Err(ConfigError::FutureSchema { found, supported });
        }
        if let Err(ConfigError::FutureSchema { found, supported }) =
            parse_config(&backup_path, &backup)
        {
            return Err(ConfigError::FutureSchema { found, supported });
        }

        let primary_digest = byte_digest(&primary);
        let backup_digest = byte_digest(&backup);
        let target_primary_digest = byte_digest(target_primary);
        let target_backup_digest = byte_digest(target_backup);
        let state = if primary_digest == journal.source_primary_digest
            && backup_digest == journal.source_backup_digest
        {
            RestoreState::Initial
        } else if primary_digest == journal.source_primary_digest
            && backup_digest == target_backup_digest
        {
            RestoreState::BackupWritten
        } else if primary_digest == target_primary_digest && backup_digest == target_backup_digest {
            RestoreState::Complete
        } else {
            return Err(ConfigError::RestoreJournalConflict {
                path: self.paths.restore_journal(),
                reason: "primary/backup digests do not match an allowed restore state".to_string(),
            });
        };
        Ok(state)
    }

    fn read_restore_component(
        &self,
        path: &Path,
        operation: &'static str,
        component: &'static str,
    ) -> Result<Vec<u8>, ConfigError> {
        match read_file(path, operation) {
            Ok(bytes) => Ok(bytes),
            Err(ConfigError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                Err(ConfigError::RestoreJournalConflict {
                    path: self.paths.restore_journal(),
                    reason: format!("restore {component} is missing"),
                })
            }
            Err(error) => Err(error),
        }
    }

    fn exclusive_lock(&self) -> Result<ConfigFileLockGuard, ConfigError> {
        let file = self.exclusive_lock_allow_credential_journal()?;
        if let Some((_, state, _)) = self.pending_credential_transaction_locked()? {
            if matches!(
                state,
                CredentialTransactionState::Initial | CredentialTransactionState::BackupWritten
            ) {
                return Err(ConfigError::CredentialRecoveryRequired {
                    path: self.paths.credential_transaction_journal(),
                });
            }
        }
        Ok(file)
    }

    fn credential_operation_lock(&self) -> Result<FileLockGuard, ConfigError> {
        let operation = LockKind::CredentialOperation
            .pending_at(self.paths.root())?
            .acquire_blocking(LOCK_TIMEOUT)?;
        {
            let _lock = self.exclusive_lock_allow_credential_journal()?;
            self.ensure_no_pending_auth_operation_locked()?;
        }
        Ok(operation)
    }

    fn ensure_no_pending_auth_operation_locked(&self) -> Result<(), ConfigError> {
        let path = self.paths.auth_operation_intent();
        if validate_regular_file_if_exists(&path)? {
            return Err(ConfigError::AuthOperationRecoveryRequired { path });
        }
        Ok(())
    }

    fn ensure_no_pending_sync_generation_recovery_locked(&self) -> Result<(), ConfigError> {
        self.ensure_no_pending_auth_operation_locked()?;
        if self
            .pending_credential_transaction_locked()?
            .is_some_and(|(_, state, _)| {
                matches!(
                    state,
                    CredentialTransactionState::Initial | CredentialTransactionState::BackupWritten
                )
            })
        {
            return Err(ConfigError::CredentialRecoveryRequired {
                path: self.paths.credential_transaction_journal(),
            });
        }
        let restore_path = self.paths.restore_journal();
        if validate_regular_file_if_exists(&restore_path)? {
            return Err(ConfigError::RestoreJournalConflict {
                path: restore_path,
                reason: "pending restore blocks sync generation validation".to_string(),
            });
        }
        Ok(())
    }

    fn exclusive_lock_allow_credential_journal(&self) -> Result<ConfigFileLockGuard, ConfigError> {
        let lock = ConfigFileLockGuard::acquire(self.paths.root(), LOCK_TIMEOUT)?;
        let restore_pending = validate_regular_file_if_exists(&self.paths.restore_journal())?;
        if restore_pending && validate_regular_file_if_exists(&self.paths.auth_operation_intent())?
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "restore and authentication intents coexist; automatic replay is blocked"
                    .to_string(),
            });
        }
        if restore_pending
            && validate_regular_file_if_exists(&self.paths.credential_transaction_journal())?
        {
            return Err(ConfigError::CredentialRecoveryRequired {
                path: self.paths.credential_transaction_journal(),
            });
        }
        self.complete_pending_restore_locked()?;
        Ok(lock)
    }

    fn pending_credential_transaction_locked(
        &self,
    ) -> Result<
        Option<(
            CredentialTransactionJournal,
            CredentialTransactionState,
            Vec<u8>,
        )>,
        ConfigError,
    > {
        let journal_path = self.paths.credential_transaction_journal();
        if !validate_regular_file_if_exists(&journal_path)? {
            return Ok(None);
        }
        let journal_bytes = read_file(&journal_path, "read credential transaction journal")?;
        let journal = parse_credential_transaction_journal(&journal_path, &journal_bytes)?;
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Err(ConfigError::CredentialTransactionJournalConflict {
                path: journal_path,
                reason: "primary config is missing".to_string(),
            });
        }
        let primary_bytes = read_file(
            &primary_path,
            "read primary for credential transaction recovery",
        )?;
        let primary = parse_config(&primary_path, &primary_bytes)?;
        let primary_generation = credential_generation(&primary, byte_digest(&primary_bytes));
        let current_backup = self
            .read_optional_durable_config_with_digest(&self.paths.backup())?
            .map(|(config, digest)| credential_generation(&config, digest));
        let original_backup_matches = current_backup == journal.source_backup;
        let source_backup_written = current_backup.as_ref() == Some(&journal.source_primary);
        let source_exact = primary_generation == journal.source_primary;
        let state = if journal.aborted {
            let cleanup_descendant = primary_generation.revision > journal.source_primary.revision
                && primary_generation.slots == journal.source_primary.slots
                && primary_generation.migration_digest == journal.source_primary.migration_digest;
            if (source_exact && (original_backup_matches || source_backup_written))
                || cleanup_descendant
            {
                CredentialTransactionState::Cleanup
            } else {
                return Err(ConfigError::CredentialTransactionJournalConflict {
                    path: journal_path,
                    reason: "aborted credential intent is not anchored to its source or descendant"
                        .to_string(),
                });
            }
        } else if source_exact {
            if original_backup_matches {
                CredentialTransactionState::Initial
            } else if source_backup_written {
                CredentialTransactionState::BackupWritten
            } else {
                return Err(ConfigError::CredentialTransactionJournalConflict {
                    path: journal_path,
                    reason: "credential source primary has an unexpected backup generation"
                        .to_string(),
                });
            }
        } else {
            let committed_exact = primary_generation == journal.candidate && source_backup_written;
            let committed_descendant = primary_generation.revision > journal.candidate.revision
                && primary_generation.slots == journal.candidate.slots
                && primary_generation.migration_digest == journal.candidate.migration_digest;
            if committed_exact || committed_descendant {
                CredentialTransactionState::Committed
            } else {
                return Err(ConfigError::CredentialTransactionJournalConflict {
                    path: journal_path,
                    reason: "primary/backup do not match source, committed candidate, or a valid descendant"
                        .to_string(),
                });
            }
        };
        Ok(Some((journal, state, journal_bytes)))
    }

    fn pending_auth_operation_intent_locked(
        &self,
    ) -> Result<Option<(AuthOperationIntent, Vec<u8>)>, ConfigError> {
        let path = self.paths.auth_operation_intent();
        if !validate_regular_file_if_exists(&path)? {
            return Ok(None);
        }
        let bytes = read_file(&path, "read authentication operation intent")?;
        let intent = parse_auth_operation_intent(&path, &bytes)?;
        Ok(Some((intent, bytes)))
    }

    fn ensure_owned_auth_operation_intent_locked(
        &self,
        permit: &AuthOperationIntentPermit,
    ) -> Result<(AuthOperationIntent, Vec<u8>), ConfigError> {
        let Some((intent, bytes)) = self.pending_auth_operation_intent_locked()? else {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "owned authentication intent disappeared".to_string(),
            });
        };
        if byte_digest(&bytes) != permit.journal_bytes_digest
            || intent.operation_id != permit.operation_id
            || intent.operation != permit.operation
            || auth_intent_source_anchor(&intent) != permit.anchor
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "authentication intent ownership proof no longer matches".to_string(),
            });
        }
        Ok((intent, bytes))
    }

    fn ensure_owned_password_login_intent_locked(
        &self,
        permit: &PasswordLoginIntentPermit,
    ) -> Result<(AuthOperationIntent, Vec<u8>), ConfigError> {
        let Some((intent, bytes)) = self.pending_auth_operation_intent_locked()? else {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "owned password-login intent disappeared".to_string(),
            });
        };
        let reservation_matches = intent.reserved_login.as_ref() == Some(&permit.reservation);
        let source_matches = intent.repository_binding_digest
            == permit.anchor.repository_binding_digest
            && intent.connection_id == permit.anchor.connection_id
            && intent.profile_name == permit.anchor.profile_name
            && intent.endpoint.address == permit.anchor.normalized_address
            && intent.endpoint.server_id == permit.anchor.server_id
            && intent.endpoint.server_fingerprint == permit.anchor.server_fingerprint
            && intent.endpoint.storage_id == permit.anchor.storage_id
            && intent.source.revision == permit.anchor.source_revision
            && intent.source.raw_digest == permit.anchor.source_digest
            && intent.client_id.as_ref() == Some(&permit.anchor.client_id);
        if byte_digest(&bytes) != permit.journal_bytes_digest
            || intent.journal_version != AUTH_OPERATION_INTENT_VERSION
            || intent.operation_id != permit.operation_id
            || intent.operation != AuthOperationKind::PasswordLogin
            || !reservation_matches
            || !source_matches
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login intent ownership proof no longer matches".to_string(),
            });
        }
        Ok((intent, bytes))
    }

    fn install_password_login_candidate_locked(
        &self,
        permit: &mut PasswordLoginIntentPermit,
        plan: &CredentialTransactionPlan,
        account_subject: &str,
    ) -> Result<(), ConfigError> {
        let (mut intent, _) = self.ensure_owned_password_login_intent_locked(permit)?;
        if intent.state != AuthOperationIntentState::Armed
            || intent.candidate_rotation.is_some()
            || intent.candidate_login.is_some()
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login intent already has a candidate".to_string(),
            });
        }
        if plan.journal.source_primary.revision != intent.source.revision
            || plan.journal.source_primary.raw_digest != intent.source.raw_digest
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login candidate source differs from the armed source".to_string(),
            });
        }
        let profile = plan
            .candidate_config
            .connections
            .get(&intent.connection_id)
            .and_then(|connection| connection.credential_profiles.get(&intent.profile_name))
            .ok_or_else(|| ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login candidate has no target profile".to_string(),
            })?;
        let reservation = intent.reserved_login.as_ref().ok_or_else(|| {
            ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login candidate has no credential reservation".to_string(),
            }
        })?;
        if profile.account_subject.as_deref() != Some(account_subject)
            || profile.auth_method != Some(AuthMethod::Password)
            || profile.credentials.get(&CredentialKind::Access)
                != Some(&reservation.access_credential_id)
            || profile.credentials.get(&CredentialKind::Refresh)
                != Some(&reservation.refresh_credential_id)
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login candidate binding or credential topology is inconsistent"
                    .to_string(),
            });
        }
        let access_expires_at = profile.access_expires_at.clone().ok_or_else(|| {
            ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login candidate has no access expiry".to_string(),
            }
        })?;
        intent.state = AuthOperationIntentState::CandidatePrepared;
        intent.candidate_login = Some(AuthIntentLoginCandidate {
            revision: plan.candidate_config.revision,
            raw_digest: byte_digest(&plan.candidate_bytes),
            account_subject: account_subject.to_string(),
            auth_method: AuthMethod::Password,
            access_expires_at,
            access_credential_id: reservation.access_credential_id.clone(),
            refresh_credential_id: reservation.refresh_credential_id.clone(),
        });
        let candidate = intent.candidate_login.clone();
        let bytes = serialize_auth_operation_intent(&intent, self.paths.root())?;
        atomic_write(&self.paths.auth_operation_intent(), &bytes)?;
        permit.journal_bytes_digest = byte_digest(&bytes);
        permit.candidate = candidate;
        Ok(())
    }

    fn accept_owned_password_login_locked(
        &self,
        permit: &PasswordLoginIntentPermit,
    ) -> Result<(), ConfigError> {
        let (intent, bytes) = self.ensure_owned_password_login_intent_locked(permit)?;
        if intent.state != AuthOperationIntentState::CandidatePrepared
            || !matches!(
                self.classify_auth_operation_intent_locked(&intent)?,
                AuthIntentState::Candidate
            )
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "owned password login is not the exact durable candidate".to_string(),
            });
        }
        self.remove_auth_operation_intent_locked(&bytes)
    }

    fn install_auth_rotation_candidate_locked(
        &self,
        permit: &mut AuthOperationIntentPermit,
        plan: &CredentialTransactionPlan,
    ) -> Result<(), ConfigError> {
        let (mut intent, _source_intent_bytes) =
            self.ensure_owned_auth_operation_intent_locked(permit)?;
        if intent.state != AuthOperationIntentState::Armed || intent.candidate_rotation.is_some() {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "authentication intent already has a rotation candidate".to_string(),
            });
        }
        if plan.journal.source_primary.revision != intent.source.revision
            || plan.journal.source_primary.raw_digest != intent.source.raw_digest
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "credential transaction source does not match the armed auth intent"
                    .to_string(),
            });
        }
        let profile = plan
            .candidate_config
            .connections
            .get(&intent.connection_id)
            .and_then(|connection| connection.credential_profiles.get(&intent.profile_name))
            .ok_or_else(|| ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "rotation candidate does not contain the intended profile".to_string(),
            })?;
        let access_credential_id = plan
            .credential_ids
            .get(&CredentialKind::Access)
            .cloned()
            .ok_or_else(|| ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "rotation candidate has no new access credential id".to_string(),
            })?;
        let refresh_credential_id = plan
            .credential_ids
            .get(&CredentialKind::Refresh)
            .cloned()
            .ok_or_else(|| ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "rotation candidate has no new refresh credential id".to_string(),
            })?;
        if profile.credentials.get(&CredentialKind::Access) != Some(&access_credential_id)
            || profile.credentials.get(&CredentialKind::Refresh) != Some(&refresh_credential_id)
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "rotation candidate credential topology is inconsistent".to_string(),
            });
        }
        let access_expires_at = profile.access_expires_at.clone().ok_or_else(|| {
            ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "rotation candidate has no access expiry".to_string(),
            }
        })?;
        intent.state = AuthOperationIntentState::CandidatePrepared;
        intent.candidate_rotation = Some(AuthIntentRotationCandidate {
            revision: plan.candidate_config.revision,
            raw_digest: byte_digest(&plan.candidate_bytes),
            access_expires_at,
            access_credential_id,
            refresh_credential_id,
        });
        let bytes = serialize_auth_operation_intent(&intent, self.paths.root())?;
        atomic_write(&self.paths.auth_operation_intent(), &bytes)?;
        permit.journal_bytes_digest = byte_digest(&bytes);
        Ok(())
    }

    fn accept_owned_auth_rotation_locked(
        &self,
        permit: &AuthOperationIntentPermit,
    ) -> Result<(), ConfigError> {
        let (intent, bytes) = self.ensure_owned_auth_operation_intent_locked(permit)?;
        if intent.state != AuthOperationIntentState::CandidatePrepared
            || !matches!(
                self.classify_auth_operation_intent_locked(&intent)?,
                AuthIntentState::Candidate
            )
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "owned rotation is not the exact durable candidate".to_string(),
            });
        }
        self.remove_auth_operation_intent_locked(&bytes)
    }

    fn classify_auth_operation_intent_locked(
        &self,
        intent: &AuthOperationIntent,
    ) -> Result<AuthIntentState, ConfigError> {
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "primary config is missing".to_string(),
            });
        }
        let primary_bytes = read_file(&primary_path, "read config for auth recovery")?;
        let config = parse_config(&primary_path, &primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        let digest = byte_digest(&primary_bytes);
        if config.revision == intent.source.revision && digest == intent.source.raw_digest {
            if intent.operation == AuthOperationKind::PasswordLogin {
                return Ok(AuthIntentState::LoginSource);
            }
            let anchor = auth_intent_source_anchor(intent);
            ensure_credential_profile_anchor_matches(
                &anchor,
                &credential_profile_anchor_repository_binding(self.paths.root())?,
                &config,
                &digest,
            )?;
            return Ok(AuthIntentState::Source(Box::new(anchor)));
        }
        let Some(connection) = config.connections.get(&intent.connection_id) else {
            return Ok(AuthIntentState::TargetRemoved);
        };
        let Some(profile) = connection.credential_profiles.get(&intent.profile_name) else {
            return Ok(AuthIntentState::TargetRemoved);
        };

        if let Some(candidate) = &intent.candidate_login {
            if config.revision == candidate.revision && digest == candidate.raw_digest {
                let normalized_address = normalize_address(
                    &connection.metadata.address,
                    &format!("$.connections.{}.metadata.address", intent.connection_id),
                )?;
                let endpoint_matches = normalized_address == intent.endpoint.address
                    && connection.metadata.server_id.as_deref()
                        == Some(intent.endpoint.server_id.as_str())
                    && connection.metadata.server_fingerprint.as_deref()
                        == Some(intent.endpoint.server_fingerprint.as_str())
                    && connection.metadata.storage_id == intent.endpoint.storage_id;
                let mut expected_credentials = intent.source.credentials.clone();
                expected_credentials.insert(
                    CredentialKind::Access,
                    candidate.access_credential_id.clone(),
                );
                expected_credentials.insert(
                    CredentialKind::Refresh,
                    candidate.refresh_credential_id.clone(),
                );
                let activation_matches = connection.active_credential.as_deref()
                    == Some(intent.profile_name.as_str())
                    && intent.client_id.as_ref().is_some_and(|client_id| {
                        config
                            .clients
                            .get(client_id)
                            .and_then(|client| client.active_connection.as_ref())
                            == Some(&intent.connection_id)
                    });
                if endpoint_matches
                    && activation_matches
                    && profile.credentials == expected_credentials
                    && profile.account_subject.as_deref()
                        == Some(candidate.account_subject.as_str())
                    && profile.auth_method == Some(candidate.auth_method)
                    && profile.access_expires_at.as_deref()
                        == Some(candidate.access_expires_at.as_str())
                {
                    return Ok(AuthIntentState::Candidate);
                }
            }
        }

        if let Some(candidate) = &intent.candidate_rotation {
            if config.revision == candidate.revision && digest == candidate.raw_digest {
                let normalized_address = normalize_address(
                    &connection.metadata.address,
                    &format!("$.connections.{}.metadata.address", intent.connection_id),
                )?;
                let endpoint_matches = normalized_address == intent.endpoint.address
                    && connection.metadata.server_id.as_deref()
                        == Some(intent.endpoint.server_id.as_str())
                    && connection.metadata.server_fingerprint.as_deref()
                        == Some(intent.endpoint.server_fingerprint.as_str())
                    && connection.metadata.storage_id == intent.endpoint.storage_id;
                let mut expected_credentials = intent.source.credentials.clone();
                expected_credentials.insert(
                    CredentialKind::Access,
                    candidate.access_credential_id.clone(),
                );
                expected_credentials.insert(
                    CredentialKind::Refresh,
                    candidate.refresh_credential_id.clone(),
                );
                if endpoint_matches
                    && profile.credentials == expected_credentials
                    && profile.access_expires_at.as_deref()
                        == Some(candidate.access_expires_at.as_str())
                {
                    return Ok(AuthIntentState::Candidate);
                }
            }
        }

        Err(ConfigError::AuthOperationIntentConflict {
            path: self.paths.auth_operation_intent(),
            reason: "primary config is neither the exact source, exact rotation candidate, nor a removed target"
                .to_string(),
        })
    }

    fn remove_auth_operation_intent_locked(
        &self,
        expected_bytes: &[u8],
    ) -> Result<(), ConfigError> {
        let path = self.paths.auth_operation_intent();
        let current = read_file(&path, "read authentication intent before removal")?;
        if current != expected_bytes {
            return Err(ConfigError::AuthOperationIntentConflict {
                path,
                reason: "authentication intent changed before durable removal".to_string(),
            });
        }
        fs::remove_file(&path).map_err(|source| ConfigError::Io {
            operation: "remove authentication operation intent",
            path: path.clone(),
            source,
        })?;
        sync_parent(self.paths.root())
    }

    fn remove_credential_transaction_journal_locked(&self) -> Result<(), ConfigError> {
        let path = self.paths.credential_transaction_journal();
        if !validate_regular_file_if_exists(&path)? {
            return Ok(());
        }
        fs::remove_file(&path).map_err(|source| ConfigError::Io {
            operation: "remove completed credential transaction journal",
            path,
            source,
        })?;
        sync_parent(self.paths.root())
    }
}

fn preflight_credential_slots(
    credential_store: &dyn CredentialStore,
    credential_ids: &BTreeMap<CredentialKind, CredentialId>,
) -> Result<(), ConfigError> {
    for credential_id in credential_ids.values() {
        let existing =
            credential_store
                .get(credential_id)
                .map_err(|source| ConfigError::CredentialStore {
                    operation: "preflight read",
                    credential_id: credential_id.clone(),
                    source,
                })?;
        if existing.is_some() {
            return Err(ConfigError::CredentialIdConflict {
                credential_id: credential_id.clone(),
            });
        }
    }
    Ok(())
}

fn prepare_credential_slots(
    credential_store: &dyn CredentialStore,
    bundle: &CredentialBundle,
    credential_ids: &BTreeMap<CredentialKind, CredentialId>,
    created_ids: &mut BTreeSet<CredentialId>,
) -> Result<(), ConfigError> {
    for (kind, credential_id) in credential_ids {
        let secret = bundle
            .secret(*kind)
            .ok_or_else(|| ConfigError::InvalidConfig {
                path: "$.credential_transaction".to_string(),
                reason: format!("planned {kind:?} credential has no secret"),
            })?;
        // Preflight proved this repository-private id absent before the durable intent.
        // It is now an attempt-owned cleanup candidate even when a backend writes then errors.
        created_ids.insert(credential_id.clone());

        if let Err(source) = credential_store.put(credential_id, secret) {
            let put_error = ConfigError::CredentialStore {
                operation: "write",
                credential_id: credential_id.clone(),
                source,
            };
            if let Ok(Some(actual)) = credential_store.get(credential_id) {
                if actual.expose_secret() == secret.expose_secret() {
                    continue;
                }
            }
            return Err(put_error);
        }
        let verified =
            credential_store
                .get(credential_id)
                .map_err(|source| ConfigError::CredentialStore {
                    operation: "verify",
                    credential_id: credential_id.clone(),
                    source,
                })?;
        if verified
            .as_ref()
            .is_none_or(|actual| actual.expose_secret() != secret.expose_secret())
        {
            return Err(ConfigError::CredentialVerification {
                credential_id: credential_id.clone(),
            });
        }
    }
    Ok(())
}

fn referenced_credential_ids(config: &ConfigV2) -> BTreeSet<CredentialId> {
    config
        .connections
        .values()
        .flat_map(|connection| connection.credential_profiles.values())
        .flat_map(|profile| profile.credentials.values().cloned())
        .collect()
}

fn credential_slot_refs(config: &ConfigV2) -> BTreeSet<CredentialSlotRef> {
    config
        .connections
        .iter()
        .flat_map(|(connection_id, connection)| {
            connection
                .credential_profiles
                .iter()
                .flat_map(move |(profile_name, profile)| {
                    profile
                        .credentials
                        .iter()
                        .map(move |(kind, credential_id)| CredentialSlotRef {
                            connection_id: connection_id.clone(),
                            profile_name: profile_name.clone(),
                            kind: *kind,
                            credential_id: credential_id.clone(),
                        })
                })
        })
        .collect()
}

fn credential_generation(config: &ConfigV2, raw_digest: String) -> CredentialGeneration {
    CredentialGeneration {
        revision: config.revision,
        raw_digest,
        migration_digest: config
            .migration
            .as_ref()
            .map(|migration| migration.source_digest.clone()),
        slots: credential_slot_refs(config),
    }
}

fn credential_ids_from_slots<'a>(
    slots: impl IntoIterator<Item = &'a CredentialSlotRef>,
) -> BTreeSet<CredentialId> {
    slots
        .into_iter()
        .map(|slot| slot.credential_id.clone())
        .collect()
}

fn credential_cleanup_targets(
    journal: &CredentialTransactionJournal,
    state: CredentialTransactionState,
) -> BTreeSet<CredentialId> {
    match state {
        CredentialTransactionState::Initial | CredentialTransactionState::BackupWritten => {
            journal.new_ids.clone()
        }
        CredentialTransactionState::Committed | CredentialTransactionState::Cleanup => journal
            .retired_slots
            .iter()
            .map(|slot| slot.credential_id.clone())
            .filter(|credential_id| !journal.settled_retired_ids.contains(credential_id))
            .collect(),
    }
}

fn with_cleanup_warnings(
    source: ConfigError,
    warnings: Vec<CredentialTransactionWarning>,
) -> ConfigError {
    if warnings.is_empty() {
        source
    } else {
        ConfigError::CredentialTransactionCleanup {
            source: Box::new(source),
            warnings,
        }
    }
}

fn read_file(path: &Path, operation: &'static str) -> Result<Vec<u8>, ConfigError> {
    validate_regular_file_if_exists(path)?;
    let file = File::open(path).map_err(|source| ConfigError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| ConfigError::Io {
        operation: "inspect open config file",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(ConfigError::UnsafePath {
            path: path.to_path_buf(),
            reason: "opened path is not a regular file".to_string(),
        });
    }
    let limit = json_size_limit(path);
    if metadata.len() > limit {
        return Err(ConfigError::ConfigTooLarge {
            path: path.to_path_buf(),
            max_bytes: limit,
        });
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ConfigError::Io {
            operation,
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        bytes.zeroize();
        return Err(ConfigError::ConfigTooLarge {
            path: path.to_path_buf(),
            max_bytes: limit,
        });
    }
    Ok(bytes)
}

fn json_size_limit(path: &Path) -> u64 {
    match path.file_name().and_then(|name| name.to_str()) {
        Some(CONFIG_RESTORE_JOURNAL_FILENAME) => RESTORE_JOURNAL_MAX_BYTES,
        Some(CREDENTIAL_TRANSACTION_JOURNAL_FILENAME) => CREDENTIAL_TRANSACTION_JOURNAL_MAX_BYTES,
        Some(AUTH_OPERATION_INTENT_FILENAME) => AUTH_OPERATION_INTENT_MAX_BYTES,
        _ => CONFIG_MAX_BYTES,
    }
}

#[derive(Clone)]
struct DuplicateFreeJson {
    nodes: Rc<Cell<usize>>,
    max_nodes: usize,
}

impl DuplicateFreeJson {
    fn new(max_nodes: usize) -> Self {
        Self {
            nodes: Rc::new(Cell::new(0)),
            max_nodes,
        }
    }

    fn consume<E: de::Error>(&self) -> Result<(), E> {
        let next = self.nodes.get().checked_add(1).ok_or_else(|| {
            de::Error::custom("JSON node/member budget exceeds addressable range")
        })?;
        if next > self.max_nodes {
            return Err(de::Error::custom("JSON node/member budget exceeded"));
        }
        self.nodes.set(next);
        Ok(())
    }
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct ZeroizingJsonKey(String);

impl Drop for ZeroizingJsonKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> DeserializeSeed<'de> for DuplicateFreeJson {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.consume()?;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DuplicateFreeJson {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("valid JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E> {
        value.zeroize();
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(self.clone())?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            self.consume()?;
            if !seen.insert(ZeroizingJsonKey(key)) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            map.next_value_seed(self.clone())?;
        }
        Ok(())
    }
}

fn validate_json_shape(bytes: &[u8], max_nodes: usize) -> Result<(), serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateFreeJson::new(max_nodes).deserialize(&mut deserializer)?;
    deserializer.end()
}

fn parse_config(path: &Path, bytes: &[u8]) -> Result<ConfigV2, ConfigError> {
    validate_json_shape(bytes, JSON_NODE_LIMIT).map_err(|source| ConfigError::Malformed {
        path: path.to_path_buf(),
        source,
    })?;
    let probe: ConfigVersionProbe =
        serde_json::from_slice(bytes).map_err(|source| ConfigError::Malformed {
            path: path.to_path_buf(),
            source,
        })?;
    let version = probe
        .schema_version
        .ok_or_else(|| ConfigError::MissingSchemaVersion {
            path: path.to_path_buf(),
        })?;
    if version > u64::from(CONFIG_SCHEMA_VERSION) {
        return Err(ConfigError::FutureSchema {
            found: version,
            supported: CONFIG_SCHEMA_VERSION,
        });
    }
    if version != u64::from(CONFIG_SCHEMA_VERSION) {
        return Err(ConfigError::UnsupportedSchema {
            found: version,
            supported: CONFIG_SCHEMA_VERSION,
        });
    }
    let config: ConfigV2 =
        serde_json::from_slice(bytes).map_err(|source| ConfigError::Malformed {
            path: path.to_path_buf(),
            source,
        })?;
    validate_config(&config)?;
    if let Some(repository_root) = path.parent() {
        validate_repository_credential_ids(&config, repository_root)?;
    }
    Ok(config)
}

struct LimitedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl LimitedBuffer {
    fn new(limit: u64) -> Self {
        Self {
            bytes: Vec::new(),
            limit: limit as usize,
            exceeded: false,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for LimitedBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(next_len) = self.bytes.len().checked_add(buffer.len()) else {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized JSON exceeds configured limit",
            ));
        };
        if next_len > self.limit {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized JSON exceeds configured limit",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialize_bounded<T: Serialize>(
    value: &T,
    limit: u64,
    logical_path: &str,
) -> Result<Vec<u8>, ConfigError> {
    let mut output = LimitedBuffer::new(limit);
    if let Err(source) = serde_json::to_writer_pretty(&mut output, value) {
        if output.exceeded {
            return Err(ConfigError::ConfigTooLarge {
                path: PathBuf::from(logical_path),
                max_bytes: limit,
            });
        }
        return Err(ConfigError::Serialization(source));
    }
    if output.write_all(b"\n").is_err() {
        return Err(ConfigError::ConfigTooLarge {
            path: PathBuf::from(logical_path),
            max_bytes: limit,
        });
    }
    Ok(output.finish())
}

fn serialize_config(config: &ConfigV2) -> Result<Vec<u8>, ConfigError> {
    validate_config(config)?;
    serialize_bounded(config, CONFIG_MAX_BYTES, CONFIG_V2_FILENAME)
}

fn parse_restore_journal(path: &Path, bytes: &[u8]) -> Result<RestoreJournal, ConfigError> {
    validate_json_shape(bytes, RESTORE_JOURNAL_NODE_LIMIT).map_err(|source| {
        ConfigError::MalformedRestoreJournal {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let probe: RestoreVersionProbe =
        serde_json::from_slice(bytes).map_err(|source| ConfigError::MalformedRestoreJournal {
            path: path.to_path_buf(),
            source,
        })?;
    let version =
        probe
            .journal_version
            .ok_or_else(|| ConfigError::MissingRestoreJournalVersion {
                path: path.to_path_buf(),
            })?;
    if version > u64::from(RESTORE_JOURNAL_VERSION) {
        return Err(ConfigError::FutureRestoreJournal {
            found: version,
            supported: RESTORE_JOURNAL_VERSION,
        });
    }
    if version != u64::from(RESTORE_JOURNAL_VERSION) {
        return Err(ConfigError::UnsupportedRestoreJournal {
            found: version,
            supported: RESTORE_JOURNAL_VERSION,
        });
    }
    let journal: RestoreJournal =
        serde_json::from_slice(bytes).map_err(|source| ConfigError::MalformedRestoreJournal {
            path: path.to_path_buf(),
            source,
        })?;
    validate_restore_journal(&journal)?;
    if let Some(repository_root) = path.parent() {
        validate_repository_credential_ids(&journal.target_primary, repository_root)?;
        validate_repository_credential_ids(&journal.target_backup, repository_root)?;
    }
    Ok(journal)
}

fn serialize_restore_journal(journal: &RestoreJournal) -> Result<Vec<u8>, ConfigError> {
    validate_restore_journal(journal)?;
    serialize_bounded(
        journal,
        RESTORE_JOURNAL_MAX_BYTES,
        CONFIG_RESTORE_JOURNAL_FILENAME,
    )
}

fn validate_restore_journal(journal: &RestoreJournal) -> Result<(), ConfigError> {
    if journal.journal_version != RESTORE_JOURNAL_VERSION {
        return Err(ConfigError::InvalidConfig {
            path: "$.journal_version".to_string(),
            reason: format!(
                "expected restore journal version {}, found {}",
                RESTORE_JOURNAL_VERSION, journal.journal_version
            ),
        });
    }
    for (path, digest) in [
        (
            "$.source_primary_digest",
            journal.source_primary_digest.as_str(),
        ),
        (
            "$.source_backup_digest",
            journal.source_backup_digest.as_str(),
        ),
    ] {
        let Some(hex) = digest.strip_prefix("sha256:") else {
            return Err(ConfigError::InvalidConfig {
                path: path.to_string(),
                reason: "restore source digest must use sha256".to_string(),
            });
        };
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ConfigError::InvalidConfig {
                path: path.to_string(),
                reason: "restore source digest must contain 64 hexadecimal digits".to_string(),
            });
        }
    }
    validate_config(&journal.target_primary)?;
    validate_config(&journal.target_backup)?;
    let _target_primary = serialize_config(&journal.target_primary)?;
    let _target_backup = serialize_config(&journal.target_backup)?;
    if journal.target_primary.revision <= journal.target_backup.revision {
        return Err(ConfigError::InvalidConfig {
            path: "$.target_primary.revision".to_string(),
            reason: "restored primary revision must be newer than its backup".to_string(),
        });
    }
    Ok(())
}

fn parse_credential_transaction_journal(
    path: &Path,
    bytes: &[u8],
) -> Result<CredentialTransactionJournal, ConfigError> {
    validate_json_shape(bytes, CREDENTIAL_TRANSACTION_JOURNAL_NODE_LIMIT).map_err(|source| {
        ConfigError::MalformedCredentialTransactionJournal {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let probe: CredentialTransactionVersionProbe =
        serde_json::from_slice(bytes).map_err(|source| {
            ConfigError::MalformedCredentialTransactionJournal {
                path: path.to_path_buf(),
                source,
            }
        })?;
    let version = probe.journal_version.ok_or_else(|| {
        ConfigError::MissingCredentialTransactionJournalVersion {
            path: path.to_path_buf(),
        }
    })?;
    if version > u64::from(CREDENTIAL_TRANSACTION_JOURNAL_VERSION) {
        return Err(ConfigError::FutureCredentialTransactionJournal {
            found: version,
            supported: CREDENTIAL_TRANSACTION_JOURNAL_VERSION,
        });
    }
    if version != u64::from(CREDENTIAL_TRANSACTION_JOURNAL_V1)
        && version != u64::from(CREDENTIAL_TRANSACTION_JOURNAL_VERSION)
    {
        return Err(ConfigError::UnsupportedCredentialTransactionJournal {
            found: version,
            supported: CREDENTIAL_TRANSACTION_JOURNAL_VERSION,
        });
    }
    let journal: CredentialTransactionJournal =
        serde_json::from_slice(bytes).map_err(|source| {
            ConfigError::MalformedCredentialTransactionJournal {
                path: path.to_path_buf(),
                source,
            }
        })?;
    validate_credential_transaction_journal(&journal)?;
    if let Some(repository_root) = path.parent() {
        validate_credential_journal_bindings(&journal, repository_root)?;
    }
    Ok(journal)
}

fn serialize_credential_transaction_journal(
    journal: &CredentialTransactionJournal,
) -> Result<Vec<u8>, ConfigError> {
    validate_credential_transaction_journal(journal)?;
    let bytes = serialize_bounded(
        journal,
        CREDENTIAL_TRANSACTION_JOURNAL_MAX_BYTES,
        CREDENTIAL_TRANSACTION_JOURNAL_FILENAME,
    )?;
    validate_json_shape(&bytes, CREDENTIAL_TRANSACTION_JOURNAL_NODE_LIMIT).map_err(|source| {
        ConfigError::MalformedCredentialTransactionJournal {
            path: PathBuf::from(CREDENTIAL_TRANSACTION_JOURNAL_FILENAME),
            source,
        }
    })?;
    Ok(bytes)
}

fn parse_auth_operation_intent(
    path: &Path,
    bytes: &[u8],
) -> Result<AuthOperationIntent, ConfigError> {
    validate_json_shape(bytes, AUTH_OPERATION_INTENT_NODE_LIMIT).map_err(|source| {
        ConfigError::MalformedAuthOperationIntent {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let probe: AuthOperationIntentVersionProbe =
        serde_json::from_slice(bytes).map_err(|source| {
            ConfigError::MalformedAuthOperationIntent {
                path: path.to_path_buf(),
                source,
            }
        })?;
    let version =
        probe
            .journal_version
            .ok_or_else(|| ConfigError::MissingAuthOperationIntentVersion {
                path: path.to_path_buf(),
            })?;
    if version > u64::from(AUTH_OPERATION_INTENT_VERSION) {
        return Err(ConfigError::FutureAuthOperationIntent {
            found: version,
            supported: AUTH_OPERATION_INTENT_VERSION,
        });
    }
    if version != u64::from(AUTH_OPERATION_INTENT_V1)
        && version != u64::from(AUTH_OPERATION_INTENT_VERSION)
    {
        return Err(ConfigError::UnsupportedAuthOperationIntent {
            found: version,
            supported: AUTH_OPERATION_INTENT_VERSION,
        });
    }
    let intent: AuthOperationIntent = serde_json::from_slice(bytes).map_err(|source| {
        ConfigError::MalformedAuthOperationIntent {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let repository_root = path.parent().ok_or_else(|| ConfigError::InvalidConfig {
        path: "$.repository_binding_digest".to_string(),
        reason: "authentication intent path has no repository root".to_string(),
    })?;
    validate_auth_operation_intent(&intent, repository_root)?;
    Ok(intent)
}

fn serialize_auth_operation_intent(
    intent: &AuthOperationIntent,
    repository_root: &Path,
) -> Result<Vec<u8>, ConfigError> {
    validate_auth_operation_intent(intent, repository_root)?;
    let bytes = serialize_bounded(
        intent,
        AUTH_OPERATION_INTENT_MAX_BYTES,
        AUTH_OPERATION_INTENT_FILENAME,
    )?;
    validate_json_shape(&bytes, AUTH_OPERATION_INTENT_NODE_LIMIT).map_err(|source| {
        ConfigError::MalformedAuthOperationIntent {
            path: PathBuf::from(AUTH_OPERATION_INTENT_FILENAME),
            source,
        }
    })?;
    Ok(bytes)
}

fn validate_auth_operation_intent(
    intent: &AuthOperationIntent,
    repository_root: &Path,
) -> Result<(), ConfigError> {
    if intent.journal_version != AUTH_OPERATION_INTENT_V1
        && intent.journal_version != AUTH_OPERATION_INTENT_VERSION
    {
        return Err(ConfigError::InvalidConfig {
            path: "$.journal_version".to_string(),
            reason: format!(
                "expected authentication operation intent version {} or {}, found {}",
                AUTH_OPERATION_INTENT_V1, AUTH_OPERATION_INTENT_VERSION, intent.journal_version
            ),
        });
    }
    let expected_repository_binding =
        credential_profile_anchor_repository_binding(repository_root)?;
    if intent.repository_binding_digest != expected_repository_binding {
        return Err(ConfigError::AuthOperationIntentRepositoryMismatch);
    }
    validate_string_len("$.operation_id", &intent.operation_id, 128)?;
    if intent.operation_id.is_empty() {
        return Err(ConfigError::InvalidConfig {
            path: "$.operation_id".to_string(),
            reason: "authentication operation id must not be empty".to_string(),
        });
    }
    validate_string_len("$.profile_name", &intent.profile_name, MAX_LEGACY_NAME_LEN)?;
    let normalized = normalize_address(&intent.endpoint.address, "$.endpoint.address")?;
    if normalized != intent.endpoint.address {
        return Err(ConfigError::InvalidConfig {
            path: "$.endpoint.address".to_string(),
            reason: "authentication intent endpoint must be canonical".to_string(),
        });
    }
    validate_required_metadata("$.endpoint.server_id", &intent.endpoint.server_id)?;
    validate_required_metadata(
        "$.endpoint.server_fingerprint",
        &intent.endpoint.server_fingerprint,
    )?;
    if let Some(storage_id) = &intent.endpoint.storage_id {
        validate_required_metadata("$.endpoint.storage_id", storage_id)?;
    }
    validate_sha256_digest(
        "$.source.raw_digest",
        &intent.source.raw_digest,
        "authentication intent source",
    )?;
    validate_count("$.source.credentials", intent.source.credentials.len(), 3)?;
    let source_ids: BTreeSet<_> = intent.source.credentials.values().collect();
    if source_ids.len() != intent.source.credentials.len() {
        return Err(ConfigError::InvalidConfig {
            path: "$.source.credentials".to_string(),
            reason: "authentication intent credential ids must be unique".to_string(),
        });
    }
    if intent.operation == AuthOperationKind::Refresh
        && !intent
            .source
            .credentials
            .contains_key(&CredentialKind::Refresh)
    {
        return Err(ConfigError::InvalidConfig {
            path: "$.source.credentials.refresh".to_string(),
            reason: "refresh intent requires a refresh credential".to_string(),
        });
    }
    let repository_binding = repository_binding(repository_root)?;
    if intent.journal_version == AUTH_OPERATION_INTENT_V1 {
        if intent.operation == AuthOperationKind::PasswordLogin
            || intent.client_id.is_some()
            || intent.reserved_login.is_some()
            || intent.candidate_login.is_some()
            || intent.source.profile_present.is_some()
            || intent.source.client_present.is_some()
            || intent.source.active_profile.is_some()
            || intent.source.client_active_connection.is_some()
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.operation".to_string(),
                reason: "authentication intent v1 only supports refresh/logout fields".to_string(),
            });
        }
        if intent.source.credentials.is_empty() {
            return Err(ConfigError::InvalidConfig {
                path: "$.source.credentials".to_string(),
                reason: "authentication intent v1 source must contain a credential profile"
                    .to_string(),
            });
        }
        if (intent.state == AuthOperationIntentState::Armed) != intent.candidate_rotation.is_none()
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.state".to_string(),
                reason: "armed refresh/logout intent must not have a candidate and candidate_prepared must have one"
                    .to_string(),
            });
        }
    } else {
        if intent.operation != AuthOperationKind::PasswordLogin
            || intent.candidate_rotation.is_some()
            || intent.client_id.is_none()
            || intent.reserved_login.is_none()
            || intent.source.profile_present.is_none()
            || intent.source.client_present.is_none()
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.operation".to_string(),
                reason: "authentication intent v2 requires the complete password-login shape"
                    .to_string(),
            });
        }
        let profile_present = intent.source.profile_present.unwrap_or(false);
        if profile_present == intent.source.credentials.is_empty() {
            return Err(ConfigError::InvalidConfig {
                path: "$.source.credentials".to_string(),
                reason: "password-login source credentials must match profile presence".to_string(),
            });
        }
        if !profile_present
            && (intent.source.account_subject.is_some()
                || intent.source.auth_method.is_some()
                || intent.source.access_expires_at.is_some())
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.source".to_string(),
                reason: "an absent password-login source profile cannot carry profile fields"
                    .to_string(),
            });
        }
        if intent.source.client_present == Some(false)
            && intent.source.client_active_connection.is_some()
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.source.client_active_connection".to_string(),
                reason: "an absent source client cannot have an active connection".to_string(),
            });
        }
        if let Some(active_profile) = &intent.source.active_profile {
            validate_string_len(
                "$.source.active_profile",
                active_profile,
                MAX_LEGACY_NAME_LEN,
            )?;
        }
        match (&intent.source.account_subject, intent.source.auth_method) {
            (None, None) => {}
            (Some(subject), Some(_)) => {
                validate_canonical_account_subject("$.source.account_subject", subject)?;
            }
            _ => {
                return Err(ConfigError::InvalidConfig {
                    path: "$.source".to_string(),
                    reason: "password-login source account binding must be a complete pair"
                        .to_string(),
                });
            }
        }
        if (intent.state == AuthOperationIntentState::Armed) != intent.candidate_login.is_none() {
            return Err(ConfigError::InvalidConfig {
                path: "$.state".to_string(),
                reason: "armed password-login intent must not have a candidate and candidate_prepared must have one"
                    .to_string(),
            });
        }
    }
    if let Some(candidate) = &intent.candidate_rotation {
        if intent.operation != AuthOperationKind::Refresh {
            return Err(ConfigError::InvalidConfig {
                path: "$.candidate_rotation".to_string(),
                reason: "logout intent cannot contain a rotation candidate".to_string(),
            });
        }
        if intent.source.revision == u64::MAX || candidate.revision != intent.source.revision + 1 {
            return Err(ConfigError::InvalidConfig {
                path: "$.candidate_rotation.revision".to_string(),
                reason: "rotation candidate must advance the source revision exactly once"
                    .to_string(),
            });
        }
        validate_sha256_digest(
            "$.candidate_rotation.raw_digest",
            &candidate.raw_digest,
            "authentication intent rotation candidate",
        )?;
        validate_required_metadata(
            "$.candidate_rotation.access_expires_at",
            &candidate.access_expires_at,
        )?;
        for (path, kind, credential_id) in [
            (
                "$.candidate_rotation.access_credential_id",
                CredentialKind::Access,
                &candidate.access_credential_id,
            ),
            (
                "$.candidate_rotation.refresh_credential_id",
                CredentialKind::Refresh,
                &candidate.refresh_credential_id,
            ),
        ] {
            if !credential_id.is_bound_lifecycle(
                &repository_binding,
                &intent.connection_id,
                &intent.profile_name,
                kind,
            ) {
                return Err(ConfigError::InvalidConfig {
                    path: path.to_string(),
                    reason: "rotation credential id is not bound to this repository slot"
                        .to_string(),
                });
            }
            if intent
                .source
                .credentials
                .values()
                .any(|source| source == credential_id)
            {
                return Err(ConfigError::InvalidConfig {
                    path: path.to_string(),
                    reason: "rotation credential id must be fresh".to_string(),
                });
            }
        }
        if candidate.access_credential_id == candidate.refresh_credential_id {
            return Err(ConfigError::InvalidConfig {
                path: "$.candidate_rotation".to_string(),
                reason: "access and refresh candidates must use distinct credential ids"
                    .to_string(),
            });
        }
    }
    if let Some(reservation) = &intent.reserved_login {
        for (path, kind, credential_id) in [
            (
                "$.reserved_login.access_credential_id",
                CredentialKind::Access,
                &reservation.access_credential_id,
            ),
            (
                "$.reserved_login.refresh_credential_id",
                CredentialKind::Refresh,
                &reservation.refresh_credential_id,
            ),
        ] {
            if !credential_id.is_bound_lifecycle(
                &repository_binding,
                &intent.connection_id,
                &intent.profile_name,
                kind,
            ) {
                return Err(ConfigError::InvalidConfig {
                    path: path.to_string(),
                    reason: "reserved login credential id is not bound to this repository slot"
                        .to_string(),
                });
            }
            if intent
                .source
                .credentials
                .values()
                .any(|source| source == credential_id)
            {
                return Err(ConfigError::InvalidConfig {
                    path: path.to_string(),
                    reason: "reserved login credential id must be fresh".to_string(),
                });
            }
        }
        if reservation.access_credential_id == reservation.refresh_credential_id {
            return Err(ConfigError::InvalidConfig {
                path: "$.reserved_login".to_string(),
                reason: "reserved access and refresh ids must be distinct".to_string(),
            });
        }
    }
    if let Some(candidate) = &intent.candidate_login {
        let reservation =
            intent
                .reserved_login
                .as_ref()
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: "$.candidate_login".to_string(),
                    reason: "password-login candidate requires a reservation".to_string(),
                })?;
        if intent.source.revision == u64::MAX || candidate.revision != intent.source.revision + 1 {
            return Err(ConfigError::InvalidConfig {
                path: "$.candidate_login.revision".to_string(),
                reason: "password-login candidate must advance the source revision exactly once"
                    .to_string(),
            });
        }
        validate_sha256_digest(
            "$.candidate_login.raw_digest",
            &candidate.raw_digest,
            "authentication intent password-login candidate",
        )?;
        validate_required_metadata(
            "$.candidate_login.account_subject",
            &candidate.account_subject,
        )?;
        validate_canonical_account_subject(
            "$.candidate_login.account_subject",
            &candidate.account_subject,
        )?;
        validate_required_metadata(
            "$.candidate_login.access_expires_at",
            &candidate.access_expires_at,
        )?;
        if candidate.auth_method != AuthMethod::Password
            || candidate.access_credential_id != reservation.access_credential_id
            || candidate.refresh_credential_id != reservation.refresh_credential_id
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.candidate_login".to_string(),
                reason: "password-login candidate must use Password and the exact reservation"
                    .to_string(),
            });
        }
    }
    Ok(())
}

fn validate_credential_transaction_journal(
    journal: &CredentialTransactionJournal,
) -> Result<(), ConfigError> {
    if journal.journal_version != CREDENTIAL_TRANSACTION_JOURNAL_V1
        && journal.journal_version != CREDENTIAL_TRANSACTION_JOURNAL_VERSION
    {
        return Err(ConfigError::InvalidConfig {
            path: "$.journal_version".to_string(),
            reason: format!(
                "expected credential transaction journal version {} or {}, found {}",
                CREDENTIAL_TRANSACTION_JOURNAL_V1,
                CREDENTIAL_TRANSACTION_JOURNAL_VERSION,
                journal.journal_version
            ),
        });
    }
    validate_credential_generation("$.source_primary", &journal.source_primary)?;
    if let Some(source_backup) = &journal.source_backup {
        validate_credential_generation("$.source_backup", source_backup)?;
        if source_backup.migration_digest != journal.source_primary.migration_digest {
            return Err(ConfigError::InvalidConfig {
                path: "$.source_backup.migration_digest".to_string(),
                reason: "backup migration digest must match the source primary".to_string(),
            });
        }
    }
    validate_credential_generation("$.candidate", &journal.candidate)?;
    if journal.candidate.revision != journal.source_primary.revision.saturating_add(1)
        || journal.source_primary.revision == u64::MAX
    {
        return Err(ConfigError::InvalidConfig {
            path: "$.candidate.revision".to_string(),
            reason: "credential candidate must advance source revision exactly once".to_string(),
        });
    }
    if journal.candidate.migration_digest != journal.source_primary.migration_digest {
        return Err(ConfigError::InvalidConfig {
            path: "$.candidate.migration_digest".to_string(),
            reason: "candidate migration digest must match the source primary".to_string(),
        });
    }
    if !journal.aborted && journal.aborted_after_backup_write {
        return Err(ConfigError::InvalidConfig {
            path: "$.aborted_after_backup_write".to_string(),
            reason: "backup-write abort state requires aborted=true".to_string(),
        });
    }
    validate_count("$.new_ids", journal.new_ids.len(), 3)?;
    validate_count(
        "$.retired_slots",
        journal.retired_slots.len(),
        MAX_CREDENTIAL_SLOTS,
    )?;
    validate_count(
        "$.carried_retired_slots",
        journal.carried_retired_slots.len(),
        MAX_CREDENTIAL_SLOTS,
    )?;
    validate_count(
        "$.settled_retired_ids",
        journal.settled_retired_ids.len(),
        MAX_CREDENTIAL_SLOTS,
    )?;
    let source_ids = credential_ids_from_slots(&journal.source_primary.slots);
    let candidate_ids = credential_ids_from_slots(&journal.candidate.slots);
    if journal.new_ids.is_empty() {
        if journal.journal_version == CREDENTIAL_TRANSACTION_JOURNAL_V1 {
            return Err(ConfigError::InvalidConfig {
                path: "$.new_ids".to_string(),
                reason: "credential transaction journal v1 requires at least one new id"
                    .to_string(),
            });
        }
        if source_ids.is_subset(&candidate_ids) {
            return Err(ConfigError::InvalidConfig {
                path: "$.new_ids".to_string(),
                reason: "a zero-write journal must describe a real credential retirement"
                    .to_string(),
            });
        }
    }
    let expected_new_ids: BTreeSet<_> = candidate_ids.difference(&source_ids).cloned().collect();
    if journal.new_ids != expected_new_ids {
        return Err(ConfigError::InvalidConfig {
            path: "$.new_ids".to_string(),
            reason: "new_ids do not exactly match candidate refs minus source refs".to_string(),
        });
    }
    let source_slots = &journal.source_primary.slots;
    let candidate_slots = &journal.candidate.slots;
    let mut expected_base_retired_slots = BTreeSet::new();
    if !journal.aborted {
        expected_base_retired_slots.extend(source_slots.difference(candidate_slots).cloned());
    }
    if let Some(source_backup) = &journal.source_backup {
        expected_base_retired_slots.extend(source_backup.slots.difference(source_slots).cloned());
    }
    let mut expected_retired_slots = expected_base_retired_slots.clone();
    expected_retired_slots.extend(journal.carried_retired_slots.iter().cloned());
    if expected_retired_slots != journal.retired_slots {
        return Err(ConfigError::InvalidConfig {
            path: "$.retired_slots".to_string(),
            reason: "retired_slots do not exactly match source, backup, and predecessor proofs"
                .to_string(),
        });
    }
    let expected_carried: BTreeSet<_> = journal
        .retired_slots
        .difference(&expected_base_retired_slots)
        .cloned()
        .collect();
    if expected_carried != journal.carried_retired_slots {
        return Err(ConfigError::InvalidConfig {
            path: "$.carried_retired_slots".to_string(),
            reason: "carried cleanup slots must be exactly those not proven by source generations"
                .to_string(),
        });
    }
    let mut retired_ids = BTreeSet::new();
    for slot in &journal.retired_slots {
        if !retired_ids.insert(slot.credential_id.clone()) {
            return Err(ConfigError::InvalidConfig {
                path: "$.retired_slots".to_string(),
                reason: format!(
                    "credential id {} is retired from more than one slot",
                    slot.credential_id
                ),
            });
        }
        if candidate_ids.contains(&slot.credential_id) {
            return Err(ConfigError::InvalidConfig {
                path: "$.retired_slots".to_string(),
                reason: format!(
                    "retired credential id {} remains referenced by the candidate",
                    slot.credential_id
                ),
            });
        }
    }
    for credential_id in &journal.new_ids {
        if credential_id.lifecycle_nonce_and_tag().is_none() {
            return Err(ConfigError::InvalidConfig {
                path: "$.new_ids".to_string(),
                reason: format!("new credential id is not lifecycle-bound: {credential_id}"),
            });
        }
        if !candidate_ids.contains(credential_id) {
            return Err(ConfigError::InvalidConfig {
                path: "$.new_ids".to_string(),
                reason: format!("candidate does not reference new credential id {credential_id}"),
            });
        }
        if retired_ids.contains(credential_id) {
            return Err(ConfigError::InvalidConfig {
                path: "$.retired_slots".to_string(),
                reason: format!("new credential id is also marked retired: {credential_id}"),
            });
        }
    }
    if !journal.settled_retired_ids.is_subset(&retired_ids) {
        return Err(ConfigError::InvalidConfig {
            path: "$.settled_retired_ids".to_string(),
            reason: "settled ids must be a subset of proven retired slots".to_string(),
        });
    }
    Ok(())
}

fn validate_credential_generation(
    path: &str,
    generation: &CredentialGeneration,
) -> Result<(), ConfigError> {
    validate_sha256_digest(
        &format!("{path}.raw_digest"),
        &generation.raw_digest,
        "credential generation",
    )?;
    if let Some(migration_digest) = &generation.migration_digest {
        validate_sha256_digest(
            &format!("{path}.migration_digest"),
            migration_digest,
            "credential generation migration",
        )?;
    }
    validate_count(
        &format!("{path}.slots"),
        generation.slots.len(),
        MAX_CREDENTIAL_SLOTS,
    )?;
    let ids = credential_ids_from_slots(&generation.slots);
    if ids.len() != generation.slots.len() {
        return Err(ConfigError::InvalidConfig {
            path: format!("{path}.slots"),
            reason: "credential ids must be unique within a generation".to_string(),
        });
    }
    Ok(())
}

fn validate_credential_journal_bindings(
    journal: &CredentialTransactionJournal,
    repository_root: &Path,
) -> Result<(), ConfigError> {
    let binding = repository_binding(repository_root)?;
    for (generation_path, generation) in [
        ("$.source_primary", Some(&journal.source_primary)),
        ("$.source_backup", journal.source_backup.as_ref()),
        ("$.candidate", Some(&journal.candidate)),
    ] {
        let Some(generation) = generation else {
            continue;
        };
        for slot in &generation.slots {
            validate_credential_slot_binding(
                generation_path,
                slot,
                generation.migration_digest.as_deref(),
                &binding,
                repository_root,
            )?;
        }
    }
    for slot in &journal.retired_slots {
        validate_credential_slot_binding(
            "$.retired_slots",
            slot,
            journal.source_primary.migration_digest.as_deref(),
            &binding,
            repository_root,
        )?;
    }
    Ok(())
}

fn validate_credential_slot_binding(
    path: &str,
    slot: &CredentialSlotRef,
    migration_digest: Option<&str>,
    repository_binding: &[u8],
    repository_root: &Path,
) -> Result<(), ConfigError> {
    validate_string_len(
        &format!("{path}.*.profile_name"),
        &slot.profile_name,
        MAX_LEGACY_NAME_LEN,
    )?;
    let valid = if slot.credential_id.lifecycle_nonce_and_tag().is_some() {
        slot.credential_id.is_bound_lifecycle(
            repository_binding,
            &slot.connection_id,
            &slot.profile_name,
            slot.kind,
        )
    } else {
        migration_digest.is_some_and(|digest| {
            slot.credential_id
                == CredentialId::deterministic(
                    repository_binding,
                    digest,
                    &slot.connection_id,
                    &slot.profile_name,
                    slot.kind,
                )
        })
    };
    if !valid {
        return Err(ConfigError::CredentialTransactionJournalConflict {
            path: repository_root.join(CREDENTIAL_TRANSACTION_JOURNAL_FILENAME),
            reason: format!(
                "retired credential id {} is not bound to its declared repository slot",
                slot.credential_id
            ),
        });
    }
    Ok(())
}

fn validate_sha256_digest(path: &str, digest: &str, label: &str) -> Result<(), ConfigError> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: format!("{label} digest must use sha256"),
        });
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: format!("{label} digest must contain 64 hexadecimal digits"),
        });
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
    let limit = json_size_limit(path);
    if bytes.len() as u64 > limit {
        return Err(ConfigError::ConfigTooLarge {
            path: path.to_path_buf(),
            max_bytes: limit,
        });
    }
    validate_regular_file_if_exists(path)?;
    let parent = path.parent().ok_or_else(|| ConfigError::Io {
        operation: "resolve config parent",
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"),
    })?;
    fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
        operation: "create config directory",
        path: parent.to_path_buf(),
        source,
    })?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|source| ConfigError::Io {
        operation: "create config temporary file",
        path: parent.to_path_buf(),
        source,
    })?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| ConfigError::Io {
            operation: "sync config temporary file",
            path: temporary.path().to_path_buf(),
            source,
        })?;
    temporary.persist(path).map_err(|error| ConfigError::Io {
        operation: "persist config",
        path: path.to_path_buf(),
        source: error.error,
    })?;
    sync_parent(parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), ConfigError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ConfigError::Io {
            operation: "sync config directory",
            path: parent.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), ConfigError> {
    Ok(())
}

fn validate_config(config: &ConfigV2) -> Result<(), ConfigError> {
    if config.schema_version != CONFIG_SCHEMA_VERSION {
        return Err(ConfigError::InvalidConfig {
            path: "$.schema_version".to_string(),
            reason: format!(
                "expected schema {}, found {}",
                CONFIG_SCHEMA_VERSION, config.schema_version
            ),
        });
    }
    if let Some(identity) = &config.identity {
        validate_kdf_params(&identity.kdf_params, "$.identity.kdf_params")?;
        validate_string_len(
            "$.identity.kdf_salt",
            &identity.kdf_salt,
            MAX_METADATA_VALUE_LEN,
        )?;
        for (field, value, maximum) in [
            (
                "salt_fingerprint",
                identity.salt_fingerprint.as_deref(),
                MAX_METADATA_VALUE_LEN,
            ),
            (
                "first_seen_at",
                identity.first_seen_at.as_deref(),
                MAX_LEGACY_NAME_LEN,
            ),
            ("email", identity.email.as_deref(), 320),
        ] {
            if let Some(value) = value {
                validate_string_len(&format!("$.identity.{field}"), value, maximum)?;
            }
        }
    }
    validate_count("$.connections", config.connections.len(), MAX_CONNECTIONS)?;
    validate_count("$.clients", config.clients.len(), MAX_CLIENTS)?;
    validate_count(
        "$.legacy_known_hosts",
        config.legacy_known_hosts.len(),
        MAX_KNOWN_HOSTS,
    )?;
    if let Some(migration) = &config.migration {
        validate_count(
            "$.migration.claimed_clients",
            migration.claimed_clients.len(),
            MAX_CLIENTS,
        )?;
        validate_count(
            "$.migration.deferred_legacy_fields",
            migration.deferred_legacy_fields.len(),
            MAX_DEFERRED_FIELDS,
        )?;
        validate_string_len(
            "$.migration.source_format",
            &migration.source_format,
            MAX_LEGACY_NAME_LEN,
        )?;
        validate_string_len(
            "$.migration.source_digest",
            &migration.source_digest,
            MAX_LEGACY_NAME_LEN,
        )?;
        for path in &migration.deferred_legacy_fields {
            validate_string_len(
                "$.migration.deferred_legacy_fields.*",
                path,
                MAX_DEFERRED_PATH_LEN,
            )?;
        }
    }
    for (address, fingerprint) in &config.legacy_known_hosts {
        validate_string_len("$.legacy_known_hosts.<address>", address, MAX_ADDRESS_LEN)?;
        validate_string_len(
            "$.legacy_known_hosts.<fingerprint>",
            fingerprint,
            MAX_METADATA_VALUE_LEN,
        )?;
    }
    let mut known_hosts_by_address: BTreeMap<String, (&str, &str)> = BTreeMap::new();
    for (address, fingerprint) in &config.legacy_known_hosts {
        let normalized = normalize_address(address, &format!("$.legacy_known_hosts.{address}"))?;
        if let Some((previous_address, previous_fingerprint)) =
            known_hosts_by_address.insert(normalized.clone(), (address, fingerprint))
        {
            if previous_fingerprint != fingerprint {
                return Err(ConfigError::InvalidConfig {
                    path: format!("$.legacy_known_hosts.{address}"),
                    reason: format!(
                        "normalized address {normalized} conflicts with {previous_address}"
                    ),
                });
            }
        }
    }

    let mut trust_by_address: BTreeMap<String, (Option<String>, Option<String>, ConnectionId)> =
        BTreeMap::new();
    for (connection_id, connection) in &config.connections {
        let metadata = &connection.metadata;
        let normalized = normalize_address(
            &metadata.address,
            &format!("$.connections.{connection_id}.metadata.address"),
        )?;
        if let Some((server_id, fingerprint, previous_id)) = trust_by_address.get(&normalized) {
            if server_id.as_deref() != metadata.server_id.as_deref() {
                return Err(ConfigError::InvalidConfig {
                    path: format!("$.connections.{connection_id}.metadata.server_id"),
                    reason: format!(
                        "must match connection {previous_id} for normalized address {normalized}"
                    ),
                });
            }
            if fingerprint.as_deref() != metadata.server_fingerprint.as_deref() {
                return Err(ConfigError::InvalidConfig {
                    path: format!("$.connections.{connection_id}.metadata.server_fingerprint"),
                    reason: format!(
                        "must match connection {previous_id} for normalized address {normalized}"
                    ),
                });
            }
        } else {
            trust_by_address.insert(
                normalized.clone(),
                (
                    metadata.server_id.clone(),
                    metadata.server_fingerprint.clone(),
                    connection_id.clone(),
                ),
            );
        }
        if let Some((known_address, known_fingerprint)) = known_hosts_by_address.get(&normalized) {
            if metadata.server_fingerprint.as_deref() != Some(*known_fingerprint) {
                return Err(ConfigError::InvalidConfig {
                    path: format!("$.connections.{connection_id}.metadata.server_fingerprint"),
                    reason: format!(
                        "must match retained known-host fingerprint for {known_address}"
                    ),
                });
            }
        }
    }
    for (client_id, client) in &config.clients {
        let path = format!("$.clients.{client_id}");
        let namespace_matches = matches!(
            (client_id.as_str(), &client.namespace),
            ("cli", ClientNamespace::CliV1(_)) | ("desktop", ClientNamespace::DesktopV1(_))
        ) || (client_id.as_str() != "cli"
            && client_id.as_str() != "desktop"
            && matches!(&client.namespace, ClientNamespace::Empty));
        if !namespace_matches {
            return Err(ConfigError::InvalidConfig {
                path: format!("{path}.namespace"),
                reason: format!("namespace variant does not match client {client_id}"),
            });
        }
        if let ClientNamespace::CliV1(namespace) = &client.namespace {
            for connection_id in namespace.default_vault_by_connection.keys() {
                if !config.connections.contains_key(connection_id) {
                    return Err(ConfigError::InvalidConfig {
                        path: format!(
                            "{path}.namespace.settings.default_vault_by_connection.{connection_id}"
                        ),
                        reason: "default vault references a missing connection".to_string(),
                    });
                }
            }
            for (connection_id, vault) in &namespace.default_vault_by_connection {
                validate_string_len(
                    &format!(
                        "{path}.namespace.settings.default_vault_by_connection.{connection_id}"
                    ),
                    vault,
                    MAX_LEGACY_NAME_LEN,
                )?;
            }
        }
        if let ClientNamespace::DesktopV1(namespace) = &client.namespace {
            if let Some(backup) = &namespace.backup {
                if let Some(backup_dir) = &backup.backup_dir {
                    validate_string_len(
                        &format!("{path}.namespace.settings.backup.backup_dir"),
                        backup_dir,
                        MAX_ADDRESS_LEN,
                    )?;
                }
            }
        }
        if let Some(connection_id) = &client.active_connection {
            if !config.connections.contains_key(connection_id) {
                return Err(ConfigError::InvalidConfig {
                    path: format!("{path}.active_connection"),
                    reason: format!("connection does not exist: {connection_id}"),
                });
            }
        }
    }
    let mut credential_locations: BTreeMap<CredentialId, String> = BTreeMap::new();
    let mut storage_locations: BTreeMap<String, ConnectionId> = BTreeMap::new();
    let mut profile_count = 0usize;
    let mut credential_slot_count = 0usize;
    for (connection_id, connection) in &config.connections {
        let path = format!("$.connections.{connection_id}");
        validate_string_len(
            &format!("{path}.metadata.name"),
            &connection.metadata.name,
            MAX_LEGACY_NAME_LEN,
        )?;
        validate_string_len(
            &format!("{path}.metadata.address"),
            &connection.metadata.address,
            MAX_ADDRESS_LEN,
        )?;
        for (field, value) in [
            ("server_id", connection.metadata.server_id.as_deref()),
            (
                "server_fingerprint",
                connection.metadata.server_fingerprint.as_deref(),
            ),
            (
                "expected_master_key_fp",
                connection.metadata.expected_master_key_fp.as_deref(),
            ),
            ("storage_id", connection.metadata.storage_id.as_deref()),
        ] {
            if let Some(value) = value {
                validate_string_len(
                    &format!("{path}.metadata.{field}"),
                    value,
                    MAX_METADATA_VALUE_LEN,
                )?;
            }
        }
        if let Some(storage_id) = &connection.metadata.storage_id {
            if let Some(previous) =
                storage_locations.insert(storage_id.clone(), connection_id.clone())
            {
                return Err(ConfigError::InvalidConfig {
                    path: format!("{path}.metadata.storage_id"),
                    reason: format!(
                        "storage id {storage_id} is already bound to connection {previous}"
                    ),
                });
            }
        }
        if let Some(active_credential) = &connection.active_credential {
            validate_string_len(
                &format!("{path}.active_credential"),
                active_credential,
                MAX_LEGACY_NAME_LEN,
            )?;
            if !connection
                .credential_profiles
                .contains_key(active_credential)
            {
                return Err(ConfigError::InvalidConfig {
                    path: format!("{path}.active_credential"),
                    reason: format!("credential profile does not exist: {active_credential}"),
                });
            }
        }
        for (profile_name, profile) in &connection.credential_profiles {
            profile_count =
                profile_count
                    .checked_add(1)
                    .ok_or_else(|| ConfigError::InvalidConfig {
                        path: "$.connections".to_string(),
                        reason: "credential profile count overflow".to_string(),
                    })?;
            validate_count(
                "$.connections.*.credential_profiles",
                profile_count,
                MAX_PROFILES_TOTAL,
            )?;
            let profile_path = format!("{path}.credential_profiles.{profile_name}");
            if profile_name.is_empty() {
                return Err(ConfigError::InvalidConfig {
                    path: profile_path,
                    reason: "credential profile name must not be empty".to_string(),
                });
            }
            if profile.credentials.is_empty() {
                return Err(ConfigError::InvalidConfig {
                    path: profile_path,
                    reason: "credential profile must reference at least one credential".to_string(),
                });
            }
            validate_string_len(&profile_path, profile_name, MAX_LEGACY_NAME_LEN)?;
            match (&profile.account_subject, profile.auth_method) {
                (None, None) => {}
                (Some(subject), Some(_)) => {
                    validate_canonical_account_subject(
                        &format!("{profile_path}.account_subject"),
                        subject,
                    )?;
                }
                _ => {
                    return Err(ConfigError::InvalidConfig {
                        path: profile_path,
                        reason:
                            "account_subject and auth_method must be both absent or both present"
                                .to_string(),
                    });
                }
            }
            if let Some(expires_at) = &profile.access_expires_at {
                validate_string_len(
                    &format!("{profile_path}.access_expires_at"),
                    expires_at,
                    MAX_LEGACY_NAME_LEN,
                )?;
            }
            for (kind, credential_id) in &profile.credentials {
                credential_slot_count = credential_slot_count.checked_add(1).ok_or_else(|| {
                    ConfigError::InvalidConfig {
                        path: "$.connections".to_string(),
                        reason: "credential slot count overflow".to_string(),
                    }
                })?;
                validate_count(
                    "$.connections.*.credential_profiles.*.credentials",
                    credential_slot_count,
                    MAX_CREDENTIAL_SLOTS,
                )?;
                let location = format!("{profile_path}.credentials.{kind:?}");
                if credential_id.lifecycle_nonce_and_tag().is_none() {
                    config
                        .migration
                        .as_ref()
                        .ok_or_else(|| ConfigError::InvalidConfig {
                            path: location.clone(),
                            reason: "legacy credential references require a migration stamp"
                                .to_string(),
                        })?;
                }
                if let Some(previous) =
                    credential_locations.insert(credential_id.clone(), location.clone())
                {
                    return Err(ConfigError::InvalidConfig {
                        path: location,
                        reason: format!(
                            "credential id {credential_id} is already referenced at {previous}"
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

fn validate_repository_credential_ids(
    config: &ConfigV2,
    repository_root: &Path,
) -> Result<(), ConfigError> {
    let repository_binding = repository_binding(repository_root)?;
    for (connection_id, connection) in &config.connections {
        for (profile_name, profile) in &connection.credential_profiles {
            for (kind, credential_id) in &profile.credentials {
                let valid = if credential_id.lifecycle_nonce_and_tag().is_some() {
                    credential_id.is_bound_lifecycle(
                        &repository_binding,
                        connection_id,
                        profile_name,
                        *kind,
                    )
                } else {
                    config.migration.as_ref().is_some_and(|migration| {
                        *credential_id
                            == CredentialId::deterministic(
                                &repository_binding,
                                &migration.source_digest,
                                connection_id,
                                profile_name,
                                *kind,
                            )
                    })
                };
                if !valid {
                    return Err(ConfigError::InvalidConfig {
                        path: format!(
                            "$.connections.{connection_id}.credential_profiles.{profile_name}.credentials.{kind:?}"
                        ),
                        reason: "credential id is not bound to this repository slot".to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn validate_kdf_params(params: &ConfigKdfParams, path: &str) -> Result<(), ConfigError> {
    KdfParams {
        algorithm: params.algorithm.clone(),
        iterations: params.iterations,
        memory_kb: params.memory_kb,
        parallelism: params.parallelism,
    }
    .validate_policy()
    .map_err(|reason| ConfigError::InvalidConfig {
        path: path.to_string(),
        reason: reason.to_string(),
    })
}

fn validate_count(path: &str, actual: usize, maximum: usize) -> Result<(), ConfigError> {
    if actual > maximum {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: format!("contains {actual} entries; maximum is {maximum}"),
        });
    }
    Ok(())
}

fn validate_string_len(path: &str, value: &str, maximum: usize) -> Result<(), ConfigError> {
    if value.is_empty() || value.len() > maximum {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: format!("string length must be between 1 and {maximum} bytes"),
        });
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_required_metadata(path: &str, value: &str) -> Result<(), ConfigError> {
    validate_string_len(path, value, MAX_METADATA_VALUE_LEN)
}

fn validate_canonical_account_subject(path: &str, value: &str) -> Result<(), ConfigError> {
    validate_required_metadata(path, value)?;
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| ConfigError::InvalidConfig {
        path: path.to_string(),
        reason: "authenticated account subject must be a UUID".to_string(),
    })?;
    if parsed.to_string() != value {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "authenticated account subject must use canonical UUID form".to_string(),
        });
    }
    Ok(())
}

fn validate_credential_bundle_input(
    path: &str,
    bundle: &CredentialBundle,
) -> Result<(), ConfigError> {
    if bundle.slots().iter().all(|(_, secret)| secret.is_none()) {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "credential bundle must contain at least one secret".to_string(),
        });
    }
    if bundle.access.is_none() && bundle.access_expires_at.is_some() {
        return Err(ConfigError::InvalidConfig {
            path: format!("{path}.access_expires_at"),
            reason: "access expiry requires an access credential".to_string(),
        });
    }
    if let Some(expires_at) = &bundle.access_expires_at {
        validate_string_len(
            &format!("{path}.access_expires_at"),
            expires_at,
            MAX_LEGACY_NAME_LEN,
        )?;
    }
    Ok(())
}

fn client_config_for(client_id: &ClientId) -> ClientConfig {
    let namespace = match client_id.as_str() {
        "cli" => ClientNamespace::CliV1(CliNamespace::default()),
        "desktop" => ClientNamespace::DesktopV1(DesktopNamespace::default()),
        _ => ClientNamespace::Empty,
    };
    ClientConfig {
        active_connection: None,
        namespace,
    }
}

fn client_entry<'a>(config: &'a mut ConfigV2, client_id: &ClientId) -> &'a mut ClientConfig {
    config
        .clients
        .entry(client_id.clone())
        .or_insert_with(|| client_config_for(client_id))
}

struct LegacyInput {
    config_bytes: Option<Zeroizing<Vec<u8>>>,
    known_hosts_bytes: Option<Zeroizing<Vec<u8>>>,
    digest: String,
}

impl LegacyInput {
    fn read(paths: &ClientPaths) -> Result<Self, ConfigError> {
        let config_bytes = read_optional_secret_file(&paths.legacy_config())?;
        let known_hosts_bytes = read_optional_secret_file(&paths.legacy_known_hosts())?;
        let digest = legacy_digest(
            config_bytes.as_ref().map(|bytes| bytes.as_slice()),
            known_hosts_bytes.as_ref().map(|bytes| bytes.as_slice()),
        );
        Ok(Self {
            config_bytes,
            known_hosts_bytes,
            digest,
        })
    }

    fn has_sources(&self) -> bool {
        self.config_bytes.is_some() || self.known_hosts_bytes.is_some()
    }

    fn active_connection_id(
        &self,
        paths: &ClientPaths,
    ) -> Result<Option<ConnectionId>, ConfigError> {
        let Some(bytes) = self.config_bytes.as_deref() else {
            return Ok(None);
        };
        validate_json_shape(bytes, JSON_NODE_LIMIT).map_err(|source| ConfigError::Malformed {
            path: paths.legacy_config(),
            source,
        })?;
        let claim: LegacyClientClaim =
            serde_json::from_slice(bytes).map_err(|source| ConfigError::Malformed {
                path: paths.legacy_config(),
                source,
            })?;
        let Some(current_context) = claim.current_context else {
            return Ok(None);
        };
        let connection =
            claim
                .contexts
                .get(&current_context)
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: "$.current_context".to_string(),
                    reason: format!("context does not exist: {current_context}"),
                })?;
        Ok(Some(ConnectionId::deterministic(
            &current_context,
            &connection.addr,
        )))
    }
}

fn read_optional_secret_file(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, ConfigError> {
    match read_file(path, "read legacy config") {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(ConfigError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn legacy_digest(config: Option<&[u8]>, known_hosts: Option<&[u8]>) -> String {
    let mut hasher = Sha256::new();
    hash_optional_source(&mut hasher, b"config", config);
    hash_optional_source(&mut hasher, b"known_hosts", known_hosts);
    format!("sha256:{}", HEXLOWER.encode(&hasher.finalize()))
}

fn hash_optional_source(hasher: &mut Sha256, label: &[u8], source: Option<&[u8]>) {
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    match source {
        Some(bytes) => {
            hasher.update([1]);
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        None => hasher.update([0]),
    }
}

fn validate_legacy_budgets(
    legacy: &LegacyConfig,
    known_hosts: &BTreeMap<String, String>,
    deferred: &BTreeSet<String>,
) -> Result<(), ConfigError> {
    validate_count("$.contexts", legacy.contexts.len(), MAX_CONNECTIONS)?;
    validate_count("$.known_hosts", known_hosts.len(), MAX_KNOWN_HOSTS)?;
    validate_count("$.deferred", deferred.len(), MAX_DEFERRED_FIELDS)?;
    for path in deferred {
        validate_string_len("$.deferred.*", path, MAX_DEFERRED_PATH_LEN)?;
    }
    if let Some(current_context) = &legacy.current_context {
        validate_string_len("$.current_context", current_context, MAX_LEGACY_NAME_LEN)?;
    }
    if let Some(identity) = &legacy.identity {
        validate_string_len(
            "$.identity.kdf_salt",
            &identity.kdf_salt,
            MAX_METADATA_VALUE_LEN,
        )?;
        validate_kdf_params(&identity.kdf_params, "$.identity.kdf_params")?;
        for (field, value, maximum) in [
            (
                "salt_fingerprint",
                identity.salt_fingerprint.as_deref(),
                MAX_METADATA_VALUE_LEN,
            ),
            (
                "first_seen_at",
                identity.first_seen_at.as_deref(),
                MAX_LEGACY_NAME_LEN,
            ),
            ("email", identity.email.as_deref(), 320),
        ] {
            if let Some(value) = value {
                validate_string_len(&format!("$.identity.{field}"), value, maximum)?;
            }
        }
    }
    if let Some(storage) = &legacy.storage {
        if let Some(backup_dir) = &storage.backup_dir {
            validate_string_len("$.storage.backup_dir", backup_dir, MAX_ADDRESS_LEN)?;
        }
    }

    let mut profile_count = 0usize;
    for (connection_name, connection) in &legacy.contexts {
        let base = legacy_path("$.contexts", connection_name);
        validate_string_len(&base, connection_name, MAX_LEGACY_NAME_LEN)?;
        validate_string_len(&format!("{base}.addr"), &connection.addr, MAX_ADDRESS_LEN)?;
        for (field, value) in [
            ("server_id", connection.server_id.as_deref()),
            (
                "server_fingerprint",
                connection.server_fingerprint.as_deref(),
            ),
            (
                "expected_master_key_fp",
                connection.expected_master_key_fp.as_deref(),
            ),
            ("storage_id", connection.storage_id.as_deref()),
            ("vault", connection.vault.as_deref()),
        ] {
            if let Some(value) = value {
                validate_string_len(&format!("{base}.{field}"), value, MAX_METADATA_VALUE_LEN)?;
            }
        }
        if let Some(current_token) = &connection.current_token {
            validate_string_len(
                &format!("{base}.current_token"),
                current_token,
                MAX_LEGACY_NAME_LEN,
            )?;
        }
        for (profile_name, profile) in &connection.tokens {
            profile_count =
                profile_count
                    .checked_add(1)
                    .ok_or_else(|| ConfigError::InvalidConfig {
                        path: "$.contexts.*.tokens".to_string(),
                        reason: "credential profile count overflow".to_string(),
                    })?;
            validate_count("$.contexts.*.tokens", profile_count, MAX_PROFILES_TOTAL)?;
            validate_string_len(
                &legacy_path(&format!("{base}.tokens"), profile_name),
                profile_name,
                MAX_LEGACY_NAME_LEN,
            )?;
            if let Some(expires_at) = &profile.access_expires_at {
                validate_string_len(
                    &format!("{base}.tokens.{profile_name}.access_expires_at"),
                    expires_at,
                    MAX_LEGACY_NAME_LEN,
                )?;
            }
            for (field, secret) in [
                ("access_token", profile.access_token.as_ref()),
                ("refresh_token", profile.refresh_token.as_ref()),
                (
                    "service_account_token",
                    profile.service_account_token.as_ref(),
                ),
            ] {
                if let Some(secret) = secret {
                    validate_string_len(
                        &format!("{base}.tokens.{profile_name}.{field}"),
                        secret.expose_secret(),
                        MAX_CREDENTIAL_SECRET_LEN,
                    )?;
                }
            }
        }
    }
    let potential_slots =
        profile_count
            .checked_mul(3)
            .ok_or_else(|| ConfigError::InvalidConfig {
                path: "$.contexts.*.tokens".to_string(),
                reason: "credential slot count overflow".to_string(),
            })?;
    validate_count(
        "$.contexts.*.tokens.*",
        potential_slots,
        MAX_CREDENTIAL_SLOTS,
    )?;
    for (address, fingerprint) in known_hosts {
        validate_string_len("$.known_hosts.<address>", address, MAX_ADDRESS_LEN)?;
        validate_string_len(
            "$.known_hosts.<fingerprint>",
            fingerprint,
            MAX_METADATA_VALUE_LEN,
        )?;
    }
    Ok(())
}

fn migrate_legacy(
    input: &LegacyInput,
    legacy_client: &ClientId,
    credential_store: &dyn CredentialStore,
    legacy_credentials: &dyn LegacyCredentialSource,
    paths: &ClientPaths,
) -> Result<ConfigV2, ConfigError> {
    let (mut legacy, legacy_unknown) = match input.config_bytes.as_deref() {
        Some(bytes) => {
            validate_json_shape(bytes, JSON_NODE_LIMIT).map_err(|source| {
                ConfigError::Malformed {
                    path: paths.legacy_config(),
                    source,
                }
            })?;
            let unknown =
                scan_legacy_unknown_fields(bytes).map_err(|source| ConfigError::Malformed {
                    path: paths.legacy_config(),
                    source,
                })?;
            let legacy = serde_json::from_slice::<LegacyConfig>(bytes).map_err(|source| {
                ConfigError::Malformed {
                    path: paths.legacy_config(),
                    source,
                }
            })?;
            (legacy, unknown)
        }
        None => (LegacyConfig::default(), LegacyUnknownFields::default()),
    };
    let known_hosts = match input.known_hosts_bytes.as_deref() {
        Some(bytes) => {
            validate_json_shape(bytes, JSON_NODE_LIMIT).map_err(|source| {
                ConfigError::Malformed {
                    path: paths.legacy_known_hosts(),
                    source,
                }
            })?;
            serde_json::from_slice::<BTreeMap<String, String>>(bytes).map_err(|source| {
                ConfigError::Malformed {
                    path: paths.legacy_known_hosts(),
                    source,
                }
            })?
        }
        None => BTreeMap::new(),
    };

    if let Some(path) = &legacy_unknown.credential_profile {
        return Err(ConfigError::UnknownLegacyCredentialField { path: path.clone() });
    }
    validate_legacy_references(&legacy)?;
    validate_legacy_budgets(&legacy, &known_hosts, &legacy_unknown.deferred)?;
    validate_legacy_keyring_accounts(&legacy, legacy_credentials)?;
    let normalized_known_hosts = normalize_known_hosts(&known_hosts)?;
    backfill_legacy_bindings(&mut legacy, &normalized_known_hosts)?;
    let credential_repository_binding = repository_binding(paths.root())?;
    let mut config = build_provisional_legacy_config(
        &legacy,
        legacy_client,
        &credential_repository_binding,
        &input.digest,
        &known_hosts,
        &normalized_known_hosts,
        legacy_unknown.deferred,
    )?;
    let provisional_bytes = serialize_config(&config)?;
    drop(provisional_bytes);

    let pending_credentials = resolve_legacy_credentials(
        &mut config,
        &legacy,
        &credential_repository_binding,
        &input.digest,
        legacy_credentials,
    )?;
    validate_config(&config)?;
    let candidate_bytes = serialize_config(&config)?;
    drop(candidate_bytes);
    store_legacy_credentials(credential_store, &pending_credentials)?;
    Ok(config)
}

fn validate_legacy_keyring_accounts(
    legacy: &LegacyConfig,
    legacy_credentials: &dyn LegacyCredentialSource,
) -> Result<(), ConfigError> {
    let semantics = legacy_credentials.account_semantics();
    let mut locators = Vec::new();
    for (connection_name, connection) in &legacy.contexts {
        for (profile_name, profile) in &connection.tokens {
            let ambiguous = connection_name.contains("::") || profile_name.contains("::");
            if ambiguous {
                if profile.access_token.is_none()
                    && profile.refresh_token.is_none()
                    && profile.service_account_token.is_none()
                {
                    return Err(ConfigError::AmbiguousLegacyCredentialAccount {
                        locator: LegacyCredentialLocator {
                            connection_name: connection_name.clone(),
                            profile_name: profile_name.clone(),
                            kind: CredentialKind::Access,
                        },
                    });
                }
                continue;
            }
            for (kind, inline) in [
                (CredentialKind::Access, profile.access_token.as_ref()),
                (
                    CredentialKind::ServiceAccount,
                    profile.service_account_token.as_ref(),
                ),
            ] {
                let locator = LegacyCredentialLocator {
                    connection_name: connection_name.clone(),
                    profile_name: profile_name.clone(),
                    kind,
                };
                let account = locator.cli_keyring_account().ok_or_else(|| {
                    ConfigError::AmbiguousLegacyCredentialAccount {
                        locator: locator.clone(),
                    }
                })?;
                let queries_source =
                    semantics == LegacyCredentialAccountSemantics::Exact || inline.is_none();
                locators.push((locator, account, queries_source));
            }
        }
    }

    // A completely inline Windows migration never consults the historical
    // case-insensitive namespace, so aliases there are irrelevant to the v2
    // result. If any lookup is needed, every logical account participates in
    // collision analysis so an inline `Prod` cannot hide an external `prod`.
    if semantics == LegacyCredentialAccountSemantics::WindowsCaseInsensitive
        && !locators.iter().any(|(_, _, queries)| *queries)
    {
        return Ok(());
    }

    let mut accounts = BTreeMap::new();
    for (locator, account, _) in &locators {
        let identity = legacy_account_identity(account, locator, semantics)?;
        if let Some(first) = accounts.insert(identity, locator.clone()) {
            if first != *locator {
                return Err(ConfigError::LegacyCredentialAccountConflict {
                    account: account.clone(),
                    first: Box::new(first),
                    second: Box::new(locator.clone()),
                });
            }
        }
    }

    for (locator, _, queries_source) in locators {
        if queries_source {
            if semantics == LegacyCredentialAccountSemantics::WindowsCaseInsensitive
                && !legacy_credentials.verifies_exact_account_identity()
            {
                return Err(ConfigError::AmbiguousLegacyCredentialAccount { locator });
            }
            legacy_credentials.validate(&locator).map_err(|source| {
                ConfigError::CredentialSource {
                    locator: locator.clone(),
                    source,
                }
            })?;
        }
    }
    Ok(())
}

fn legacy_account_identity(
    account: &str,
    locator: &LegacyCredentialLocator,
    semantics: LegacyCredentialAccountSemantics,
) -> Result<String, ConfigError> {
    match semantics {
        LegacyCredentialAccountSemantics::Exact => Ok(account.to_string()),
        LegacyCredentialAccountSemantics::WindowsCaseInsensitive => {
            if !account.is_ascii() {
                return Err(ConfigError::AmbiguousLegacyCredentialAccount {
                    locator: locator.clone(),
                });
            }
            Ok(account.to_ascii_lowercase())
        }
    }
}

fn build_provisional_legacy_config(
    legacy: &LegacyConfig,
    legacy_client: &ClientId,
    repository_binding: &[u8],
    source_digest: &str,
    known_hosts: &BTreeMap<String, String>,
    normalized_known_hosts: &BTreeMap<String, (String, String)>,
    deferred_legacy_fields: BTreeSet<String>,
) -> Result<ConfigV2, ConfigError> {
    let mut config = ConfigV2::empty();
    config.identity = legacy.identity.as_ref().map(|identity| ConfigIdentity {
        kdf_salt: identity.kdf_salt.clone(),
        kdf_params: identity.kdf_params.clone(),
        salt_fingerprint: identity.salt_fingerprint.clone(),
        first_seen_at: identity.first_seen_at.clone(),
        email: identity.email.clone(),
    });
    if let Some(storage) = &legacy.storage {
        let desktop_id = ClientId("desktop".to_string());
        let desktop = client_entry(&mut config, &desktop_id);
        if let ClientNamespace::DesktopV1(namespace) = &mut desktop.namespace {
            namespace.backup = Some(DesktopBackupSettings {
                backup_dir: storage.backup_dir.clone(),
                backup_retention_days: storage.backup_retention_days,
                backup_max_count: storage.backup_max_count,
            });
        }
    }
    let mut consumed_known_hosts = BTreeSet::new();
    let mut trust_by_address: BTreeMap<String, String> = BTreeMap::new();
    let mut ids_by_name = BTreeMap::new();
    let mut default_vault_by_connection = BTreeMap::new();

    for (name, legacy_connection) in &legacy.contexts {
        let normalized_address =
            normalize_address(&legacy_connection.addr, &format!("$.contexts.{name}.addr"))?;
        let known_host_fingerprint = normalized_known_hosts.get(&normalized_address);
        if let Some((original, fingerprint)) = known_host_fingerprint {
            consumed_known_hosts.insert(original.clone());
            if let Some(config_fingerprint) = &legacy_connection.server_fingerprint {
                if config_fingerprint != fingerprint {
                    return Err(ConfigError::TrustConflict {
                        address: legacy_connection.addr.clone(),
                        config_fingerprint: config_fingerprint.clone(),
                        known_hosts_fingerprint: fingerprint.clone(),
                    });
                }
            }
        }
        let fingerprint = legacy_connection
            .server_fingerprint
            .clone()
            .or_else(|| known_host_fingerprint.map(|(_, fingerprint)| fingerprint.clone()));
        if let Some(candidate) = &fingerprint {
            if let Some(existing) = trust_by_address.insert(normalized_address, candidate.clone()) {
                if existing != *candidate {
                    return Err(ConfigError::TrustConflict {
                        address: legacy_connection.addr.clone(),
                        config_fingerprint: existing,
                        known_hosts_fingerprint: candidate.clone(),
                    });
                }
            }
        }

        let connection_id = ConnectionId::deterministic(name, &legacy_connection.addr);
        let mut connection = ConnectionConfig {
            metadata: ConnectionMetadata {
                name: name.clone(),
                address: legacy_connection.addr.clone(),
                needs_salt_update: legacy_connection.needs_salt_update,
                server_id: legacy_connection.server_id.clone(),
                server_fingerprint: fingerprint,
                expected_master_key_fp: legacy_connection.expected_master_key_fp.clone(),
                storage_id: legacy_connection.storage_id.clone(),
            },
            credential_profiles: BTreeMap::new(),
            active_credential: legacy_connection.current_token.clone(),
        };
        if let Some(vault) = &legacy_connection.vault {
            default_vault_by_connection.insert(connection_id.clone(), vault.clone());
        }

        for (profile_name, legacy_profile) in &legacy_connection.tokens {
            let mut credentials = BTreeMap::new();
            for kind in [
                CredentialKind::Access,
                CredentialKind::Refresh,
                CredentialKind::ServiceAccount,
            ] {
                credentials.insert(
                    kind,
                    CredentialId::deterministic(
                        repository_binding,
                        source_digest,
                        &connection_id,
                        profile_name,
                        kind,
                    ),
                );
            }
            connection.credential_profiles.insert(
                profile_name.clone(),
                CredentialProfile {
                    account_subject: None,
                    auth_method: None,
                    access_expires_at: legacy_profile.access_expires_at.clone(),
                    credentials,
                },
            );
        }
        ids_by_name.insert(name.clone(), connection_id.clone());
        config.connections.insert(connection_id, connection);
    }

    if let Some(current_context) = &legacy.current_context {
        let active_connection = ids_by_name.get(current_context).cloned().ok_or_else(|| {
            ConfigError::MissingConnection {
                connection_id: ConnectionId::deterministic(current_context, "missing"),
            }
        })?;
        client_entry(&mut config, legacy_client).active_connection = Some(active_connection);
    }
    if !default_vault_by_connection.is_empty() {
        let cli_id = ClientId("cli".to_string());
        let cli = client_entry(&mut config, &cli_id);
        if let ClientNamespace::CliV1(namespace) = &mut cli.namespace {
            namespace.default_vault_by_connection = default_vault_by_connection;
        }
    }

    let unmatched_known_hosts: BTreeMap<_, _> = known_hosts
        .iter()
        .filter(|(address, _)| !consumed_known_hosts.contains(*address))
        .map(|(address, fingerprint)| (address.clone(), fingerprint.clone()))
        .collect();
    if !unmatched_known_hosts.is_empty() {
        config.legacy_known_hosts = unmatched_known_hosts;
    }
    config.migration = Some(MigrationStamp {
        source_format: "legacy-v1".to_string(),
        source_digest: source_digest.to_string(),
        claimed_clients: BTreeSet::from([legacy_client.clone()]),
        deferred_legacy_fields,
    });
    validate_config(&config)?;
    Ok(config)
}

fn resolve_legacy_credentials(
    config: &mut ConfigV2,
    legacy: &LegacyConfig,
    repository_binding: &[u8],
    source_digest: &str,
    legacy_credentials: &dyn LegacyCredentialSource,
) -> Result<Vec<(CredentialKind, CredentialId, CredentialSecret)>, ConfigError> {
    let mut pending_credentials = Vec::new();
    for (connection_name, legacy_connection) in &legacy.contexts {
        let connection_id = ConnectionId::deterministic(connection_name, &legacy_connection.addr);
        for (profile_name, legacy_profile) in &legacy_connection.tokens {
            let mut credentials = BTreeMap::new();
            for (kind, inline) in [
                (CredentialKind::Access, legacy_profile.access_token.as_ref()),
                (
                    CredentialKind::Refresh,
                    legacy_profile.refresh_token.as_ref(),
                ),
                (
                    CredentialKind::ServiceAccount,
                    legacy_profile.service_account_token.as_ref(),
                ),
            ] {
                if let Some((kind, credential_id, secret)) = resolve_credential(
                    repository_binding,
                    source_digest,
                    &connection_id,
                    LegacyCredentialLocator {
                        connection_name: connection_name.clone(),
                        profile_name: profile_name.clone(),
                        kind,
                    },
                    inline,
                    legacy_credentials,
                )? {
                    credentials.insert(kind, credential_id.clone());
                    pending_credentials.push((kind, credential_id, secret));
                }
            }
            if credentials.is_empty() {
                return Err(ConfigError::MissingCredential {
                    connection_name: connection_name.clone(),
                    profile_name: profile_name.clone(),
                });
            }
            let connection = config.connections.get_mut(&connection_id).ok_or_else(|| {
                ConfigError::MissingConnection {
                    connection_id: connection_id.clone(),
                }
            })?;
            let profile = connection
                .credential_profiles
                .get_mut(profile_name)
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: format!(
                        "$.connections.{connection_id}.credential_profiles.{profile_name}"
                    ),
                    reason: "provisional credential profile is missing".to_string(),
                })?;
            profile.credentials = credentials;
        }
    }
    Ok(pending_credentials)
}

fn resolve_credential(
    repository_binding: &[u8],
    source_digest: &str,
    connection_id: &ConnectionId,
    locator: LegacyCredentialLocator,
    inline: Option<&LegacySecret>,
    legacy_credentials: &dyn LegacyCredentialSource,
) -> Result<Option<(CredentialKind, CredentialId, CredentialSecret)>, ConfigError> {
    let kind = locator.kind;
    let unrepresentable_cli_account = locator.cli_keyring_account().is_none();
    let skip_case_insensitive_inline_lookup = inline.is_some()
        && legacy_credentials.account_semantics()
            == LegacyCredentialAccountSemantics::WindowsCaseInsensitive;
    let external = if unrepresentable_cli_account || skip_case_insensitive_inline_lookup {
        None
    } else {
        legacy_credentials
            .get(&locator)
            .map_err(|source| ConfigError::CredentialSource {
                locator: locator.clone(),
                source,
            })?
    };
    let selected =
        match (inline, external) {
            (Some(inline), Some(external)) => {
                if inline.expose_secret() != external.expose_secret() {
                    return Err(ConfigError::CredentialConflict { locator });
                }
                CredentialSecret::new(inline.expose_secret().to_string()).map_err(|source| {
                    ConfigError::InvalidCredentialSecret {
                        locator: locator.clone(),
                        source,
                    }
                })?
            }
            (Some(inline), None) => CredentialSecret::new(inline.expose_secret().to_string())
                .map_err(|source| ConfigError::InvalidCredentialSecret {
                    locator: locator.clone(),
                    source,
                })?,
            (None, Some(external)) => external,
            (None, None) => return Ok(None),
        };
    let credential_id = CredentialId::deterministic(
        repository_binding,
        source_digest,
        connection_id,
        &locator.profile_name,
        kind,
    );
    Ok(Some((kind, credential_id, selected)))
}

fn store_legacy_credentials(
    store: &dyn CredentialStore,
    pending: &[(CredentialKind, CredentialId, CredentialSecret)],
) -> Result<(), ConfigError> {
    for (kind, credential_id, secret) in pending {
        store.validate(credential_id, secret).map_err(|source| {
            ConfigError::CredentialValidation {
                kind: *kind,
                source,
            }
        })?;
    }

    let mut missing = BTreeSet::new();
    for (_, credential_id, secret) in pending {
        let existing = store
            .get(credential_id)
            .map_err(|source| ConfigError::CredentialStore {
                operation: "preflight read",
                credential_id: credential_id.clone(),
                source,
            })?;
        match existing {
            Some(existing) if existing.expose_secret() != secret.expose_secret() => {
                return Err(ConfigError::CredentialIdConflict {
                    credential_id: credential_id.clone(),
                });
            }
            Some(_) => {}
            None => {
                missing.insert(credential_id.clone());
            }
        }
    }

    for (_, credential_id, secret) in pending {
        if missing.contains(credential_id) {
            store
                .put(credential_id, secret)
                .map_err(|source| ConfigError::CredentialStore {
                    operation: "write",
                    credential_id: credential_id.clone(),
                    source,
                })?;
        }
    }

    for (_, credential_id, secret) in pending {
        let verified = store
            .get(credential_id)
            .map_err(|source| ConfigError::CredentialStore {
                operation: "verify",
                credential_id: credential_id.clone(),
                source,
            })?;
        if verified
            .as_ref()
            .is_none_or(|stored| stored.expose_secret() != secret.expose_secret())
        {
            return Err(ConfigError::CredentialVerification {
                credential_id: credential_id.clone(),
            });
        }
    }
    Ok(())
}

fn backfill_legacy_bindings(
    legacy: &mut LegacyConfig,
    known_hosts: &BTreeMap<String, (String, String)>,
) -> Result<(), ConfigError> {
    let mut bindings: BTreeMap<String, (Option<String>, Option<String>, String)> = BTreeMap::new();
    for (name, connection) in &legacy.contexts {
        let path = format!("$.contexts.{name}.addr");
        let normalized = normalize_address(&connection.addr, &path)?;
        let known_fingerprint = known_hosts
            .get(&normalized)
            .map(|(_, fingerprint)| fingerprint);
        if let (Some(config_fingerprint), Some(known_fingerprint)) =
            (&connection.server_fingerprint, known_fingerprint)
        {
            if config_fingerprint != known_fingerprint {
                return Err(ConfigError::TrustConflict {
                    address: connection.addr.clone(),
                    config_fingerprint: config_fingerprint.clone(),
                    known_hosts_fingerprint: known_fingerprint.clone(),
                });
            }
        }
        let candidate_fingerprint = connection
            .server_fingerprint
            .clone()
            .or_else(|| known_fingerprint.cloned());
        match bindings.get_mut(&normalized) {
            Some((server_id, fingerprint, previous_name)) => {
                if let (Some(previous), Some(current)) =
                    (server_id.as_ref(), connection.server_id.as_ref())
                {
                    if previous != current {
                        return Err(ConfigError::InvalidConfig {
                            path: format!("$.contexts.{name}.server_id"),
                            reason: format!(
                                "conflicts with context {previous_name} for endpoint {normalized}"
                            ),
                        });
                    }
                } else if server_id.is_none() {
                    *server_id = connection.server_id.clone();
                }
                if let (Some(previous), Some(current)) =
                    (fingerprint.as_ref(), candidate_fingerprint.as_ref())
                {
                    if previous != current {
                        return Err(ConfigError::TrustConflict {
                            address: connection.addr.clone(),
                            config_fingerprint: previous.clone(),
                            known_hosts_fingerprint: current.clone(),
                        });
                    }
                } else if fingerprint.is_none() {
                    *fingerprint = candidate_fingerprint;
                }
            }
            None => {
                bindings.insert(
                    normalized,
                    (
                        connection.server_id.clone(),
                        candidate_fingerprint,
                        name.clone(),
                    ),
                );
            }
        }
    }
    for (name, connection) in &mut legacy.contexts {
        let normalized = normalize_address(&connection.addr, &format!("$.contexts.{name}.addr"))?;
        let (server_id, fingerprint, _) =
            bindings
                .get(&normalized)
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: format!("$.contexts.{name}"),
                    reason: "missing normalized endpoint binding".to_string(),
                })?;
        connection.server_id = server_id.clone();
        connection.server_fingerprint = fingerprint.clone();
    }
    Ok(())
}

fn normalize_known_hosts(
    known_hosts: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, (String, String)>, ConfigError> {
    let mut normalized: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (address, fingerprint) in known_hosts {
        let key = normalize_address(address, &format!("$.known_hosts.{address}"))?;
        if let Some((_, existing)) = normalized.get(&key) {
            if existing != fingerprint {
                return Err(ConfigError::TrustConflict {
                    address: address.clone(),
                    config_fingerprint: existing.clone(),
                    known_hosts_fingerprint: fingerprint.clone(),
                });
            }
        }
        normalized.insert(key, (address.clone(), fingerprint.clone()));
    }
    Ok(normalized)
}

fn normalize_address(address: &str, path: &str) -> Result<String, ConfigError> {
    let mut parsed = Url::parse(address).map_err(|error| ConfigError::InvalidConfig {
        path: path.to_string(),
        reason: format!("invalid server URL: {error}"),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "server URL scheme must be http or https".to_string(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "server URL must not contain userinfo".to_string(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "server URL must not contain a query or fragment".to_string(),
        });
    }
    if parsed.host().is_none() || parsed.cannot_be_a_base() {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "server URL must have a network host".to_string(),
        });
    }
    if parsed.path().contains('%') {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "percent-encoded server URL paths are not supported".to_string(),
        });
    }
    let normalized_domain = match parsed.host() {
        Some(Host::Domain(domain)) if domain.ends_with('.') => {
            let domain = domain.strip_suffix('.').unwrap_or_default();
            if domain.is_empty() || domain.ends_with('.') {
                return Err(ConfigError::InvalidConfig {
                    path: path.to_string(),
                    reason: "server URL has an invalid DNS trailing dot".to_string(),
                });
            }
            Some(domain.to_string())
        }
        _ => None,
    };
    if let Some(domain) = normalized_domain {
        parsed
            .set_host(Some(&domain))
            .map_err(|error| ConfigError::InvalidConfig {
                path: path.to_string(),
                reason: format!("invalid normalized server host: {error}"),
            })?;
    }
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

#[derive(Default)]
struct LegacyUnknownFields {
    deferred: BTreeSet<String>,
    credential_profile: Option<String>,
}

#[derive(Clone, Copy)]
enum LegacyScanKind {
    Root,
    Contexts,
    Connection,
    Profiles,
    Profile,
    Identity,
    Storage,
}

#[derive(Clone)]
struct LegacyScan {
    kind: LegacyScanKind,
    path: String,
    fields: Rc<RefCell<LegacyUnknownFields>>,
}

impl LegacyScan {
    fn child(&self, kind: LegacyScanKind, path: String) -> Self {
        Self {
            kind,
            path,
            fields: Rc::clone(&self.fields),
        }
    }

    fn record_deferred<E: de::Error>(&self, path: String) -> Result<(), E> {
        let mut fields = self.fields.borrow_mut();
        if !fields.deferred.contains(&path) && fields.deferred.len() >= MAX_DEFERRED_FIELDS {
            return Err(de::Error::custom("legacy deferred-field budget exceeded"));
        }
        fields.deferred.insert(path);
        Ok(())
    }

    fn record_credential_profile_unknown(&self, path: String) {
        let mut fields = self.fields.borrow_mut();
        if fields.credential_profile.is_none() {
            fields.credential_profile = Some(path);
        }
    }
}

impl<'de> DeserializeSeed<'de> for LegacyScan {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for LegacyScan {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("legacy JSON")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E> {
        value.zeroize();
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(mut key) = map.next_key::<String>()? {
            match self.kind {
                LegacyScanKind::Root => match key.as_str() {
                    "contexts" => map.next_value_seed(
                        self.child(LegacyScanKind::Contexts, "$.contexts".to_string()),
                    )?,
                    "identity" => map.next_value_seed(
                        self.child(LegacyScanKind::Identity, "$.identity".to_string()),
                    )?,
                    "storage" => map.next_value_seed(
                        self.child(LegacyScanKind::Storage, "$.storage".to_string()),
                    )?,
                    "current_context" => {
                        map.next_value::<IgnoredAny>()?;
                    }
                    _ => {
                        let path = checked_legacy_scan_path::<A::Error>(
                            &self.path,
                            &key,
                            MAX_DEFERRED_PATH_LEN,
                        )?;
                        self.record_deferred(path)?;
                        map.next_value::<IgnoredAny>()?;
                    }
                },
                LegacyScanKind::Contexts => {
                    let path = checked_legacy_scan_path::<A::Error>(
                        &self.path,
                        &key,
                        MAX_LEGACY_NAME_LEN,
                    )?;
                    map.next_value_seed(self.child(LegacyScanKind::Connection, path))?
                }
                LegacyScanKind::Connection => match key.as_str() {
                    "tokens" => {
                        let path = checked_legacy_scan_path::<A::Error>(
                            &self.path,
                            &key,
                            MAX_LEGACY_NAME_LEN,
                        )?;
                        map.next_value_seed(self.child(LegacyScanKind::Profiles, path))?
                    }
                    "addr"
                    | "needs_salt_update"
                    | "server_id"
                    | "server_fingerprint"
                    | "expected_master_key_fp"
                    | "current_token"
                    | "storage_id"
                    | "vault" => {
                        map.next_value::<IgnoredAny>()?;
                    }
                    _ => {
                        let path = checked_legacy_scan_path::<A::Error>(
                            &self.path,
                            &key,
                            MAX_DEFERRED_PATH_LEN,
                        )?;
                        self.record_deferred(path)?;
                        map.next_value::<IgnoredAny>()?;
                    }
                },
                LegacyScanKind::Profiles => {
                    let path = checked_legacy_scan_path::<A::Error>(
                        &self.path,
                        &key,
                        MAX_LEGACY_NAME_LEN,
                    )?;
                    map.next_value_seed(self.child(LegacyScanKind::Profile, path))?
                }
                LegacyScanKind::Profile => match key.as_str() {
                    "access_token"
                    | "refresh_token"
                    | "service_account_token"
                    | "access_expires_at" => {
                        map.next_value::<IgnoredAny>()?;
                    }
                    _ => {
                        if self.fields.borrow().credential_profile.is_none() {
                            let path = checked_legacy_scan_path::<A::Error>(
                                &self.path,
                                &key,
                                MAX_DEFERRED_PATH_LEN,
                            )?;
                            self.record_credential_profile_unknown(path);
                        }
                        map.next_value::<IgnoredAny>()?;
                    }
                },
                LegacyScanKind::Identity => match key.as_str() {
                    "kdf_salt" | "kdf_params" | "salt_fingerprint" | "first_seen_at" | "email" => {
                        map.next_value::<IgnoredAny>()?;
                    }
                    _ => {
                        let path = checked_legacy_scan_path::<A::Error>(
                            &self.path,
                            &key,
                            MAX_DEFERRED_PATH_LEN,
                        )?;
                        self.record_deferred(path)?;
                        map.next_value::<IgnoredAny>()?;
                    }
                },
                LegacyScanKind::Storage => match key.as_str() {
                    "backup_dir" | "backup_retention_days" | "backup_max_count" => {
                        map.next_value::<IgnoredAny>()?;
                    }
                    _ => {
                        let path = checked_legacy_scan_path::<A::Error>(
                            &self.path,
                            &key,
                            MAX_DEFERRED_PATH_LEN,
                        )?;
                        self.record_deferred(path)?;
                        map.next_value::<IgnoredAny>()?;
                    }
                },
            }
            key.zeroize();
        }
        Ok(())
    }
}

fn scan_legacy_unknown_fields(bytes: &[u8]) -> Result<LegacyUnknownFields, serde_json::Error> {
    let fields = Rc::new(RefCell::new(LegacyUnknownFields::default()));
    let scan = LegacyScan {
        kind: LegacyScanKind::Root,
        path: "$".to_string(),
        fields: Rc::clone(&fields),
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    scan.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Rc::try_unwrap(fields)
        .map(RefCell::into_inner)
        .map_err(|_| de::Error::custom("legacy scan retained internal state"))
}

fn legacy_path(base: &str, segment: &str) -> String {
    let escaped = escape_legacy_path_segment(segment);
    if escaped.starts_with('[') {
        format!("{base}{escaped}")
    } else {
        format!("{base}.{escaped}")
    }
}

fn checked_legacy_scan_path<E: de::Error>(
    base: &str,
    segment: &str,
    maximum_segment_len: usize,
) -> Result<String, E> {
    if segment.is_empty() || segment.len() > maximum_segment_len {
        return Err(de::Error::custom(
            "legacy JSON path segment is out of bounds",
        ));
    }
    let path = legacy_path(base, segment);
    if path.len() > MAX_DEFERRED_PATH_LEN {
        return Err(de::Error::custom(
            "legacy JSON path exceeds configured limit",
        ));
    }
    Ok(path)
}

fn escape_legacy_path_segment(segment: &str) -> String {
    if segment
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        segment.to_string()
    } else {
        format!("['{}']", segment.replace('\\', "\\\\").replace('\'', "\\'"))
    }
}

fn validate_legacy_references(legacy: &LegacyConfig) -> Result<(), ConfigError> {
    if let Some(current_context) = &legacy.current_context {
        if !legacy.contexts.contains_key(current_context) {
            return Err(ConfigError::InvalidConfig {
                path: "$.current_context".to_string(),
                reason: format!("context does not exist: {current_context}"),
            });
        }
    }
    for (connection_name, connection) in &legacy.contexts {
        if let Some(current_token) = &connection.current_token {
            if !connection.tokens.contains_key(current_token) {
                return Err(ConfigError::InvalidConfig {
                    path: format!("$.contexts.{connection_name}.current_token"),
                    reason: format!("credential profile does not exist: {current_token}"),
                });
            }
        }
    }
    Ok(())
}

#[derive(Default, Deserialize)]
struct LegacyConfig {
    #[serde(default)]
    current_context: Option<String>,
    #[serde(default)]
    contexts: BTreeMap<String, LegacyConnection>,
    #[serde(default)]
    identity: Option<LegacyIdentity>,
    #[serde(default)]
    storage: Option<LegacyStorage>,
}

#[derive(Deserialize)]
struct LegacyClientClaim {
    #[serde(default)]
    current_context: Option<String>,
    #[serde(default)]
    contexts: BTreeMap<String, LegacyConnectionClaim>,
}

#[derive(Deserialize)]
struct LegacyConnectionClaim {
    addr: String,
}

#[derive(Deserialize)]
struct LegacyStorage {
    #[serde(default)]
    backup_dir: Option<String>,
    #[serde(default)]
    backup_retention_days: Option<u32>,
    #[serde(default)]
    backup_max_count: Option<u32>,
}

#[derive(Deserialize)]
struct LegacyIdentity {
    kdf_salt: String,
    kdf_params: ConfigKdfParams,
    #[serde(default)]
    salt_fingerprint: Option<String>,
    #[serde(default)]
    first_seen_at: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

impl From<LegacyIdentity> for ConfigIdentity {
    fn from(identity: LegacyIdentity) -> Self {
        Self {
            kdf_salt: identity.kdf_salt,
            kdf_params: identity.kdf_params,
            salt_fingerprint: identity.salt_fingerprint,
            first_seen_at: identity.first_seen_at,
            email: identity.email,
        }
    }
}

#[derive(Deserialize)]
struct LegacyConnection {
    addr: String,
    #[serde(default)]
    needs_salt_update: bool,
    #[serde(default)]
    server_id: Option<String>,
    #[serde(default)]
    server_fingerprint: Option<String>,
    #[serde(default)]
    expected_master_key_fp: Option<String>,
    #[serde(default)]
    tokens: BTreeMap<String, LegacyCredentialProfile>,
    #[serde(default)]
    current_token: Option<String>,
    #[serde(default)]
    storage_id: Option<String>,
    #[serde(default)]
    vault: Option<String>,
}

#[derive(Deserialize)]
struct LegacyCredentialProfile {
    #[serde(default)]
    access_token: Option<LegacySecret>,
    #[serde(default)]
    refresh_token: Option<LegacySecret>,
    #[serde(default)]
    service_account_token: Option<LegacySecret>,
    #[serde(default)]
    access_expires_at: Option<String>,
}

struct LegacySecret(Zeroizing<String>);

impl LegacySecret {
    fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for LegacySecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

#[cfg(test)]
mod authenticated_session_tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use tempfile::TempDir;

    type PutCallback = Box<dyn FnOnce() + Send>;

    #[derive(Default)]
    struct TestCredentialStore {
        values: Mutex<BTreeMap<String, String>>,
        validations: AtomicUsize,
        reads: AtomicUsize,
        puts: AtomicUsize,
        deletes: AtomicUsize,
        deleted_ids: Mutex<Vec<CredentialId>>,
        fail_deletes: AtomicBool,
        after_put: Mutex<Option<PutCallback>>,
    }

    impl TestCredentialStore {
        fn calls(&self) -> (usize, usize, usize, usize) {
            (
                self.validations.load(Ordering::SeqCst),
                self.reads.load(Ordering::SeqCst),
                self.puts.load(Ordering::SeqCst),
                self.deletes.load(Ordering::SeqCst),
            )
        }

        fn set_after_put(&self, callback: impl FnOnce() + Send + 'static) {
            *self.after_put.lock().expect("callback lock") = Some(Box::new(callback));
        }

        fn value(&self, credential_id: &CredentialId) -> Option<String> {
            self.values
                .lock()
                .expect("credential map lock")
                .get(credential_id.as_str())
                .cloned()
        }

        fn deleted_ids(&self) -> Vec<CredentialId> {
            self.deleted_ids.lock().expect("deleted ids lock").clone()
        }

        fn set_fail_deletes(&self, fail: bool) {
            self.fail_deletes.store(fail, Ordering::SeqCst);
        }
    }

    impl CredentialStore for TestCredentialStore {
        fn validate(
            &self,
            _credential_id: &CredentialId,
            _secret: &CredentialSecret,
        ) -> Result<(), CredentialPortError> {
            self.validations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn put(
            &self,
            credential_id: &CredentialId,
            secret: &CredentialSecret,
        ) -> Result<(), CredentialPortError> {
            self.puts.fetch_add(1, Ordering::SeqCst);
            self.values.lock().expect("credential map lock").insert(
                credential_id.as_str().to_string(),
                secret.expose_secret().to_string(),
            );
            let callback = self.after_put.lock().expect("callback lock").take();
            if let Some(callback) = callback {
                callback();
            }
            Ok(())
        }

        fn get(
            &self,
            credential_id: &CredentialId,
        ) -> Result<Option<CredentialSecret>, CredentialPortError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.values
                .lock()
                .expect("credential map lock")
                .get(credential_id.as_str())
                .cloned()
                .map(CredentialSecret::new)
                .transpose()
                .map_err(|error| CredentialPortError::new(error.to_string()))
        }

        fn delete(&self, credential_id: &CredentialId) -> Result<(), CredentialPortError> {
            self.deletes.fetch_add(1, Ordering::SeqCst);
            self.deleted_ids
                .lock()
                .expect("deleted ids lock")
                .push(credential_id.clone());
            if self.fail_deletes.load(Ordering::SeqCst) {
                return Err(CredentialPortError::new("injected delete failure"));
            }
            self.values
                .lock()
                .expect("credential map lock")
                .remove(credential_id.as_str());
            Ok(())
        }
    }

    struct EmptyLegacyCredentials;

    impl LegacyCredentialSource for EmptyLegacyCredentials {
        fn get(
            &self,
            _locator: &LegacyCredentialLocator,
        ) -> Result<Option<CredentialSecret>, CredentialPortError> {
            Ok(None)
        }
    }

    fn repository(temp: &TempDir) -> ConfigRepository {
        ConfigRepository::new(ClientPaths::new(temp.path()))
    }

    fn client_id(value: &str) -> ClientId {
        ClientId::new(value).expect("client id")
    }

    fn initialize(repo: &ConfigRepository) {
        repo.initialize(
            &client_id("test"),
            &TestCredentialStore::default(),
            &EmptyLegacyCredentials,
        )
        .expect("initialize empty config");
    }

    fn identity(label: &str) -> ConfigIdentity {
        ConfigIdentity {
            kdf_salt: format!("salt-{label}"),
            kdf_params: ConfigKdfParams {
                algorithm: "argon2id".to_string(),
                iterations: 3,
                memory_kb: 64 * 1024,
                parallelism: 1,
            },
            salt_fingerprint: None,
            first_seen_at: None,
            email: None,
        }
    }

    fn endpoint(address: &str, server_id: &str, fingerprint: &str) -> VerifiedEndpointBinding {
        VerifiedEndpointBinding::new_for_test(address, server_id, fingerprint)
            .expect("verified endpoint")
    }

    fn stored_binding(
        address: &str,
        server_id: Option<&str>,
        fingerprint: Option<&str>,
        storage_id: Option<&str>,
    ) -> StoredConnectionBinding {
        StoredConnectionBinding::new(
            address,
            server_id.map(str::to_string),
            fingerprint.map(str::to_string),
            storage_id.map(str::to_string),
        )
    }

    fn bundle(value: &str) -> CredentialBundle {
        CredentialBundle::new(
            Some(CredentialSecret::new(value).expect("credential secret")),
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit(
        repo: &ConfigRepository,
        revision: u64,
        endpoint: VerifiedEndpointBinding,
        storage_id: Option<&str>,
        target: AuthenticatedConnectionTarget,
        identity: IdentityCommit,
        client: &str,
        profile: &str,
        secret: &str,
        store: &TestCredentialStore,
    ) -> Result<AuthenticatedSessionOutcome, ConfigError> {
        repo.commit_authenticated_session(
            revision,
            AuthenticatedSessionCommit::new(
                endpoint,
                storage_id.map(str::to_string),
                target,
                identity,
                client_id(client),
                profile,
                bundle(secret),
            ),
            store,
        )
    }

    #[test]
    fn authenticated_targets_publish_complete_generations_and_preserve_metadata() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let callback_repo = repo.clone();
        store.set_after_put(move || {
            assert!(matches!(
                callback_repo.snapshot(),
                Err(ConfigError::CredentialRecoveryRequired { .. })
            ));
        });
        let config_identity = identity("targets");
        let created = commit(
            &repo,
            0,
            endpoint("https://AUTH.test:443/", "server-a", "pin-a"),
            Some("storage-a"),
            AuthenticatedConnectionTarget::Create {
                connection_name: "primary".to_string(),
            },
            IdentityCommit::InitializeOrMatch(config_identity.clone()),
            "desktop",
            "first",
            "first-secret",
            &store,
        )
        .expect("create authenticated connection");
        let connection_id = created.connection_id().clone();
        assert_eq!(created.snapshot().revision(), 1);
        assert_eq!(created.storage_id(), Some("storage-a"));
        assert_eq!(created.profile_name(), "first");
        assert_eq!(
            created.snapshot().config().identity,
            Some(config_identity.clone())
        );
        let connection = &created.snapshot().config().connections[&connection_id];
        assert_eq!(connection.metadata.address, "https://auth.test");
        assert_eq!(connection.metadata.server_id.as_deref(), Some("server-a"));
        assert_eq!(
            connection.metadata.server_fingerprint.as_deref(),
            Some("pin-a")
        );
        assert_eq!(connection.metadata.storage_id.as_deref(), Some("storage-a"));
        assert_eq!(connection.active_credential(), Some("first"));
        assert_eq!(
            created.snapshot().config().clients[&client_id("desktop")].active_connection(),
            Some(&connection_id)
        );
        let first_id =
            &connection.credential_profiles()["first"].credentials()[&CredentialKind::Access];
        assert_eq!(store.value(first_id).as_deref(), Some("first-secret"));

        let exact = stored_binding(
            "https://auth.test",
            Some("server-a"),
            Some("pin-a"),
            Some("storage-a"),
        );
        commit(
            &repo,
            1,
            endpoint("https://auth.test", "server-a", "pin-a"),
            Some("storage-a"),
            AuthenticatedConnectionTarget::UseExisting {
                connection_id: connection_id.clone(),
                expected: exact,
            },
            IdentityCommit::InitializeOrMatch(config_identity.clone()),
            "cli",
            "second",
            "second-secret",
            &store,
        )
        .expect("use exact authenticated binding");

        let unpinned_id = ConnectionId::deterministic("unpinned", "https://unpinned.test");
        let mut unpinned = ConnectionMetadata::new("unpinned", "https://unpinned.test");
        unpinned.needs_salt_update = true;
        unpinned.expected_master_key_fp = Some("master-key-fp".to_string());
        repo.upsert_connection(unpinned_id.clone(), unpinned)
            .expect("insert unpinned metadata");
        let pinned = commit(
            &repo,
            3,
            endpoint("https://unpinned.test", "server-b", "pin-b"),
            Some("storage-b"),
            AuthenticatedConnectionTarget::PinExisting {
                connection_id: unpinned_id.clone(),
                expected: stored_binding("https://unpinned.test", None, None, None),
            },
            IdentityCommit::InitializeOrMatch(config_identity.clone()),
            "cli",
            "pinned",
            "pinned-secret",
            &store,
        )
        .expect("pin previously unpinned connection");
        let pinned_metadata = pinned.snapshot().config().connections[&unpinned_id].metadata();
        assert!(pinned_metadata.needs_salt_update);
        assert_eq!(
            pinned_metadata.expected_master_key_fp.as_deref(),
            Some("master-key-fp")
        );

        commit(
            &repo,
            4,
            endpoint("https://auth.test", "server-a", "pin-a-2"),
            Some("storage-a"),
            AuthenticatedConnectionTarget::ReplaceFingerprint {
                connection_id: connection_id.clone(),
                expected: stored_binding(
                    "https://auth.test",
                    Some("server-a"),
                    Some("pin-a"),
                    Some("storage-a"),
                ),
            },
            IdentityCommit::InitializeOrMatch(config_identity.clone()),
            "desktop",
            "third",
            "third-secret",
            &store,
        )
        .expect("replace fingerprint under exact trust CAS");
        let relocated = commit(
            &repo,
            5,
            endpoint("https://new.test/base/", "server-a", "pin-a-3"),
            Some("storage-a"),
            AuthenticatedConnectionTarget::RelocateEndpoint {
                connection_id: connection_id.clone(),
                expected: stored_binding(
                    "https://auth.test",
                    Some("server-a"),
                    Some("pin-a-2"),
                    Some("storage-a"),
                ),
            },
            IdentityCommit::InitializeOrMatch(config_identity),
            "desktop",
            "fourth",
            "fourth-secret",
            &store,
        )
        .expect("relocate endpoint with the same signed server id");
        let relocated_connection = &relocated.snapshot().config().connections[&connection_id];
        assert_eq!(
            relocated_connection.metadata.address,
            "https://new.test/base"
        );
        assert_eq!(
            relocated_connection.metadata.server_fingerprint.as_deref(),
            Some("pin-a-3")
        );
        assert_eq!(relocated_connection.credential_profiles().len(), 4);
    }

    #[test]
    fn authenticated_storage_is_optional_and_outcome_reports_the_effective_binding() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let config_identity = identity("optional-storage");
        let calls = store.calls();
        assert!(matches!(
            commit(
                &repo,
                0,
                endpoint("https://remote-only.test", "server-remote", "pin-remote"),
                Some(""),
                AuthenticatedConnectionTarget::Create {
                    connection_name: "remote-only".to_string(),
                },
                IdentityCommit::InitializeOrMatch(config_identity.clone()),
                "cli",
                "invalid",
                "invalid-secret",
                &store,
            )
            .expect_err("Some storage id still requires validation"),
            ConfigError::InvalidConfig { .. }
        ));
        assert_eq!(store.calls(), calls);
        let created = commit(
            &repo,
            0,
            endpoint("https://remote-only.test", "server-remote", "pin-remote"),
            None,
            AuthenticatedConnectionTarget::Create {
                connection_name: "remote-only".to_string(),
            },
            IdentityCommit::InitializeOrMatch(config_identity.clone()),
            "cli",
            "first",
            "first-secret",
            &store,
        )
        .expect("DB-free create without storage");
        let connection_id = created.connection_id().clone();
        assert_eq!(created.storage_id(), None);
        assert_eq!(
            created.snapshot().config().connections[&connection_id]
                .metadata()
                .storage_id,
            None
        );

        let without_storage = stored_binding(
            "https://remote-only.test",
            Some("server-remote"),
            Some("pin-remote"),
            None,
        );
        let still_without_storage = commit(
            &repo,
            1,
            endpoint("https://remote-only.test", "server-remote", "pin-remote"),
            None,
            AuthenticatedConnectionTarget::UseExisting {
                connection_id: connection_id.clone(),
                expected: without_storage.clone(),
            },
            IdentityCommit::InitializeOrMatch(config_identity.clone()),
            "cli",
            "second",
            "second-secret",
            &store,
        )
        .expect("None preserves an existing None binding");
        assert_eq!(still_without_storage.storage_id(), None);

        let filled = commit(
            &repo,
            2,
            endpoint("https://remote-only.test", "server-remote", "pin-remote"),
            Some("storage-local"),
            AuthenticatedConnectionTarget::UseExisting {
                connection_id: connection_id.clone(),
                expected: without_storage,
            },
            IdentityCommit::InitializeOrMatch(config_identity.clone()),
            "desktop",
            "third",
            "third-secret",
            &store,
        )
        .expect("Some fills a previously absent storage binding");
        assert_eq!(filled.storage_id(), Some("storage-local"));

        let with_storage = stored_binding(
            "https://remote-only.test",
            Some("server-remote"),
            Some("pin-remote"),
            Some("storage-local"),
        );
        let preserved = commit(
            &repo,
            3,
            endpoint("https://remote-only.test", "server-remote", "pin-remote"),
            None,
            AuthenticatedConnectionTarget::UseExisting {
                connection_id: connection_id.clone(),
                expected: with_storage.clone(),
            },
            IdentityCommit::InitializeOrMatch(config_identity.clone()),
            "cli",
            "fourth",
            "fourth-secret",
            &store,
        )
        .expect("None preserves an existing Some binding");
        assert_eq!(preserved.storage_id(), Some("storage-local"));
        assert_eq!(
            preserved.snapshot().config().connections[&connection_id]
                .metadata()
                .storage_id
                .as_deref(),
            Some("storage-local")
        );

        let calls = store.calls();
        assert!(matches!(
            commit(
                &repo,
                4,
                endpoint("https://remote-only.test", "server-remote", "pin-remote"),
                Some("storage-replacement"),
                AuthenticatedConnectionTarget::UseExisting {
                    connection_id,
                    expected: with_storage,
                },
                IdentityCommit::InitializeOrMatch(config_identity),
                "cli",
                "replacement",
                "replacement-secret",
                &store,
            )
            .expect_err("Some cannot replace an existing storage binding"),
            ConfigError::AuthenticatedBindingConflict { .. }
        ));
        assert_eq!(store.calls(), calls);
    }

    #[test]
    fn authenticated_conflicts_fail_before_ports_and_leave_primary_unchanged() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let config_identity = identity("conflicts");
        let created = commit(
            &repo,
            0,
            endpoint("https://one.test", "server-one", "pin-one"),
            Some("storage-one"),
            AuthenticatedConnectionTarget::Create {
                connection_name: "one".to_string(),
            },
            IdentityCommit::InitializeOrMatch(config_identity.clone()),
            "cli",
            "first",
            "first-secret",
            &store,
        )
        .expect("first connection");
        let before = fs::read(repo.paths().config()).expect("primary before conflict");
        let calls = store.calls();
        for (verified, target) in [
            (
                endpoint("https://ONE.test:443/", "other-server", "other-pin"),
                AuthenticatedConnectionTarget::Create {
                    connection_name: "address-alias".to_string(),
                },
            ),
            (
                endpoint("https://two.test", "server-one", "other-pin"),
                AuthenticatedConnectionTarget::Create {
                    connection_name: "server-alias".to_string(),
                },
            ),
        ] {
            assert!(matches!(
                commit(
                    &repo,
                    1,
                    verified,
                    Some("storage-two"),
                    target,
                    IdentityCommit::InitializeOrMatch(config_identity.clone()),
                    "cli",
                    "other",
                    "other-secret",
                    &store,
                )
                .expect_err("endpoint alias must fail"),
                ConfigError::AuthenticatedEndpointAlias { .. }
            ));
        }
        assert!(matches!(
            commit(
                &repo,
                1,
                endpoint("https://one.test", "server-one", "pin-one"),
                Some("storage-one"),
                AuthenticatedConnectionTarget::UseExisting {
                    connection_id: created.connection_id().clone(),
                    expected: stored_binding(
                        "https://wrong.test",
                        Some("server-one"),
                        Some("pin-one"),
                        Some("storage-one"),
                    ),
                },
                IdentityCommit::InitializeOrMatch(config_identity),
                "cli",
                "other",
                "other-secret",
                &store,
            )
            .expect_err("stale stored binding must fail"),
            ConfigError::AuthenticatedBindingConflict { .. }
        ));
        assert_eq!(store.calls(), calls);
        assert_eq!(
            fs::read(repo.paths().config()).expect("unchanged primary"),
            before
        );
    }

    #[test]
    fn authenticated_known_host_identity_and_storage_are_exact_cas() {
        let temp = TempDir::new().expect("tempdir");
        fs::write(
            temp.path().join(LEGACY_KNOWN_HOSTS_FILENAME),
            r#"{"https://KNOWN.test:443/":"pin-one"}"#,
        )
        .expect("known hosts");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let base_identity = identity("identity");
        let created = commit(
            &repo,
            0,
            endpoint("https://known.test", "server-one", "pin-one"),
            Some("storage-one"),
            AuthenticatedConnectionTarget::Create {
                connection_name: "known".to_string(),
            },
            IdentityCommit::InitializeOrMatch(base_identity.clone()),
            "desktop",
            "first",
            "first-secret",
            &store,
        )
        .expect("matching retained pin is consumed");
        assert!(created.snapshot().config().legacy_known_hosts.is_empty());
        let connection_id = created.connection_id().clone();
        commit(
            &repo,
            1,
            endpoint("https://known.test", "server-one", "pin-two"),
            Some("storage-one"),
            AuthenticatedConnectionTarget::ReplaceFingerprint {
                connection_id: connection_id.clone(),
                expected: stored_binding(
                    "https://known.test",
                    Some("server-one"),
                    Some("pin-one"),
                    Some("storage-one"),
                ),
            },
            IdentityCommit::InitializeOrMatch(base_identity.clone()),
            "desktop",
            "second",
            "second-secret",
            &store,
        )
        .expect("consumed legacy pin does not block explicit replacement");

        let mut enriched = base_identity.clone();
        enriched.email = Some("user@example.test".to_string());
        enriched.salt_fingerprint = Some("salt-fingerprint".to_string());
        commit(
            &repo,
            2,
            endpoint("https://known.test", "server-one", "pin-two"),
            Some("storage-one"),
            AuthenticatedConnectionTarget::UseExisting {
                connection_id: connection_id.clone(),
                expected: stored_binding(
                    "https://known.test",
                    Some("server-one"),
                    Some("pin-two"),
                    Some("storage-one"),
                ),
            },
            IdentityCommit::InitializeOrMatch(enriched.clone()),
            "desktop",
            "third",
            "third-secret",
            &store,
        )
        .expect("optional missing identity fields may enrich");
        let calls = store.calls();
        let mut conflict = enriched.clone();
        conflict.email = Some("other@example.test".to_string());
        assert!(matches!(
            commit(
                &repo,
                3,
                endpoint("https://known.test", "server-one", "pin-two"),
                Some("storage-one"),
                AuthenticatedConnectionTarget::UseExisting {
                    connection_id: connection_id.clone(),
                    expected: stored_binding(
                        "https://known.test",
                        Some("server-one"),
                        Some("pin-two"),
                        Some("storage-one"),
                    ),
                },
                IdentityCommit::InitializeOrMatch(conflict),
                "desktop",
                "conflict",
                "conflict-secret",
                &store,
            )
            .expect_err("identity Some/Some mismatch"),
            ConfigError::AuthenticatedIdentityConflict { .. }
        ));
        assert_eq!(store.calls(), calls);

        let replacement = identity("replacement");
        commit(
            &repo,
            3,
            endpoint("https://known.test", "server-one", "pin-two"),
            Some("storage-one"),
            AuthenticatedConnectionTarget::UseExisting {
                connection_id: connection_id.clone(),
                expected: stored_binding(
                    "https://known.test",
                    Some("server-one"),
                    Some("pin-two"),
                    Some("storage-one"),
                ),
            },
            IdentityCommit::ReplaceExact {
                expected: enriched,
                replacement: replacement.clone(),
            },
            "desktop",
            "replacement",
            "replacement-secret",
            &store,
        )
        .expect("explicit exact identity replacement");
        assert_eq!(
            repo.snapshot().expect("snapshot").config().identity,
            Some(replacement.clone())
        );

        let other_id = ConnectionId::deterministic("other", "https://other.test");
        repo.upsert_connection(
            other_id.clone(),
            ConnectionMetadata::new("other", "https://other.test"),
        )
        .expect("insert second connection");
        let calls = store.calls();
        assert!(matches!(
            commit(
                &repo,
                5,
                endpoint("https://other.test", "server-two", "pin-other"),
                Some("storage-one"),
                AuthenticatedConnectionTarget::PinExisting {
                    connection_id: other_id,
                    expected: stored_binding("https://other.test", None, None, None),
                },
                IdentityCommit::InitializeOrMatch(replacement),
                "desktop",
                "other",
                "other-secret",
                &store,
            )
            .expect_err("storage id may not be reused"),
            ConfigError::StorageBindingConflict { .. }
        ));
        assert_eq!(store.calls(), calls);
    }

    #[test]
    fn candidate_marker_without_credential_journal_recovers_by_revoking_only_source_ids() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = ConnectionId::deterministic("intent", "https://intent.test");
        let committed = repo
            .commit_authenticated_session(
                0,
                AuthenticatedSessionCommit::new(
                    endpoint("https://intent.test", "server-intent", "pin-intent"),
                    Some("storage-intent".to_string()),
                    AuthenticatedConnectionTarget::Create {
                        connection_name: "intent".to_string(),
                    },
                    IdentityCommit::InitializeOrMatch(identity("intent")),
                    client_id("test"),
                    "default",
                    CredentialBundle::new(
                        Some(CredentialSecret::new("old-access").expect("access")),
                        Some(CredentialSecret::new("old-refresh").expect("refresh")),
                        Some(CredentialSecret::new("service-secret").expect("service")),
                    )
                    .with_access_expires_at(Some("2026-08-16T11:00:00Z".to_string())),
                ),
                &store,
            )
            .expect("seed authenticated profile");
        assert_eq!(committed.connection_id(), &connection_id);
        repo.reconcile_credentials_with_operation_lock(&store)
            .expect("settle seed credential journal");
        let anchor = repo
            .resolve_credential_profile_anchor(&connection_id, "default")
            .expect("source anchor");
        let source_ids: BTreeSet<_> = anchor.credentials().values().cloned().collect();
        let mut permit = repo
            .prepare_auth_operation_intent_with_operation_locks(
                &anchor,
                AuthOperationKind::Refresh,
                "operation-marker-cut",
            )
            .expect("arm intent");
        let candidate_plan = repo
            .install_auth_rotation_candidate_without_credential_journal_for_test(
                &mut permit,
                CredentialSecret::new("new-access").expect("new access"),
                CredentialSecret::new("new-refresh").expect("new refresh"),
                "2026-08-16T13:00:00Z".to_string(),
                &store,
            )
            .expect("install candidate marker only");
        let candidate_ids = candidate_plan.credential_ids.clone();
        assert!(repo.paths().auth_operation_intent().exists());
        assert!(!repo.paths().credential_transaction_journal().exists());
        drop(permit);

        let (recovered, disposition) = repo
            .reconcile_auth_operation_with_operation_locks(&store)
            .expect("restart recovery");
        assert_eq!(disposition, AuthOperationRecoveryDisposition::SourceRevoked);
        let profiles =
            recovered.snapshot().config().connections[&connection_id].credential_profiles();
        assert!(
            profiles.get("default").is_none(),
            "profiles after recovery: {:?}",
            profiles.keys().collect::<Vec<_>>()
        );
        assert!(!repo.paths().auth_operation_intent().exists());
        // The normal credential journal may remain as the durable authority
        // for source ids still referenced by the backup generation.
        assert!(repo.paths().credential_transaction_journal().exists());
        assert!(matches!(
            repo.restore_backup(),
            Err(ConfigError::CredentialRecoveryRequired { .. })
        ));
        let deleted: BTreeSet<_> = store.deleted_ids().into_iter().collect();
        assert!(deleted.is_subset(&source_ids));
        assert!(candidate_ids
            .values()
            .all(|candidate| !deleted.contains(candidate)));
    }

    fn seed_auth_intent_profile(
        repo: &ConfigRepository,
        store: &TestCredentialStore,
    ) -> ConnectionId {
        let connection_id = ConnectionId::deterministic("intent", "https://intent.test");
        repo.commit_authenticated_session(
            0,
            AuthenticatedSessionCommit::new(
                endpoint("https://intent.test", "server-intent", "pin-intent"),
                Some("storage-intent".to_string()),
                AuthenticatedConnectionTarget::Create {
                    connection_name: "intent".to_string(),
                },
                IdentityCommit::InitializeOrMatch(identity("intent")),
                client_id("test"),
                "default",
                CredentialBundle::new(
                    Some(CredentialSecret::new("old-access").expect("access")),
                    Some(CredentialSecret::new("old-refresh").expect("refresh")),
                    Some(CredentialSecret::new("service-secret").expect("service")),
                )
                .with_access_expires_at(Some("2026-08-16T11:00:00Z".to_string())),
            ),
            store,
        )
        .expect("seed authenticated profile");
        connection_id
    }

    #[test]
    fn authorized_generation_proves_the_temporary_single_target_topology() {
        let profile_temp = TempDir::new().expect("profile tempdir");
        let profile_repo = repository(&profile_temp);
        initialize(&profile_repo);
        let profile_store = TestCredentialStore::default();
        let profile_connection = seed_auth_intent_profile(&profile_repo, &profile_store);
        let exact_anchor = profile_repo
            .resolve_credential_profile_anchor(&profile_connection, "default")
            .expect("exact topology anchor");
        let exact = profile_repo
            .authorized_target_generation_from_anchor(&exact_anchor)
            .expect("exact topology generation");
        assert!(exact.single_target_topology());

        let revision = profile_repo
            .snapshot()
            .expect("profile snapshot")
            .revision();
        profile_repo
            .replace_credential_bundle(
                revision,
                &profile_connection,
                "secondary",
                bundle("secondary-secret"),
                CredentialActivation::Preserve,
                &profile_store,
            )
            .expect("add second profile");
        let multi_profile_anchor = profile_repo
            .resolve_credential_profile_anchor(&profile_connection, "default")
            .expect("multi-profile anchor");
        let multi_profile = profile_repo
            .authorized_target_generation_from_anchor(&multi_profile_anchor)
            .expect("multi-profile generation");
        assert!(!multi_profile.single_target_topology());
        assert_ne!(
            exact.stable_target_fingerprint(),
            multi_profile.stable_target_fingerprint(),
            "the stable proof must bind the topology decision"
        );

        let connection_temp = TempDir::new().expect("connection tempdir");
        let connection_repo = repository(&connection_temp);
        initialize(&connection_repo);
        let connection_store = TestCredentialStore::default();
        let selected_connection = seed_auth_intent_profile(&connection_repo, &connection_store);
        let selected_anchor = connection_repo
            .resolve_credential_profile_anchor(&selected_connection, "default")
            .expect("selected anchor");
        let selected = connection_repo
            .authorized_target_generation_from_anchor(&selected_anchor)
            .expect("selected exact generation");
        assert!(selected.single_target_topology());

        let other = ConnectionId::deterministic("other", "https://other-topology.test");
        connection_repo
            .upsert_connection(
                other,
                ConnectionMetadata::new("Other", "https://other-topology.test"),
            )
            .expect("add second connection");
        let multi_connection_anchor = connection_repo
            .resolve_credential_profile_anchor(&selected_connection, "default")
            .expect("multi-connection anchor");
        let multi_connection = connection_repo
            .authorized_target_generation_from_anchor(&multi_connection_anchor)
            .expect("multi-connection generation");
        assert!(!multi_connection.single_target_topology());
        assert_ne!(
            selected.stable_target_fingerprint(),
            multi_connection.stable_target_fingerprint(),
            "adding a connection must change the stable topology proof"
        );
    }

    #[cfg(feature = "session")]
    #[tokio::test(flavor = "current_thread")]
    async fn sync_generation_rejects_same_revision_raw_rewrite() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = seed_auth_intent_profile(&repo, &store);
        let anchor = repo
            .resolve_credential_profile_anchor(&connection_id, "default")
            .expect("source anchor");
        let generation = repo
            .authorized_target_generation_from_anchor(&anchor)
            .expect("authorized generation");

        let mut raw = fs::read(repo.paths().config()).expect("read raw config");
        raw.push(b'\n');
        fs::write(repo.paths().config(), raw).expect("rewrite same revision with new bytes");

        assert!(matches!(
            repo.acquire_sync_commit_lease(&generation).await,
            Err(ConfigError::ConfigContentConflict { revision })
                if revision == anchor.source_revision()
        ));
    }

    #[cfg(feature = "session")]
    #[tokio::test(flavor = "current_thread")]
    async fn sync_lease_releases_config_but_blocks_config_writer_at_shared_gate() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = seed_auth_intent_profile(&repo, &store);
        let anchor = repo
            .resolve_credential_profile_anchor(&connection_id, "default")
            .expect("source anchor");
        let generation = repo
            .authorized_target_generation_from_anchor(&anchor)
            .expect("authorized generation");
        let lease = repo
            .acquire_sync_commit_lease(&generation)
            .await
            .expect("exact sync lease");

        let config = LockKind::Config
            .pending_at(repo.paths().root())
            .expect("open config lock while lease is held")
            .acquire_blocking(Duration::from_millis(100))
            .expect("lease releases config after exact validation");
        drop(config);

        let error = repo
            .snapshot()
            .expect_err("config repository writer/read must enter through shared sync gate");
        assert!(matches!(
            error,
            ConfigError::Busy { path, .. } if path == repo.paths().sync_commit_lock()
        ));
        drop(lease);
        repo.snapshot().expect("writer proceeds after lease drop");
    }

    #[cfg(feature = "session")]
    #[tokio::test(flavor = "current_thread")]
    async fn sync_lease_is_repository_bound_and_refuses_every_recovery_barrier() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = seed_auth_intent_profile(&repo, &store);
        let anchor = repo
            .resolve_credential_profile_anchor(&connection_id, "default")
            .expect("source anchor");
        let generation = repo
            .authorized_target_generation_from_anchor(&anchor)
            .expect("authorized generation");

        let other_temp = TempDir::new().expect("other tempdir");
        let other = repository(&other_temp);
        initialize(&other);
        assert!(matches!(
            other.acquire_sync_commit_lease(&generation).await,
            Err(ConfigError::CredentialProfileAnchorRepositoryMismatch)
        ));

        fs::write(repo.paths().auth_operation_intent(), b"{}").expect("arm auth barrier");
        assert!(matches!(
            repo.acquire_sync_commit_lease(&generation).await,
            Err(ConfigError::AuthOperationRecoveryRequired { .. })
        ));
        fs::remove_file(repo.paths().auth_operation_intent()).expect("clear auth barrier");

        fs::write(repo.paths().credential_transaction_journal(), b"{}")
            .expect("arm credential barrier");
        assert!(repo.acquire_sync_commit_lease(&generation).await.is_err());
        fs::remove_file(repo.paths().credential_transaction_journal())
            .expect("clear credential barrier");

        fs::write(repo.paths().restore_journal(), b"{}").expect("arm restore barrier");
        assert!(matches!(
            repo.acquire_sync_commit_lease(&generation).await,
            Err(ConfigError::RestoreJournalConflict { .. })
        ));
    }

    #[test]
    fn committed_candidate_restart_preserves_rotation_and_service_slot() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = seed_auth_intent_profile(&repo, &store);
        let anchor = repo
            .resolve_credential_profile_anchor(&connection_id, "default")
            .expect("source anchor");
        let service_id = anchor.credentials()[&CredentialKind::ServiceAccount].clone();
        let mut permit = repo
            .prepare_auth_operation_intent_with_operation_locks(
                &anchor,
                AuthOperationKind::Refresh,
                "operation-committed-cut",
            )
            .expect("arm intent");
        let plan = repo
            .install_auth_rotation_candidate_without_credential_journal_for_test(
                &mut permit,
                CredentialSecret::new("new-access").expect("new access"),
                CredentialSecret::new("new-refresh").expect("new refresh"),
                "2026-08-16T13:00:00Z".to_string(),
                &store,
            )
            .expect("candidate marker");
        let expected_revision = plan.journal.source_primary.revision;
        let bundle = CredentialBundle::new(
            Some(CredentialSecret::new("new-access").expect("new access")),
            Some(CredentialSecret::new("new-refresh").expect("new refresh")),
            None,
        )
        .with_access_expires_at(Some("2026-08-16T13:00:00Z".to_string()));
        {
            let _lock = repo.exclusive_lock().expect("config lock");
            repo.install_credential_transaction_intent_locked(expected_revision, &plan)
                .expect("install credential journal");
        }
        repo.execute_installed_credential_transaction_plan(
            expected_revision,
            Some(&bundle),
            plan,
            &store,
        )
        .expect("publish candidate without clearing auth intent");
        assert!(repo.paths().auth_operation_intent().exists());
        drop(permit);

        let (_outcome, disposition) = repo
            .reconcile_auth_operation_with_operation_locks(&store)
            .expect("restart candidate recovery");
        assert_eq!(
            disposition,
            AuthOperationRecoveryDisposition::CandidatePreserved
        );
        let current = repo
            .resolve_credential_profile_anchor(&connection_id, "default")
            .expect("candidate anchor");
        assert_eq!(
            current.credentials()[&CredentialKind::ServiceAccount],
            service_id
        );
        assert_eq!(current.access_expires_at(), Some("2026-08-16T13:00:00Z"));
        assert!(!repo.paths().auth_operation_intent().exists());
    }

    #[test]
    fn removed_target_restart_accepts_revoke_and_clears_auth_intent() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = seed_auth_intent_profile(&repo, &store);
        let anchor = repo
            .resolve_credential_profile_anchor(&connection_id, "default")
            .expect("source anchor");
        let permit = repo
            .prepare_auth_operation_intent_with_operation_locks(
                &anchor,
                AuthOperationKind::Logout,
                "operation-removed-cut",
            )
            .expect("arm logout intent");
        repo.remove_credential_profile_if_matches_with_operation_lock(
            &anchor,
            ActiveCredentialAfterRemoval::Clear,
            &store,
        )
        .expect("publish revoke without clearing auth intent");
        assert!(repo.paths().auth_operation_intent().exists());
        drop(permit);

        let (_outcome, disposition) = repo
            .reconcile_auth_operation_with_operation_locks(&store)
            .expect("restart removed-target recovery");
        assert_eq!(disposition, AuthOperationRecoveryDisposition::TargetRemoved);
        assert!(!repo.paths().auth_operation_intent().exists());
        assert!(matches!(
            repo.restore_backup(),
            Err(ConfigError::CredentialRecoveryRequired { .. })
        ));
    }

    fn password_login_identity() -> ConfigIdentity {
        let mut value = identity("intent");
        value.email = Some("person@example.test".to_string());
        value
    }

    #[test]
    fn armed_password_login_with_absent_profile_abandons_without_credential_deletes() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = seed_auth_intent_profile(&repo, &store);
        repo.reconcile_credentials_with_operation_lock(&store)
            .expect("settle seed journal");
        let anchor = repo
            .resolve_password_login_anchor(&connection_id, "password", &client_id("test"))
            .expect("absent-profile login anchor");
        let permit = repo
            .prepare_password_login_intent_with_operation_locks(
                &anchor,
                &endpoint("https://intent.test", "server-intent", "pin-intent"),
                password_login_identity(),
                "operation-password-armed",
                &store,
            )
            .expect("arm password login");
        let calls_after_arm = store.calls();
        let deleted_before = store.deleted_ids();
        drop(permit);

        let (outcome, disposition) = repo
            .reconcile_auth_operation_with_operation_locks(&store)
            .expect("restart abandons armed login");
        assert_eq!(
            disposition,
            AuthOperationRecoveryDisposition::LoginAbandoned
        );
        assert_eq!(store.calls(), calls_after_arm);
        assert_eq!(store.deleted_ids(), deleted_before);
        assert!(!repo.paths().auth_operation_intent().exists());
        assert!(outcome.snapshot().config().connections[&connection_id]
            .credential_profiles()
            .get("password")
            .is_none());
    }

    #[test]
    fn absent_password_login_target_in_descendant_clears_without_credential_io() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = seed_auth_intent_profile(&repo, &store);
        repo.reconcile_credentials_with_operation_lock(&store)
            .expect("settle seed journal");
        let anchor = repo
            .resolve_password_login_anchor(&connection_id, "password", &client_id("test"))
            .expect("absent-profile login anchor");
        let permit = repo
            .prepare_password_login_intent_with_operation_locks(
                &anchor,
                &endpoint("https://intent.test", "server-intent", "pin-intent"),
                password_login_identity(),
                "operation-password-removed",
                &store,
            )
            .expect("arm password login");
        let calls_after_arm = store.calls();
        let deleted_before = store.deleted_ids();

        // Simulate a separately durable, later config generation in which the login target is
        // still absent. Recovery may accept that absence, but must never infer ownership of the
        // reserved IDs from the auth intent alone.
        let mut descendant = repo.snapshot().expect("source snapshot").config().clone();
        descendant.revision = descendant
            .revision
            .checked_add(1)
            .expect("revision advance");
        descendant.legacy_known_hosts.insert(
            "https://descendant.test".to_string(),
            "descendant-pin".to_string(),
        );
        atomic_write(
            &repo.paths().config(),
            &serialize_config(&descendant).expect("serialize descendant"),
        )
        .expect("publish descendant");
        drop(permit);

        let (_outcome, disposition) = repo
            .reconcile_auth_operation_with_operation_locks(&store)
            .expect("restart accepts absent target");
        assert_eq!(disposition, AuthOperationRecoveryDisposition::TargetRemoved);
        assert_eq!(store.calls(), calls_after_arm);
        assert_eq!(store.deleted_ids(), deleted_before);
        assert!(!repo.paths().auth_operation_intent().exists());
    }

    #[test]
    fn password_login_candidate_marker_without_credential_journal_abandons_source() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = seed_auth_intent_profile(&repo, &store);
        repo.reconcile_credentials_with_operation_lock(&store)
            .expect("settle seed journal");
        let anchor = repo
            .resolve_password_login_anchor(&connection_id, "password", &client_id("test"))
            .expect("absent-profile login anchor");
        let mut permit = repo
            .prepare_password_login_intent_with_operation_locks(
                &anchor,
                &endpoint("https://intent.test", "server-intent", "pin-intent"),
                password_login_identity(),
                "operation-password-marker",
                &store,
            )
            .expect("arm password login");
        let bundle = CredentialBundle::new(
            Some(CredentialSecret::new("new-access").expect("access")),
            Some(CredentialSecret::new("new-refresh").expect("refresh")),
            None,
        )
        .with_access_expires_at(Some("2026-08-16T13:00:00Z".to_string()));
        let plan = repo
            .install_password_login_candidate_without_credential_journal_for_test(
                &mut permit,
                "018f4f08-7f1d-7d57-bd43-bb4b7c520001",
                &bundle,
                &store,
            )
            .expect("candidate marker only");
        let reserved: BTreeSet<_> = plan.credential_ids.values().cloned().collect();
        assert!(!repo.paths().credential_transaction_journal().exists());
        let deletes_before = store.deleted_ids();
        drop(permit);

        let (_outcome, disposition) = repo
            .reconcile_auth_operation_with_operation_locks(&store)
            .expect("restart abandons marker-only login");
        assert_eq!(
            disposition,
            AuthOperationRecoveryDisposition::LoginAbandoned
        );
        let deleted: BTreeSet<_> = store.deleted_ids().into_iter().collect();
        assert_eq!(deleted, deletes_before.into_iter().collect());
        assert!(reserved.iter().all(|id| !deleted.contains(id)));
        assert!(!repo.paths().auth_operation_intent().exists());
    }

    #[test]
    fn committed_password_login_candidate_is_preserved_with_exact_binding_and_service_slot() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = seed_auth_intent_profile(&repo, &store);
        repo.reconcile_credentials_with_operation_lock(&store)
            .expect("settle seed journal");
        let source = repo
            .resolve_credential_profile_anchor(&connection_id, "default")
            .expect("source profile");
        let service_id = source.credentials()[&CredentialKind::ServiceAccount].clone();
        let anchor = repo
            .resolve_password_login_anchor(&connection_id, "default", &client_id("test"))
            .expect("present-profile login anchor");
        let mut permit = repo
            .prepare_password_login_intent_with_operation_locks(
                &anchor,
                &endpoint("https://intent.test", "server-intent", "pin-intent"),
                password_login_identity(),
                "operation-password-committed",
                &store,
            )
            .expect("arm password login");
        let bundle = CredentialBundle::new(
            Some(CredentialSecret::new("new-access").expect("access")),
            Some(CredentialSecret::new("new-refresh").expect("refresh")),
            None,
        )
        .with_access_expires_at(Some("2026-08-16T13:00:00Z".to_string()));
        let plan = repo
            .install_password_login_candidate_without_credential_journal_for_test(
                &mut permit,
                "018f4f08-7f1d-7d57-bd43-bb4b7c520001",
                &bundle,
                &store,
            )
            .expect("candidate marker");
        let expected_revision = plan.journal.source_primary.revision;
        {
            let _lock = repo.exclusive_lock().expect("config lock");
            repo.install_credential_transaction_intent_locked(expected_revision, &plan)
                .expect("install credential journal");
        }
        repo.execute_installed_credential_transaction_plan(
            expected_revision,
            Some(&bundle),
            plan,
            &store,
        )
        .expect("publish candidate while retaining auth intent");
        drop(permit);

        let (_outcome, disposition) = repo
            .reconcile_auth_operation_with_operation_locks(&store)
            .expect("restart preserves candidate");
        assert_eq!(
            disposition,
            AuthOperationRecoveryDisposition::CandidatePreserved
        );
        let candidate_snapshot = repo.snapshot().expect("candidate snapshot");
        let profile = &candidate_snapshot.config().connections[&connection_id]
            .credential_profiles()["default"];
        assert_eq!(
            profile.account_subject(),
            Some("018f4f08-7f1d-7d57-bd43-bb4b7c520001")
        );
        assert_eq!(profile.auth_method(), Some(AuthMethod::Password));
        assert_eq!(
            profile.credentials()[&CredentialKind::ServiceAccount],
            service_id
        );
        assert!(!repo.paths().auth_operation_intent().exists());
    }

    #[test]
    fn password_login_rebases_unrelated_revision_but_rejects_same_revision_aba() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = seed_auth_intent_profile(&repo, &store);
        repo.reconcile_credentials_with_operation_lock(&store)
            .expect("settle seed journal");
        let anchor = repo
            .resolve_password_login_anchor(&connection_id, "password", &client_id("test"))
            .expect("login anchor");
        repo.mutate(None, |config| {
            config.legacy_known_hosts.insert(
                "https://unrelated.test".to_string(),
                "unrelated-pin".to_string(),
            );
            Ok(())
        })
        .expect("unrelated revision advance");
        let permit = repo
            .prepare_password_login_intent_with_operation_locks(
                &anchor,
                &endpoint("https://intent.test", "server-intent", "pin-intent"),
                password_login_identity(),
                "operation-password-rebase",
                &store,
            )
            .expect("unrelated revision rebases");
        drop(permit);
        repo.reconcile_auth_operation_with_operation_locks(&store)
            .expect("clear rebased intent");

        let aba_anchor = repo
            .resolve_password_login_anchor(&connection_id, "password", &client_id("test"))
            .expect("ABA anchor");
        let mut tampered = repo.snapshot().expect("ABA source").config().clone();
        tampered
            .legacy_known_hosts
            .insert("https://aba.test".to_string(), "aba-pin".to_string());
        atomic_write(
            &repo.paths().config(),
            &serialize_config(&tampered).expect("serialize ABA config"),
        )
        .expect("publish same-revision ABA");
        let error = match repo.prepare_password_login_intent_with_operation_locks(
            &aba_anchor,
            &endpoint("https://intent.test", "server-intent", "pin-intent"),
            password_login_identity(),
            "operation-password-aba",
            &store,
        ) {
            Ok(_) => panic!("same-revision content change must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, ConfigError::ConfigContentConflict { .. }));
        assert!(!repo.paths().auth_operation_intent().exists());
    }

    #[test]
    fn published_password_candidate_proof_normalizes_legacy_endpoint_address() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = seed_auth_intent_profile(&repo, &store);
        repo.reconcile_credentials_with_operation_lock(&store)
            .expect("settle seed journal");
        repo.mutate(None, |config| {
            config
                .connections
                .get_mut(&connection_id)
                .expect("connection")
                .metadata
                .address = "https://intent.test/".to_string();
            Ok(())
        })
        .expect("retain legacy noncanonical address");
        let anchor = repo
            .resolve_password_login_anchor(&connection_id, "password", &client_id("test"))
            .expect("normalized login anchor");
        let mut permit = repo
            .prepare_password_login_intent_with_operation_locks(
                &anchor,
                &endpoint("https://intent.test", "server-intent", "pin-intent"),
                password_login_identity(),
                "operation-password-visible-unlink",
                &store,
            )
            .expect("arm login");
        let bundle = CredentialBundle::new(
            Some(CredentialSecret::new("new-access").expect("access")),
            Some(CredentialSecret::new("new-refresh").expect("refresh")),
            None,
        )
        .with_access_expires_at(Some("2026-08-16T13:00:00Z".to_string()));
        let plan = repo
            .install_password_login_candidate_without_credential_journal_for_test(
                &mut permit,
                "018f4f08-7f1d-7d57-bd43-bb4b7c520001",
                &bundle,
                &store,
            )
            .expect("candidate marker");
        let expected_revision = plan.journal.source_primary.revision;
        {
            let _lock = repo.exclusive_lock().expect("config lock");
            repo.install_credential_transaction_intent_locked(expected_revision, &plan)
                .expect("credential journal");
        }
        repo.execute_installed_credential_transaction_plan(
            expected_revision,
            Some(&bundle),
            plan,
            &store,
        )
        .expect("publish candidate");
        fs::remove_file(repo.paths().auth_operation_intent()).expect("simulate visible unlink");
        sync_parent(repo.paths().root()).expect("sync visible unlink");

        assert!(repo
            .password_login_candidate_is_published_with_operation_locks(&permit)
            .expect("candidate proof")
            .is_some());
    }

    fn valid_auth_intent(root: &Path) -> AuthOperationIntent {
        AuthOperationIntent {
            journal_version: AUTH_OPERATION_INTENT_V1,
            operation_id: "operation-parser".to_string(),
            operation: AuthOperationKind::Logout,
            state: AuthOperationIntentState::Armed,
            repository_binding_digest: credential_profile_anchor_repository_binding(root)
                .expect("repository binding"),
            connection_id: ConnectionId::deterministic("intent", "https://intent.test"),
            profile_name: "default".to_string(),
            endpoint: AuthIntentEndpoint {
                address: normalize_address("https://intent.test", "$.test.address")
                    .expect("canonical address"),
                server_id: "server-intent".to_string(),
                server_fingerprint: "pin-intent".to_string(),
                storage_id: Some("storage-intent".to_string()),
            },
            source: AuthIntentSource {
                revision: 7,
                raw_digest: format!("sha256:{}", "a".repeat(64)),
                account_subject: Some("user@example.test".to_string()),
                auth_method: None,
                access_expires_at: Some("2026-08-16T12:00:00Z".to_string()),
                credentials: BTreeMap::from([(
                    CredentialKind::Refresh,
                    CredentialId::from_serialized(format!("cred_{}", "b".repeat(64)))
                        .expect("credential id"),
                )]),
                profile_present: None,
                client_present: None,
                active_profile: None,
                client_active_connection: None,
            },
            candidate_rotation: None,
            client_id: None,
            reserved_login: None,
            candidate_login: None,
        }
    }

    #[test]
    fn credential_anchor_and_auth_intent_protect_stable_profile_binding() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let mut protected_identity = identity("subject");
        protected_identity.email = Some("user@example.test".to_string());
        let committed = repo
            .commit_authenticated_session(
                0,
                AuthenticatedSessionCommit::new(
                    endpoint("https://subject.test", "server-subject", "pin-subject"),
                    Some("storage-subject".to_string()),
                    AuthenticatedConnectionTarget::Create {
                        connection_name: "subject".to_string(),
                    },
                    IdentityCommit::InitializeOrMatch(protected_identity),
                    client_id("test"),
                    "default",
                    CredentialBundle::new(
                        Some(CredentialSecret::new("access").expect("access")),
                        Some(CredentialSecret::new("refresh").expect("refresh")),
                        None,
                    )
                    .with_access_expires_at(Some("2026-08-16T12:00:00Z".to_string())),
                ),
                &store,
            )
            .expect("seed subject-bound session");
        repo.reconcile_credentials_with_operation_lock(&store)
            .expect("settle credential journal");
        let subject = "018f4f08-7f1d-7d57-bd43-bb4b7c520001";
        let mut bound = repo.snapshot().expect("bound snapshot").config().clone();
        let bound_connection = bound
            .connections
            .get_mut(committed.connection_id())
            .expect("bound connection");
        bound_connection.metadata.expected_master_key_fp = Some("0123456789ab".to_string());
        let bound_profile = bound_connection
            .credential_profiles
            .get_mut("default")
            .expect("bound profile");
        bound_profile.account_subject = Some(subject.to_string());
        bound_profile.auth_method = Some(AuthMethod::Password);
        bound.revision += 1;
        atomic_write(
            &repo.paths().config(),
            &serialize_config(&bound).expect("serialize bound config"),
        )
        .expect("publish bound config");
        let anchor = repo
            .resolve_credential_profile_anchor(committed.connection_id(), "default")
            .expect("subject-bound anchor");
        assert_eq!(anchor.expected_master_key_fp(), Some("0123456789ab"));
        assert_eq!(anchor.account_subject(), Some(subject));
        assert_eq!(anchor.auth_method(), Some(AuthMethod::Password));

        let permit = repo
            .prepare_auth_operation_intent_with_operation_locks(
                &anchor,
                AuthOperationKind::Refresh,
                "operation-subject",
            )
            .expect("arm subject-bound intent");
        let bytes = fs::read(repo.paths().auth_operation_intent()).expect("read auth intent");
        let intent = parse_auth_operation_intent(&repo.paths().auth_operation_intent(), &bytes)
            .expect("parse auth intent");
        assert_eq!(intent.source.account_subject.as_deref(), Some(subject));
        {
            let _lock = repo
                .exclusive_lock_allow_credential_journal()
                .expect("config lock");
            repo.ensure_owned_auth_operation_intent_locked(&permit)
                .expect("auth permit reconstructs without changing the v1/v2 wire document");
        }
        drop(permit);

        let mut changed = repo.snapshot().expect("snapshot").config().clone();
        changed.revision = anchor.source_revision + 1;
        changed
            .connections
            .get_mut(committed.connection_id())
            .expect("changed connection")
            .credential_profiles
            .get_mut("default")
            .expect("changed profile")
            .account_subject = Some("018f4f08-7f1d-7d57-bd43-bb4b7c520002".to_string());
        let error = ensure_credential_profile_anchor_matches(
            &anchor,
            &anchor.repository_binding_digest,
            &changed,
            &anchor.source_digest,
        )
        .expect_err("subject change invalidates the anchor");
        assert!(matches!(
            error,
            ConfigError::CredentialProfileAnchorConflict {
                field: "account_subject",
                ..
            }
        ));
    }

    #[test]
    fn credential_profile_account_binding_is_an_exact_canonical_pair() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = seed_auth_intent_profile(&repo, &store);
        let source = repo.snapshot().expect("source snapshot").config().clone();

        let mutate_profile =
            |config: &mut ConfigV2, subject: Option<&str>, method: Option<AuthMethod>| {
                let profile = config
                    .connections
                    .get_mut(&connection_id)
                    .expect("connection")
                    .credential_profiles
                    .get_mut("default")
                    .expect("profile");
                profile.account_subject = subject.map(str::to_string);
                profile.auth_method = method;
            };

        let mut subject_only = source.clone();
        mutate_profile(
            &mut subject_only,
            Some("018f4f08-7f1d-7d57-bd43-bb4b7c520001"),
            None,
        );
        assert!(matches!(
            serialize_config(&subject_only),
            Err(ConfigError::InvalidConfig { .. })
        ));

        let mut method_only = source.clone();
        mutate_profile(&mut method_only, None, Some(AuthMethod::Password));
        assert!(matches!(
            serialize_config(&method_only),
            Err(ConfigError::InvalidConfig { .. })
        ));

        let mut noncanonical = source.clone();
        mutate_profile(
            &mut noncanonical,
            Some("018F4F08-7F1D-7D57-BD43-BB4B7C520001"),
            Some(AuthMethod::Password),
        );
        assert!(matches!(
            serialize_config(&noncanonical),
            Err(ConfigError::InvalidConfig { .. })
        ));

        let mut canonical = source;
        mutate_profile(
            &mut canonical,
            Some("018f4f08-7f1d-7d57-bd43-bb4b7c520001"),
            Some(AuthMethod::Password),
        );
        serialize_config(&canonical).expect("canonical binding pair");
    }

    #[test]
    fn auth_intent_without_account_subject_remains_source_compatible() {
        let temp = TempDir::new().expect("tempdir");
        let intent = valid_auth_intent(temp.path());
        let bytes = serialize_auth_operation_intent(&intent, temp.path()).expect("serialize");
        let encoded = String::from_utf8(bytes).expect("intent JSON is UTF-8");
        let legacy_bytes = encoded
            .lines()
            .filter(|line| !line.contains("\"account_subject\""))
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        let parsed = parse_auth_operation_intent(
            &temp.path().join(AUTH_OPERATION_INTENT_FILENAME),
            &legacy_bytes,
        )
        .expect("pre-binding v1 intent remains readable");
        assert!(parsed.source.account_subject.is_none());
    }

    #[test]
    fn auth_intent_parser_is_bounded_duplicate_free_future_strict_and_root_bound() {
        let first = TempDir::new().expect("first tempdir");
        let second = TempDir::new().expect("second tempdir");
        let intent = valid_auth_intent(first.path());
        let bytes = serialize_auth_operation_intent(&intent, first.path()).expect("serialize");
        let encoded = String::from_utf8(bytes.clone()).expect("intent json is utf8");
        parse_auth_operation_intent(&first.path().join(AUTH_OPERATION_INTENT_FILENAME), &bytes)
            .expect("parse valid intent");

        let duplicate = encoded
            .clone()
            .replacen(
                "\"journal_version\": 1,",
                "\"journal_version\": 1,\n  \"journal_version\": 1,",
                1,
            )
            .into_bytes();
        assert!(matches!(
            parse_auth_operation_intent(
                &first.path().join(AUTH_OPERATION_INTENT_FILENAME),
                &duplicate,
            ),
            Err(ConfigError::MalformedAuthOperationIntent { .. })
        ));

        let future = encoded
            .replacen("\"journal_version\": 1", "\"journal_version\": 3", 1)
            .into_bytes();
        assert!(matches!(
            parse_auth_operation_intent(
                &first.path().join(AUTH_OPERATION_INTENT_FILENAME),
                &future,
            ),
            Err(ConfigError::FutureAuthOperationIntent { .. })
        ));

        let unknown = encoded
            .replacen('{', "{\n  \"unexpected\": true,", 1)
            .into_bytes();
        assert!(matches!(
            parse_auth_operation_intent(
                &first.path().join(AUTH_OPERATION_INTENT_FILENAME),
                &unknown,
            ),
            Err(ConfigError::MalformedAuthOperationIntent { .. })
        ));

        let excessive_nodes = encoded
            .replacen(
                '{',
                &format!("{{\n  \"unexpected\": [{}],", vec!["null"; 256].join(",")),
                1,
            )
            .into_bytes();
        assert!(matches!(
            parse_auth_operation_intent(
                &first.path().join(AUTH_OPERATION_INTENT_FILENAME),
                &excessive_nodes,
            ),
            Err(ConfigError::MalformedAuthOperationIntent { .. })
        ));

        assert!(matches!(
            parse_auth_operation_intent(
                &second.path().join(AUTH_OPERATION_INTENT_FILENAME),
                &bytes,
            ),
            Err(ConfigError::AuthOperationIntentRepositoryMismatch)
        ));

        let oversized_path = first.path().join(AUTH_OPERATION_INTENT_FILENAME);
        fs::write(
            &oversized_path,
            vec![b' '; AUTH_OPERATION_INTENT_MAX_BYTES as usize + 1],
        )
        .expect("oversized intent");
        assert!(matches!(
            read_file(&oversized_path, "read oversized auth intent"),
            Err(ConfigError::ConfigTooLarge { max_bytes, .. })
                if max_bytes == AUTH_OPERATION_INTENT_MAX_BYTES
        ));
    }

    #[test]
    fn invalid_auth_intent_preflight_blocks_pending_credential_cleanup_port_calls() {
        let temp = TempDir::new().expect("tempdir");
        let repo = repository(&temp);
        initialize(&repo);
        let store = TestCredentialStore::default();
        let connection_id = seed_auth_intent_profile(&repo, &store);
        let anchor = repo
            .resolve_credential_profile_anchor(&connection_id, "default")
            .expect("source anchor");
        repo.remove_credential_profile_if_matches_with_operation_lock(
            &anchor,
            ActiveCredentialAfterRemoval::Clear,
            &store,
        )
        .expect("publish source revoke");
        repo.upsert_connection(
            ConnectionId::deterministic("other", "https://other.intent.test"),
            ConnectionMetadata::new("other", "https://other.intent.test"),
        )
        .expect("rotate backup beyond removed source");
        store.set_fail_deletes(true);
        repo.reconcile_credentials_with_operation_lock(&store)
            .expect("leave failed cleanup journal");
        store.set_fail_deletes(false);
        assert!(repo.paths().credential_transaction_journal().exists());

        let other = TempDir::new().expect("other root");
        let cross_root =
            serialize_auth_operation_intent(&valid_auth_intent(other.path()), other.path())
                .expect("cross-root intent");
        let cases = [
            b"{broken".to_vec(),
            br#"{"journal_version":2}"#.to_vec(),
            cross_root,
        ];
        for bytes in cases {
            fs::write(repo.paths().auth_operation_intent(), bytes)
                .expect("write invalid auth intent");
            let calls = store.calls();
            assert!(repo
                .reconcile_auth_operation_with_operation_locks(&store)
                .is_err());
            assert_eq!(store.calls(), calls, "invalid auth intent touched store");
            assert!(repo.paths().auth_operation_intent().exists());
            assert!(repo.paths().credential_transaction_journal().exists());
        }
    }
}
