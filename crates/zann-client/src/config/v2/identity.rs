use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientPaths {
    pub(super) root: PathBuf,
    pub(super) local_db: PathBuf,
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
        pub struct $name(pub(super) String);

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

pub(super) fn valid_client_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub(super) fn valid_generated_id(value: &str, prefix: &str) -> bool {
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
pub struct CredentialId(pub(super) String);

impl CredentialId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn from_serialized(value: String) -> Result<Self, ConfigError> {
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
    pub(super) fn deterministic(
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

    pub(super) fn fresh(
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

    pub(super) fn lifecycle_nonce_and_tag(&self) -> Option<(&str, &str)> {
        let suffix = self.0.strip_prefix(LIFECYCLE_CREDENTIAL_ID_PREFIX)?;
        let (nonce, tag) = suffix.split_at(LIFECYCLE_NONCE_HEX_LEN);
        Some((nonce, tag))
    }

    pub(super) fn is_bound_lifecycle(
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

pub(super) fn lifecycle_credential_tag(
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

pub(super) fn stable_hash(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    HEXLOWER.encode(&hasher.finalize())
}

pub(super) fn repository_binding(root: &Path) -> Result<Vec<u8>, ConfigError> {
    let canonical = fs::canonicalize(root).map_err(|source| ConfigError::Io {
        operation: "canonicalize config root",
        path: root.to_path_buf(),
        source,
    })?;
    Ok(repository_path_bytes(&canonical))
}

pub(super) fn credential_profile_anchor_repository_binding(
    root: &Path,
) -> Result<String, ConfigError> {
    let repository_binding = repository_binding(root)?;
    Ok(stable_hash(&[
        b"credential-profile-anchor-repository-v1",
        &repository_binding,
    ]))
}

#[cfg(unix)]
pub(super) fn repository_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
pub(super) fn repository_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(not(any(unix, windows)))]
pub(super) fn repository_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().to_string_lossy().into_owned().into_bytes()
}

pub(super) fn byte_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", HEXLOWER.encode(&hasher.finalize()))
}
