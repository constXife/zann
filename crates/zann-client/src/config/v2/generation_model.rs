use super::*;

#[derive(Clone, Debug)]
pub struct ConfigSnapshot {
    pub(super) config: ConfigV2,
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
    pub(super) repository_fingerprint: [u8; 32],
    pub(super) anchor_fingerprint: [u8; 32],
    pub(super) stable_target_fingerprint: [u8; 32],
    pub(super) revision_be: [u8; 8],
    pub(super) content_fingerprint: [u8; 32],
    pub(super) repository_binding_digest: String,
    pub(super) source_digest: String,
    pub(super) connection_id: ConnectionId,
    pub(super) profile_name: String,
    pub(super) display_name: String,
    pub(super) normalized_address: String,
    pub(super) server_id: Option<String>,
    pub(super) server_fingerprint: Option<String>,
    pub(super) storage_id: Option<String>,
    pub(super) expected_master_key_fp: Option<String>,
    pub(super) account_subject: Option<String>,
    pub(super) auth_method: Option<AuthMethod>,
    pub(super) single_target_topology: bool,
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
    pub(super) generation: Arc<AuthorizedTargetGeneration>,
    pub(super) _sync_commit: FileLockGuard,
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

pub(super) struct GenerationFingerprint(pub(super) Sha256);

impl GenerationFingerprint {
    pub(super) fn new(domain: &'static [u8]) -> Self {
        let mut fingerprint = Self(Sha256::new());
        fingerprint.part(b"domain", domain);
        fingerprint
    }

    pub(super) fn part(&mut self, label: &'static [u8], value: &[u8]) {
        for part in [label, value] {
            self.0.update(
                u64::try_from(part.len())
                    .expect("generation fingerprint input length fits u64")
                    .to_be_bytes(),
            );
            self.0.update(part);
        }
    }

    pub(super) fn optional_part(&mut self, label: &'static [u8], value: Option<&str>) {
        match value {
            Some(value) => {
                self.part(label, b"present");
                self.part(b"value", value.as_bytes());
            }
            None => self.part(label, b"absent"),
        }
    }

    pub(super) fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

pub(super) fn authorized_target_generation(
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
