use super::*;

pub struct CredentialSecret(pub(super) Zeroizing<String>);

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
    pub(super) access: Option<CredentialSecret>,
    pub(super) refresh: Option<CredentialSecret>,
    pub(super) service_account: Option<CredentialSecret>,
    pub(super) access_expires_at: Option<String>,
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

    pub(super) fn slots(&self) -> [(CredentialKind, Option<&CredentialSecret>); 3] {
        [
            (CredentialKind::Access, self.access.as_ref()),
            (CredentialKind::Refresh, self.refresh.as_ref()),
            (
                CredentialKind::ServiceAccount,
                self.service_account.as_ref(),
            ),
        ]
    }

    pub(super) fn secret(&self, kind: CredentialKind) -> Option<&CredentialSecret> {
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
    pub(super) address: String,
    pub(super) server_id: String,
    pub(super) server_fingerprint: String,
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
    pub(super) address: String,
    pub(super) server_id: Option<String>,
    pub(super) server_fingerprint: Option<String>,
    pub(super) storage_id: Option<String>,
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

    pub(super) fn from_metadata(metadata: &ConnectionMetadata) -> Self {
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
    pub(super) endpoint: VerifiedEndpointBinding,
    pub(super) storage_id: Option<String>,
    pub(super) target: AuthenticatedConnectionTarget,
    pub(super) identity: IdentityCommit,
    pub(super) client_id: ClientId,
    pub(super) profile_name: String,
    pub(super) bundle: CredentialBundle,
    pub(super) account_binding: Option<(String, AuthMethod)>,
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
