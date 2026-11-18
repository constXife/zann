//! Durable recovery intent foundation. Only the canonical auth flow may consume
//! these crate-private operations; no unverified endpoint or network API exists.
use super::*;
use uuid::Uuid;
use zann_core::recovery::{RecoveryStatus, MAX_CLIENT_RECOVERY_OPERATIONS};
use zann_crypto::recovery::RecoverySecrets;

mod io;
mod repository;
#[cfg(test)]
mod tests;

pub(crate) struct RecoveryPreparation {
    operation_id: Uuid,
    target: RecoveryTarget,
    secrets: RecoverySecrets,
    confirmed: bool,
}
impl RecoveryPreparation {
    pub(crate) fn new(
        endpoint: &VerifiedEndpointBinding,
        locator: String,
    ) -> Result<Self, ConfigError> {
        let target = RecoveryTarget::new(endpoint, locator)?;
        Ok(Self {
            operation_id: Uuid::new_v4(),
            target,
            secrets: RecoverySecrets::generate(),
            confirmed: false,
        })
    }
    pub(crate) fn matches(&self, endpoint: &VerifiedEndpointBinding) -> bool {
        self.target.matches(endpoint)
    }
    pub(crate) fn operation_id(&self) -> Uuid {
        self.operation_id
    }
    pub(crate) fn next_recovery_key(&self) -> &str {
        self.secrets.next_recovery_key()
    }
    pub(crate) fn confirm_saved(&mut self, code: &str) -> Result<(), ConfigError> {
        if !self.secrets.confirms_code(code) {
            return Err(conflict("successor confirmation mismatch"));
        }
        self.confirmed = true;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryTarget {
    address: String,
    server_id: String,
    fingerprint: String,
    locator: String,
}
impl RecoveryTarget {
    fn new(endpoint: &VerifiedEndpointBinding, locator: String) -> Result<Self, ConfigError> {
        let target = Self {
            address: endpoint.address().to_owned(),
            server_id: endpoint.server_id().to_owned(),
            fingerprint: endpoint.server_fingerprint().to_owned(),
            locator,
        };
        target.validate()?;
        Ok(target)
    }
    fn validate(&self) -> Result<(), ConfigError> {
        if self.locator.is_empty()
            || self.locator.len() > 320
            || self.locator.chars().any(char::is_control)
            || normalize_address(&self.address, "$.recovery.target.address")? != self.address
        {
            return Err(conflict("invalid recovery target"));
        }
        validate_required_metadata("$.recovery.target.server_id", &self.server_id)?;
        validate_required_metadata("$.recovery.target.fingerprint", &self.fingerprint)
    }
    fn matches(&self, endpoint: &VerifiedEndpointBinding) -> bool {
        self.address == endpoint.address()
            && self.server_id == endpoint.server_id()
            && self.fingerprint == endpoint.server_fingerprint()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecoveryIntentPhase {
    Prepared,
    Dispatched,
    Consumed,
    Completed,
    Stopped,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryIntent {
    pub(crate) operation_id: Uuid,
    target: RecoveryTarget,
    credential_id: CredentialId,
    bundle_digest: String,
    pub(crate) phase: RecoveryIntentPhase,
    consume_digest: Option<String>,
    consume_device: Option<zann_core::api::account_access::DeviceDescriptor>,
    pub(crate) status: Option<RecoveryStatus>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryIntents {
    journal_version: u32,
    operations: BTreeMap<Uuid, RecoveryIntent>,
}
fn conflict(reason: &'static str) -> ConfigError {
    ConfigError::RecoveryIntentConflict { reason }
}
fn store_error(source: CredentialPortError) -> ConfigError {
    ConfigError::RecoveryCredential { source }
}
fn credential_id(
    root: &Path,
    id: Uuid,
    target: &RecoveryTarget,
) -> Result<CredentialId, ConfigError> {
    operation_credential(
        root,
        id,
        b"recovery-credential-v1",
        &[
            target.address.as_bytes(),
            target.server_id.as_bytes(),
            target.fingerprint.as_bytes(),
            target.locator.as_bytes(),
        ],
    )
}

impl RecoveryIntent {
    pub(crate) fn locator(&self) -> &str {
        &self.target.locator
    }
    pub(crate) fn matches(&self, endpoint: &VerifiedEndpointBinding) -> bool {
        self.target.matches(endpoint)
    }
}
