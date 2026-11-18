//! Restricted consume/resume protocol; never ordinary session tokens.
use super::*;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryConsume {
    pub operation_id: Uuid,
    pub locator: String,
    pub recovery_key: String,
    pub next_recovery_key: String,
    pub device: DeviceDescriptor,
}
impl Drop for RecoveryConsume {
    fn drop(&mut self) {
        self.recovery_key.zeroize();
        self.next_recovery_key.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryComplete {
    pub successor_code_version: i64,
    pub mutation_id: Uuid,
    pub expected_revision: i64,
    pub next_recovery_key: String,
}
impl Drop for RecoveryComplete {
    fn drop(&mut self) {
        self.next_recovery_key.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryConsumeReceipt {
    pub operation_id: Uuid,
    pub user_id: Uuid,
    pub auth_epoch: i64,
    pub account_key_epoch: Option<i64>,
    pub successor_code_version: i64,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}
impl From<&crate::recovery::RecoveryStatus> for RecoveryConsumeReceipt {
    fn from(status: &crate::recovery::RecoveryStatus) -> Self {
        Self {
            operation_id: status.operation_id,
            user_id: status.user_id,
            auth_epoch: status.auth_epoch,
            account_key_epoch: status.account_key_epoch,
            successor_code_version: status.successor_code_version,
            expires_at: status.expires_at,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCredentialOptions {
    pub mutation_id: Uuid,
    pub expected_revision: i64,
    pub action: RecoveryOptionsPhase,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryOptionsPhase {
    Register { name: String, mode: PasskeyMode },
    Test,
    Grant { body_digest: String },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCredentialFinish {
    pub mutation_id: Uuid,
    pub expected_revision: i64,
    pub action: RecoveryFinishPhase,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryFinishPhase {
    Register {
        response: CeremonyResponse,
    },
    Test {
        response: CeremonyResponse,
    },
    Grant {
        grant: Box<AccountGrant>,
        proof: CustodyProof,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryStepReply {
    pub mutation_id: Uuid,
    pub status: crate::recovery::RecoveryStatus,
    pub result: RecoveryStepResult,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryStepResult {
    Ceremony { options: CeremonyOptions },
    Custody { context: MutationContext },
    Tested { receipt: CandidateReceipt },
    GrantReady { grant_id: Uuid },
    Completed,
    Abandoned,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCandidate {
    pub name: String,
    pub mode: PasskeyMode,
    pub registered_credential_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryView {
    pub status: crate::recovery::RecoveryStatus,
    pub security_revision: i64,
    pub descriptor: Option<AccountDescriptor>,
    pub descriptor_issue: Option<GrantIssue>,
    pub candidate: Option<RecoveryCandidate>,
    pub receipt: Option<CandidateReceipt>,
    pub grant: Option<AccountGrant>,
    pub kdf: crate::api::auth::PreloginResponse,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAbandon {
    pub mutation_id: Uuid,
    pub expected_revision: i64,
}

impl RecoveryConsume {
    pub fn digest(
        &self,
        server_id: &str,
    ) -> Result<[u8; 32], zann_crypto::account_access::AccountAccessError> {
        use zann_crypto::account_access::{AccountAccessError, Transcript};
        if self.operation_id.get_version_num() != 4
            || self.locator.is_empty()
            || self.locator.len() > 320
            || self.locator.chars().any(char::is_control)
            || !zann_crypto::recovery::valid_recovery_code(&self.recovery_key)
            || !zann_crypto::recovery::valid_recovery_code(&self.next_recovery_key)
            || zann_crypto::tokens::constant_time_equal(
                self.recovery_key.as_bytes(),
                self.next_recovery_key.as_bytes(),
            )
        {
            return Err(AccountAccessError::Invalid("recovery consume request"));
        }
        let mut t = Transcript::new("zann recovery consume v1")
            .field(server_id.as_bytes())
            .field(self.operation_id.as_bytes())
            .field(self.locator.as_bytes())
            .field(self.recovery_key.as_bytes())
            .field(self.next_recovery_key.as_bytes())
            .field(self.device.name.as_bytes())
            .field(self.device.platform.as_bytes());
        for value in [
            &self.device.fingerprint,
            &self.device.os,
            &self.device.os_version,
            &self.device.app_version,
        ] {
            t = t.field(&[u8::from(value.is_some())]);
            if let Some(value) = value {
                t = t.field(value.as_bytes());
            }
        }
        Ok(t.digest())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyEnvelope {
    pub vault_id: Uuid,
    pub vault_key_enc: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyMaterial {
    pub personal: Option<RecoveryKeyEnvelope>,
}
