//! Ordinary account-security management DTOs.
use super::*;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeySummary {
    pub credential_id: String,
    pub name: String,
    pub mode: PasskeyMode,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSecurity {
    pub user_id: Uuid,
    pub auth_epoch: i64,
    pub security_revision: i64,
    pub descriptor: Option<AccountDescriptor>,
    pub descriptor_issue: Option<GrantIssue>,
    pub credentials: Vec<PasskeySummary>,
    pub password_enabled: bool,
    pub recovery_key_version: i64,
    pub recovery_candidate_id: Option<Uuid>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub name: String,
    pub mode: PasskeyMode,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyFinish {
    pub operation_id: Uuid,
    pub response: CeremonyResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateReceipt {
    pub operation_id: Uuid,
    pub receipt_id: Uuid,
    pub credential_id: String,
    pub registration_digest: String,
    pub tested: bool,
    pub mode: PasskeyMode,
}
impl CandidateReceipt {
    pub fn activation_digest(
        &self,
    ) -> Result<[u8; 32], zann_crypto::account_access::AccountAccessError> {
        use zann_crypto::account_access::{array, decode, Transcript};
        Ok(Transcript::new("zann account credential add v1")
            .field(&decode(&self.credential_id, 1024)?)
            .field(&array::<32>(&self.registration_digest)?)
            .field(self.mode.as_str().as_bytes())
            .field(self.receipt_id.as_bytes())
            .digest())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorBootstrap {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub descriptor: AccountDescriptor,
    pub proof: ManagementProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UvAuthorizationIntent {
    Mutation {
        purpose: MutationPurpose,
        body_digest: String,
    },
    Descriptor {
        descriptor: AccountDescriptor,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UvAuthorizationRequest {
    pub expected_revision: i64,
    pub intent: UvAuthorizationIntent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationOptions {
    pub purpose: MutationPurpose,
    pub body_digest: String,
    pub expected_revision: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyProof {
    pub context: MutationContext,
    pub signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagementProof {
    Custody {
        proof: CustodyProof,
    },
    ExistingPasskey {
        operation_id: Uuid,
        response: CeremonyResponse,
    },
    InitialPassword {
        server_password: String,
    },
}
impl Drop for ManagementProof {
    fn drop(&mut self) {
        if let Self::InitialPassword { server_password } = self {
            server_password.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateCredential {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub proof: ManagementProof,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageGrant {
    pub operation_id: Uuid,
    pub grant: AccountGrant,
    pub proof: CustodyProof,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeCredential {
    pub mutation_id: Uuid,
    pub expected_revision: i64,
    pub credential_id: String,
    pub revoke_sessions: bool,
    pub proof: ManagementProof,
}
impl RevokeCredential {
    pub fn digest(&self) -> Result<[u8; 32], zann_crypto::account_access::AccountAccessError> {
        Self::body_digest(&self.credential_id, self.revoke_sessions)
    }
    pub fn body_digest(
        credential_id: &str,
        revoke_sessions: bool,
    ) -> Result<[u8; 32], zann_crypto::account_access::AccountAccessError> {
        use zann_crypto::account_access::{decode, Transcript};
        Ok(Transcript::new("zann account credential revoke v1")
            .field(&decode(credential_id, 1024)?)
            .field(&[u8::from(revoke_sessions)])
            .digest())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityReceipt {
    pub mutation_id: Uuid,
    pub security_revision: i64,
    pub credential_id: Option<String>,
    pub recovery_key_version: Option<i64>,
    pub recovery_candidate_id: Option<Uuid>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateRecoveryCode {
    pub candidate_id: Uuid,
    pub expected_revision: i64,
    pub recovery_key: String,
    pub disable_password: bool,
    pub proof: ManagementProof,
}
impl Drop for ActivateRecoveryCode {
    fn drop(&mut self) {
        self.recovery_key.zeroize();
    }
}
impl ActivateRecoveryCode {
    pub fn digest(&self) -> Result<[u8; 32], zann_crypto::account_access::AccountAccessError> {
        Self::body_digest(self.candidate_id, &self.recovery_key, self.disable_password)
    }
    pub fn body_digest(
        candidate_id: Uuid,
        recovery_key: &str,
        disable_password: bool,
    ) -> Result<[u8; 32], zann_crypto::account_access::AccountAccessError> {
        use zann_crypto::account_access::{AccountAccessError, Transcript};
        if candidate_id.get_version_num() != 4
            || !zann_crypto::recovery::valid_recovery_code(recovery_key)
        {
            return Err(AccountAccessError::Invalid("recovery candidate"));
        }
        let commitment = Transcript::new("zann recovery code commitment v1")
            .field(recovery_key.as_bytes())
            .digest();
        Ok(Transcript::new("zann recovery code activate v1")
            .field(candidate_id.as_bytes())
            .field(&commitment)
            .field(&[u8::from(disable_password)])
            .digest())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateTestOptions {
    pub operation_id: Uuid,
    pub request_id: Uuid,
}
