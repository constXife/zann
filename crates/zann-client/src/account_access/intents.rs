//! Closed public journal projection. No password, recovery code, PRF or bearer.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zann_core::api::account_access::*;
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PublicProof {
    FreshPassword,
    Custody {
        proof: CustodyProof,
    },
    ExistingPasskey {
        operation_id: Uuid,
        response: CeremonyResponse,
    },
}
impl From<&ManagementProof> for PublicProof {
    fn from(proof: &ManagementProof) -> Self {
        match proof {
            ManagementProof::InitialPassword { .. } => Self::FreshPassword,
            ManagementProof::Custody { proof } => Self::Custody {
                proof: proof.clone(),
            },
            ManagementProof::ExistingPasskey {
                operation_id,
                response,
            } => Self::ExistingPasskey {
                operation_id: *operation_id,
                response: response.clone(),
            },
        }
    }
}
impl PublicProof {
    pub(crate) fn replay(&self) -> Option<ManagementProof> {
        match self {
            Self::FreshPassword => None,
            Self::Custody { proof } => Some(ManagementProof::Custody {
                proof: proof.clone(),
            }),
            Self::ExistingPasskey {
                operation_id,
                response,
            } => Some(ManagementProof::ExistingPasskey {
                operation_id: *operation_id,
                response: response.clone(),
            }),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "request",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum PublicRequest {
    Enrollment(EnrollmentRequest),
    Ceremony(CeremonyFinish),
    TestOptions(CandidateTestOptions),
    Uv(UvAuthorizationRequest),
    Mutation(MutationOptions),
    Grant(StageGrant),
    Descriptor {
        operation_id: Uuid,
        expected_revision: i64,
        descriptor: AccountDescriptor,
        proof: PublicProof,
    },
    Activate {
        operation_id: Uuid,
        expected_revision: i64,
        proof: PublicProof,
    },
    Revoke {
        mutation_id: Uuid,
        expected_revision: i64,
        credential_id: String,
        revoke_sessions: bool,
        proof: PublicProof,
    },
    Code {
        candidate_id: Uuid,
        expected_revision: i64,
        disable_password: bool,
        body_digest: String,
        proof: PublicProof,
    },
    RecoveryOptions(RecoveryCredentialOptions),
    RecoveryFinish(RecoveryCredentialFinish),
    RecoveryComplete {
        mutation_id: Uuid,
        expected_revision: i64,
        successor_code_version: i64,
    },
    RecoveryAbandon(RecoveryAbandon),
}
pub(crate) trait SecurityRequest: Serialize {
    fn public_request(&self) -> PublicRequest;
}
macro_rules! request {
    ($ty:ty,$variant:ident) => {
        impl SecurityRequest for $ty {
            fn public_request(&self) -> PublicRequest {
                PublicRequest::$variant(self.clone())
            }
        }
    };
}
request!(EnrollmentRequest, Enrollment);
request!(CeremonyFinish, Ceremony);
request!(CandidateTestOptions, TestOptions);
request!(UvAuthorizationRequest, Uv);
request!(MutationOptions, Mutation);
request!(StageGrant, Grant);
request!(RecoveryCredentialOptions, RecoveryOptions);
request!(RecoveryCredentialFinish, RecoveryFinish);
request!(RecoveryAbandon, RecoveryAbandon);
impl SecurityRequest for DescriptorBootstrap {
    fn public_request(&self) -> PublicRequest {
        PublicRequest::Descriptor {
            operation_id: self.operation_id,
            expected_revision: self.expected_revision,
            descriptor: self.descriptor.clone(),
            proof: (&self.proof).into(),
        }
    }
}
impl SecurityRequest for ActivateCredential {
    fn public_request(&self) -> PublicRequest {
        PublicRequest::Activate {
            operation_id: self.operation_id,
            expected_revision: self.expected_revision,
            proof: (&self.proof).into(),
        }
    }
}
impl SecurityRequest for RevokeCredential {
    fn public_request(&self) -> PublicRequest {
        PublicRequest::Revoke {
            mutation_id: self.mutation_id,
            expected_revision: self.expected_revision,
            credential_id: self.credential_id.clone(),
            revoke_sessions: self.revoke_sessions,
            proof: (&self.proof).into(),
        }
    }
}
impl SecurityRequest for ActivateRecoveryCode {
    fn public_request(&self) -> PublicRequest {
        PublicRequest::Code {
            candidate_id: self.candidate_id,
            expected_revision: self.expected_revision,
            disable_password: self.disable_password,
            body_digest: zann_crypto::account_access::encode(
                &self
                    .digest()
                    .expect("validated recovery candidate before dispatch"),
            ),
            proof: (&self.proof).into(),
        }
    }
}
impl SecurityRequest for RecoveryComplete {
    fn public_request(&self) -> PublicRequest {
        PublicRequest::RecoveryComplete {
            mutation_id: self.mutation_id,
            expected_revision: self.expected_revision,
            successor_code_version: self.successor_code_version,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "reply",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum PublicReceipt {
    Rejected { status: u16 },
    Ceremony(CeremonyOptions),
    Candidate(CandidateReceipt),
    Security(AccountSecurity),
    Mutation(MutationContext),
    SecurityReceipt(SecurityReceipt),
    Recovery(RecoveryStepReply),
}
pub(crate) trait SecurityReply: serde::de::DeserializeOwned {
    fn public_receipt(&self) -> PublicReceipt;
}
macro_rules! reply {
    ($ty:ty,$variant:ident) => {
        impl SecurityReply for $ty {
            fn public_receipt(&self) -> PublicReceipt {
                PublicReceipt::$variant(self.clone())
            }
        }
    };
}
reply!(CeremonyOptions, Ceremony);
reply!(CandidateReceipt, Candidate);
reply!(AccountSecurity, Security);
reply!(MutationContext, Mutation);
reply!(SecurityReceipt, SecurityReceipt);
reply!(RecoveryStepReply, Recovery);
