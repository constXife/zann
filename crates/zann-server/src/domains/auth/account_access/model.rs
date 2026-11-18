use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use webauthn_rs_core::proto::{AuthenticationState, Credential, RegistrationState};
use zann_core::api::account_access::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum OperationKind {
    Enrollment { name: String, mode: PasskeyMode },
    Login { device: DeviceDescriptor },
    Authorize { intent: UvAuthorizationIntent },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationData {
    pub kind: OperationKind,
    pub options: CeremonyOptions,
    pub challenge_expires_at: DateTime<Utc>,
    pub registration: Option<RegistrationState>,
    pub assertion: Option<AuthenticationState>,
    pub credential: Option<Credential>,
    pub register_response_digest: Option<[u8; 32]>,
    pub register_reply: Option<CeremonyOptions>,
    pub test_rounds: u8,
    pub test_refreshes: Vec<(uuid::Uuid, CeremonyOptions)>,
    pub test_response_digest: Option<[u8; 32]>,
    pub receipt: Option<CandidateReceipt>,
    pub grant: Option<AccountGrant>,
    pub login_consumed: bool,
    pub credential_fence: Option<i64>,
}
impl OperationData {
    pub fn new(kind: OperationKind, options: CeremonyOptions) -> Self {
        Self {
            kind,
            options,
            challenge_expires_at: Utc::now() + chrono::Duration::seconds(CHALLENGE_SECONDS),
            registration: None,
            assertion: None,
            credential: None,
            register_response_digest: None,
            register_reply: None,
            test_rounds: 0,
            test_refreshes: Vec::new(),
            test_response_digest: None,
            receipt: None,
            grant: None,
            login_consumed: false,
            credential_fence: None,
        }
    }
}
