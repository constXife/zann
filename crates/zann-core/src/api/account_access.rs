//! Strict public account-access protocol. PRF output is deliberately absent.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
pub use zann_crypto::account_access::{
    AccountDescriptor, AccountGrant, MutationContext, MutationPurpose,
};
use zeroize::Zeroize;

pub const MAX_CREDENTIALS: usize = 16;
pub const MAX_CEREMONY_BYTES: usize = 64 * 1024;
pub const CHALLENGE_SECONDS: i64 = 120;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyMode {
    AuthOnly,
    VaultUnlock,
}
impl PasskeyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthOnly => "auth_only",
            Self::VaultUnlock => "vault_unlock",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyConfiguration {
    pub server_id: String,
    pub rp_id: String,
    pub rp_name: String,
    pub origins: Vec<String>,
    pub prf_input: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyOptions {
    pub operation_id: Uuid,
    pub phase: CeremonyPhase,
    pub challenge: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_id: Option<Uuid>,
    pub user_name: Option<String>,
    pub credential_ids: Vec<String>,
    pub prf_input: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyPhase {
    Register,
    Test,
    Login,
    Authorize,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum CeremonyResponse {
    Register {
        credential_id: String,
        client_data_json: String,
        attestation_object: String,
    },
    Assertion {
        credential_id: String,
        client_data_json: String,
        authenticator_data: String,
        signature: String,
        user_handle: Option<String>,
    },
}
impl CeremonyResponse {
    pub fn credential_id(&self) -> &str {
        match self {
            Self::Register { credential_id, .. } | Self::Assertion { credential_id, .. } => {
                credential_id
            }
        }
    }
    pub fn registration_digest(
        &self,
    ) -> Result<[u8; 32], zann_crypto::account_access::AccountAccessError> {
        use zann_crypto::account_access::{decode, AccountAccessError, Transcript};
        let Self::Register {
            credential_id,
            client_data_json,
            attestation_object,
        } = self
        else {
            return Err(AccountAccessError::Invalid("registration phase"));
        };
        Ok(Transcript::new("zann account registration response v1")
            .field(&decode(credential_id, 1024)?)
            .field(&decode(client_data_json, 8192)?)
            .field(&decode(attestation_object, 32768)?)
            .digest())
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceDescriptor {
    pub name: String,
    pub platform: String,
    pub fingerprint: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub app_version: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyLoginOptions {
    pub operation_id: Uuid,
    pub device: DeviceDescriptor,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyLogin {
    pub tokens: super::auth::LoginResponse,
    pub user_id: Uuid,
    pub credential_id: String,
    pub auth_epoch: i64,
    pub security_revision: i64,
    pub key_access: AccountKeyAccess,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccountKeyAccess {
    AuthOnly {
        descriptor: Option<AccountDescriptor>,
    },
    Ready {
        descriptor: AccountDescriptor,
        grant: Box<AccountGrant>,
    },
    Unavailable {
        reason: GrantIssue,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantIssue {
    Descriptor,
    Missing,
    Encoding,
    Verification,
}

mod management;
mod recovery;
pub use management::*;
pub use recovery::*;
