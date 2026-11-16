//! Bounded browser ceremony contract. No private key or payload is a wire type.
use super::{BrowserContext, BrowserScope, IpcError, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zann_autofill::{CrossOriginPermission, RpId};

pub const PASSKEY_CANDIDATE_LIMIT: usize = zann_core::BROWSER_PAGE_LIMIT as usize;
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "ceremony", rename_all = "snake_case", deny_unknown_fields)]
pub enum PasskeyOperation {
    Create {
        rp_name: String,
        user_id: String,
        user_name: String,
        user_display_name: String,
        algorithms: Vec<i32>,
        exclude_credentials: Vec<String>,
    },
    Get {
        allow_credentials: Vec<String>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyRequest {
    pub context: BrowserContext,
    pub rp_id: String,
    pub challenge: String,
    pub require_verification: bool,
    pub operation: PasskeyOperation,
}
impl PasskeyRequest {
    pub fn validate(&self) -> Result<RpId> {
        let (top, frame) = self.context.credential_context()?;
        let rp = RpId::parse(&self.rp_id).map_err(IpcError::Policy)?;
        if rp.as_str() != self.rp_id {
            return Err(IpcError::Protocol);
        }
        rp.authorize(&top, &frame, CrossOriginPermission::Denied)
            .map_err(IpcError::Policy)?;
        decode(&self.challenge, 1024)?;
        let ids = match &self.operation {
            PasskeyOperation::Create {
                rp_name,
                user_id,
                user_name,
                user_display_name,
                algorithms,
                exclude_credentials,
            } => {
                for label in [rp_name, user_name, user_display_name] {
                    if label.len() > 1024 || label.chars().any(char::is_control) {
                        return Err(IpcError::Protocol);
                    }
                }
                decode(user_id, 64)?;
                if algorithms.is_empty() || algorithms.len() > 64 || !algorithms.contains(&-7) {
                    return Err(IpcError::Protocol);
                }
                exclude_credentials
            }
            PasskeyOperation::Get { allow_credentials } => allow_credentials,
        };
        if ids.len() > 64 {
            return Err(IpcError::Protocol);
        }
        for id in ids {
            decode(id, 1023)?;
        }
        // No platform verification adapter is installed. An unlocked session is
        // never verification evidence, including password unlock before a query.
        if self.require_verification {
            return Err(IpcError::Protocol);
        }
        Ok(rp)
    }
    pub fn client_data(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let (_, frame) = self.context.credential_context()?;
        #[derive(Serialize)]
        struct ClientData<'a> {
            r#type: &'a str,
            challenge: &'a str,
            origin: String,
            #[serde(rename = "crossOrigin")]
            cross_origin: bool,
        }
        let kind = match self.operation {
            PasskeyOperation::Create { .. } => "webauthn.create",
            PasskeyOperation::Get { .. } => "webauthn.get",
        };
        // origin_url ends in '/', while WebAuthn's serialized origin does not.
        let origin = frame.origin_url().trim_end_matches('/').to_string();
        Ok(serde_json::to_vec(&ClientData {
            r#type: kind,
            challenge: &self.challenge,
            origin,
            cross_origin: false,
        })?)
    }
    pub fn client_data_hash(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.client_data()?).into())
    }
}
pub fn decode(value: &str, max: usize) -> Result<Vec<u8>> {
    if value.is_empty() || value.len() > max.div_ceil(3) * 4 {
        return Err(IpcError::Protocol);
    }
    let bytes = B64.decode(value).map_err(IpcError::Encoding)?;
    if bytes.is_empty() || bytes.len() > max || B64.encode(&bytes) != value {
        return Err(IpcError::Protocol);
    }
    Ok(bytes)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyCandidate {
    pub item_id: String,
    pub title: String,
    pub user_name: String,
    pub user_display_name: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyMatches {
    pub scope: BrowserScope,
    pub items: Vec<PasskeyCandidate>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyResponse {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub attestation_object: Option<String>,
    pub public_key_spki: Option<String>,
    pub signature: Option<String>,
    pub user_handle: Option<String>,
}
