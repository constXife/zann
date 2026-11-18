//! Account RP bridge, separate from the vault's website-passkey provider.
//! PRF output exists only on the encrypted paired native channel, never HTTP.
use serde::{Deserialize, Serialize};
use zann_core::api::account_access::{CeremonyOptions, CeremonyPhase, CeremonyResponse};
use zeroize::Zeroizing;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountCeremonyPrompt {
    pub server_address: String,
    pub server_fingerprint: String,
    pub server_id: String,
    pub options: CeremonyOptions,
    pub require_prf: bool,
}
pub struct PrfOutput(Zeroizing<[u8; 32]>);
impl PrfOutput {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn into_account_prf(self) -> zann_crypto::account_access::AccountPrf {
        zann_crypto::account_access::AccountPrf::from_bytes(*self.0)
    }
}
impl Serialize for PrfOutput {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&Zeroizing::new(zann_crypto::account_access::encode(
            &*self.0,
        )))
    }
}
impl<'de> Deserialize<'de> for PrfOutput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use base64::Engine as _;
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        if encoded.len() != 43 {
            return Err(serde::de::Error::custom("PRF length"));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        let size = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode_slice(encoded.as_bytes(), bytes.as_mut())
            .map_err(serde::de::Error::custom)?;
        if size != 32 {
            return Err(serde::de::Error::custom("PRF length"));
        }
        Ok(Self(bytes))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountCeremonyResult {
    pub response: CeremonyResponse,
    pub prf: Option<PrfOutput>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountCeremonyFailure {
    Cancelled,
    MissingPrf,
    Provider,
    Expired,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccountCeremonyCompletion {
    Completed { result: AccountCeremonyResult },
    Failed { reason: AccountCeremonyFailure },
}
pub fn validate_account_prompt(prompt: &AccountCeremonyPrompt) -> Result<(), AccountCeremonyError> {
    use zann_crypto::account_access::{array, decode, prf_input};
    let invalid = || AccountCeremonyError::InvalidContext;
    let options = &prompt.options;
    zann_autofill::RpId::parse(&options.rp_id).map_err(|_| invalid())?;
    if prompt.server_address.is_empty()
        || prompt.server_address.len() > 2048
        || prompt.server_address.chars().any(char::is_control)
        || prompt.server_fingerprint.is_empty()
        || prompt.server_fingerprint.len() > 256
        || prompt.server_fingerprint.chars().any(char::is_control)
        || options.rp_name.is_empty()
        || options.rp_name.len() > 128
        || options.rp_name.chars().any(char::is_control)
        || options.credential_ids.len() > 16
        || options.operation_id.get_version_num() != 4
        || options.user_id.is_some_and(|id| id.is_nil())
        || options
            .user_name
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 320 || s.chars().any(char::is_control))
    {
        return Err(invalid());
    }
    if prf_input(&prompt.server_id, &options.rp_id).map_err(|_| invalid())?
        != array::<32>(&options.prf_input).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    if decode(&options.challenge, 64).map_err(|_| invalid())?.len() < 16 {
        return Err(invalid());
    }
    for (index, id) in options.credential_ids.iter().enumerate() {
        if decode(id, 1024).map_err(|_| invalid())?.is_empty()
            || options.credential_ids[..index].contains(id)
        {
            return Err(invalid());
        }
    }
    match options.phase {
        CeremonyPhase::Register if options.user_id.is_none() || options.user_name.is_none() => {
            Err(invalid())
        }
        CeremonyPhase::Test | CeremonyPhase::Login if !options.credential_ids.is_empty() => {
            Err(invalid())
        }
        CeremonyPhase::Authorize if options.credential_ids.is_empty() => Err(invalid()),
        _ => Ok(()),
    }
}
#[derive(Debug, thiserror::Error)]
pub enum AccountCeremonyError {
    #[error("invalid account ceremony context")]
    InvalidContext,
    #[error("account ceremony did not complete: {0:?}")]
    Failed(AccountCeremonyFailure),
    #[error("account ceremony adapter failed")]
    Adapter(#[source] Box<dyn std::error::Error + Send + Sync>),
}
pub type AccountCeremonyFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<AccountCeremonyResult, AccountCeremonyError>>
            + Send
            + 'a,
    >,
>;
/// Trusted native adapter. A web page cannot obtain this capability.
pub trait AccountCeremonyProvider: Send + Sync {
    fn perform(&self, prompt: AccountCeremonyPrompt) -> AccountCeremonyFuture<'_>;
}
#[cfg(feature = "app")]
pub(crate) mod intents;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prf_decode_is_exact_zeroizing_and_never_accepted_in_public_rp_json() {
        let encoded = Zeroizing::new(serde_json::to_string(&PrfOutput::new([9; 32])).unwrap());
        let decoded: PrfOutput = serde_json::from_str(&encoded).unwrap();
        assert!(serde_json::to_string(&decoded).unwrap() == encoded.as_str());
        assert!(serde_json::from_str::<PrfOutput>("\"wrong\"").is_err());
        let response = serde_json::json!({"phase":"assertion","credential_id":"AA","client_data_json":"AA","authenticator_data":"AA","signature":"AA","user_handle":null,"prf":"forbidden"});
        assert!(serde_json::from_value::<CeremonyResponse>(response).is_err());
    }
}
