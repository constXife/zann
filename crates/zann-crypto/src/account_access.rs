//! ADR 0018 account-key custody and PRF grants. No password KDF or platform IO.
use crate::{
    crypto::{CryptoError, SecretKey},
    signatures::Ed25519Secret,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

mod grants;
mod mutation;
pub use mutation::{Authority, MutationContext, MutationPurpose};

#[derive(Debug)]
pub enum AccountAccessError {
    Invalid(&'static str),
    Encoding(base64::DecodeError),
    Crypto(CryptoError),
}
impl std::fmt::Display for AccountAccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid account access {reason}"),
            Self::Encoding(_) => f.write_str("invalid account access binary encoding"),
            Self::Crypto(_) => f.write_str("account-key grant cryptography failed"),
        }
    }
}
impl std::error::Error for AccountAccessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(e) => Some(e),
            Self::Crypto(e) => Some(e),
            Self::Invalid(_) => None,
        }
    }
}
impl From<CryptoError> for AccountAccessError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}
pub type Result<T> = std::result::Result<T, AccountAccessError>;

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn decode(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.len() > maximum.div_ceil(3) * 4 {
        return Err(AccountAccessError::Invalid("binary length"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(AccountAccessError::Encoding)?;
    if bytes.len() > maximum || encode(&bytes) != value {
        return Err(AccountAccessError::Invalid("binary encoding"));
    }
    Ok(bytes)
}
pub fn array<const N: usize>(value: &str) -> Result<[u8; N]> {
    decode(value, N)?
        .try_into()
        .map_err(|_| AccountAccessError::Invalid("binary length"))
}

/// Canonical length-prefixed transcript. Secret-bearing callers retain its zeroizing buffer.
pub struct Transcript(Zeroizing<Vec<u8>>);
impl Transcript {
    pub fn new(label: &'static str) -> Self {
        let mut bytes = Zeroizing::new(label.as_bytes().to_vec());
        bytes.push(0);
        Self(bytes)
    }
    pub fn field(mut self, bytes: &[u8]) -> Self {
        self.0.extend_from_slice(
            &u32::try_from(bytes.len())
                .expect("bounded transcript field")
                .to_be_bytes(),
        );
        self.0.extend_from_slice(bytes);
        self
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.bytes()).into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDescriptor {
    pub format: u64,
    pub server_id: String,
    pub user_id: Uuid,
    pub key_epoch: u64,
    pub proof_public_key: String,
}
impl AccountDescriptor {
    pub fn validate(&self) -> Result<()> {
        if self.format != 1
            || self.key_epoch == 0
            || !valid_server_id(&self.server_id)
            || self.user_id.is_nil()
        {
            return Err(AccountAccessError::Invalid("descriptor"));
        }
        array::<32>(&self.proof_public_key)?;
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        Ok(Transcript::new("zann account descriptor v1")
            .field(&self.format.to_be_bytes())
            .field(self.server_id.as_bytes())
            .field(self.user_id.as_bytes())
            .field(&self.key_epoch.to_be_bytes())
            .field(&array::<32>(&self.proof_public_key)?)
            .digest())
    }
}

pub struct AccountCustody(Ed25519Secret);
impl AccountCustody {
    pub fn derive(key: &SecretKey, server_id: &str, user_id: Uuid, key_epoch: u64) -> Result<Self> {
        if !valid_server_id(server_id) || user_id.is_nil() || key_epoch == 0 {
            return Err(AccountAccessError::Invalid("custody identity"));
        }
        let material = Transcript::new("zann account custody material v1")
            .field(key.as_bytes())
            .field(server_id.as_bytes())
            .field(user_id.as_bytes())
            .field(&key_epoch.to_be_bytes());
        Ok(Self(Ed25519Secret::from_seed(blake3::derive_key(
            "zann account custody seed v1",
            material.bytes(),
        ))))
    }
    pub fn descriptor(&self, server_id: &str, user_id: Uuid, key_epoch: u64) -> AccountDescriptor {
        AccountDescriptor {
            format: 1,
            server_id: server_id.into(),
            user_id,
            key_epoch,
            proof_public_key: encode(&self.0.public_key()),
        }
    }
    pub fn proves(&self, descriptor: &AccountDescriptor) -> Result<()> {
        descriptor.validate()?;
        if array::<32>(&descriptor.proof_public_key)? != self.0.public_key() {
            return Err(AccountAccessError::Invalid("custody proof"));
        }
        Ok(())
    }
}

/// The PRF result has no wire/serde/debug projection and is never persisted.
pub struct AccountPrf(Zeroizing<[u8; 32]>);
impl AccountPrf {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}
pub fn prf_input(server_id: &str, rp_id: &str) -> Result<[u8; 32]> {
    validate_rp(rp_id)?;
    if !valid_server_id(server_id) {
        return Err(AccountAccessError::Invalid("server identity"));
    }
    Ok(Transcript::new("zann account prf input v1")
        .field(server_id.as_bytes())
        .field(rp_id.as_bytes())
        .digest())
}
pub fn ctap_prf_salt(server_id: &str, rp_id: &str) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"WebAuthn PRF\0");
    hash.update(prf_input(server_id, rp_id)?);
    Ok(hash.finalize().into())
}
fn validate_rp(rp: &str) -> Result<()> {
    if rp.is_empty()
        || rp.len() > 253
        || rp
            .bytes()
            .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'))
    {
        return Err(AccountAccessError::Invalid("canonical RP"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountGrant {
    pub format: u64,
    pub server_id: String,
    pub user_id: Uuid,
    pub rp_id: String,
    pub credential_id: String,
    pub grant_id: Uuid,
    pub key_epoch: u64,
    pub proof_public_key: String,
    pub algorithm: String,
    pub blob: String,
    pub signature: String,
}

#[cfg(test)]
mod tests;

fn valid_server_id(id: &str) -> bool {
    id.len() == 52
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        && matches!(id.as_bytes().last(), Some(b'a' | b'q'))
}
