//! Feature-gated ES256 for syncable passkeys. No item-envelope format changes.
use std::fmt;

use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The dependency zeroizes its scalar on drop. Never derive Debug or Serialize.
pub struct Es256Key(SigningKey);

pub enum Es256Error {
    Entropy(rand::Error),
    Key(p256::ecdsa::Error),
    Pkcs8(p256::pkcs8::Error),
    Signature(p256::ecdsa::Error),
    EntropyExhausted,
    KeyLength,
}

impl fmt::Display for Es256Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Entropy(_) | Self::EntropyExhausted => "passkey entropy unavailable",
            Self::Key(_) | Self::Pkcs8(_) | Self::KeyLength => "invalid ES256 private key",
            Self::Signature(_) => "invalid ES256 signature",
        })
    }
}

impl fmt::Debug for Es256Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for Es256Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Entropy(source) => Some(source),
            Self::Key(source) | Self::Signature(source) => Some(source),
            Self::Pkcs8(source) => Some(source),
            Self::EntropyExhausted | Self::KeyLength => None,
        }
    }
}

impl Es256Key {
    pub fn generate() -> Result<Self, Es256Error> {
        let mut scalar = Zeroizing::new([0u8; 32]);
        for _ in 0..128 {
            OsRng
                .try_fill_bytes(scalar.as_mut())
                .map_err(Es256Error::Entropy)?;
            if let Ok(key) = SigningKey::from_slice(scalar.as_ref()) {
                return Ok(Self(key));
            }
        }
        Err(Es256Error::EntropyExhausted)
    }

    pub fn from_scalar(bytes: &[u8]) -> Result<Self, Es256Error> {
        if bytes.len() != 32 {
            return Err(Es256Error::KeyLength);
        }
        SigningKey::from_slice(bytes)
            .map(Self)
            .map_err(Es256Error::Key)
    }

    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self, Es256Error> {
        SigningKey::from_pkcs8_der(bytes)
            .map(Self)
            .map_err(Es256Error::Pkcs8)
    }

    /// For local encrypted item storage / authorized export only, never IPC.
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, Es256Error> {
        let document = p256::SecretKey::from(&self.0)
            .to_pkcs8_der()
            .map_err(Es256Error::Pkcs8)?;
        Ok(Zeroizing::new(document.as_bytes().to_vec()))
    }

    /// Uncompressed SEC1: 0x04 || x || y.
    pub fn public_key(&self) -> [u8; 65] {
        self.0
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .expect("P-256 uncompressed points have 65 bytes")
    }

    /// WebAuthn ES256 uses ASN.1 DER signatures over SHA-256(message).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Es256Error> {
        let signature: Signature = self.0.try_sign(message).map_err(Es256Error::Signature)?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

pub fn verify(public_key: &[u8], message: &[u8], der_signature: &[u8]) -> Result<(), Es256Error> {
    let key = VerifyingKey::from_sec1_bytes(public_key).map_err(Es256Error::Key)?;
    let signature = Signature::from_der(der_signature).map_err(Es256Error::Signature)?;
    key.verify(message, &signature)
        .map_err(Es256Error::Signature)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn credential_id() -> Result<[u8; 32], Es256Error> {
    let mut id = [0; 32];
    OsRng.try_fill_bytes(&mut id).map_err(Es256Error::Entropy)?;
    Ok(id)
}
