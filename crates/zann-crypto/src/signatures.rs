//! Purpose-neutral Ed25519 primitive. Domain owners expose typed signing operations.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

pub(crate) struct Ed25519Secret(Zeroizing<[u8; 32]>);

impl Ed25519Secret {
    pub(crate) fn from_seed(seed: [u8; 32]) -> Self {
        Self(Zeroizing::new(seed))
    }
    pub(crate) fn seed(&self) -> &[u8; 32] {
        &self.0
    }
    pub(crate) fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.0).verifying_key().to_bytes()
    }
    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.0).sign(message).to_bytes()
    }
}

pub fn verify_ed25519(public: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_strict(message, &signature).is_ok()
}
