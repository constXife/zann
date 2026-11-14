//! Ed25519 identities for authenticated local IPC; no vault keys or envelopes.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

pub struct IpcSigningKey(Zeroizing<[u8; 32]>);

impl IpcSigningKey {
    pub fn generate() -> Self {
        Self::from_seed(random_nonce())
    }
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(Zeroizing::new(seed))
    }
    /// Only for an owner-only identity store; never a browser/wire operation.
    pub fn seed(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.0).verifying_key().to_bytes()
    }
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.0).sign(message).to_bytes()
    }
}

pub fn random_nonce() -> [u8; 32] {
    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_strict(message, &signature).is_ok()
}
