//! Ed25519 identities for authenticated local IPC; no vault keys or envelopes.
use crate::signatures::Ed25519Secret;
use rand::{rngs::OsRng, RngCore};

pub struct IpcSigningKey(Ed25519Secret);

impl IpcSigningKey {
    pub fn generate() -> Self {
        Self::from_seed(random_nonce())
    }
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(Ed25519Secret::from_seed(seed))
    }
    /// Only for an owner-only identity store; never a browser/wire operation.
    pub fn seed(&self) -> &[u8; 32] {
        self.0.seed()
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.0.public_key()
    }
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message)
    }
}

pub fn random_nonce() -> [u8; 32] {
    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    crate::signatures::verify_ed25519(public_key, message, signature)
}
