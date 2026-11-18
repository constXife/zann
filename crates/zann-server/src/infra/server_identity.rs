//! Canonical signed discovery identity, shared with account-access transcripts.
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
pub fn server_id(key: &ed25519_dalek::VerifyingKey) -> String {
    BASE32_NOPAD
        .encode(&Sha256::digest(key.to_bytes()))
        .to_ascii_lowercase()
}
