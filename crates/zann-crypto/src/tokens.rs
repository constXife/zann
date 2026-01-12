use sha2::{Digest, Sha256};

#[must_use]
pub fn hash_token(token: &str, pepper: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.update(pepper.as_bytes());
    hex::encode(hasher.finalize())
}
