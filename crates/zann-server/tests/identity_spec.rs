use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const SIG_PREFIX: &str = "zann-id:v1";

fn derive_server_id(public_key: &[u8]) -> String {
    let hash = Sha256::digest(public_key);
    BASE32_NOPAD.encode(&hash).to_ascii_lowercase()
}

fn canonical_message(server_id: &str, timestamp: u64) -> String {
    format!("{SIG_PREFIX}:{server_id}:{timestamp}")
}

#[test]
fn server_id_is_hash_of_public_key() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);

    let server_id = derive_server_id(verifying_key.as_bytes());
    let recomputed = derive_server_id(verifying_key.as_bytes());

    assert_eq!(server_id, recomputed);
    assert!(!server_id.is_empty());
    assert_eq!(server_id, server_id.to_ascii_lowercase());
}

#[test]
fn signature_proves_key_possession() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let server_id = derive_server_id(verifying_key.as_bytes());
    let timestamp = 1_704_400_000_u64;
    let message = canonical_message(&server_id, timestamp);

    let signature = signing_key.sign(message.as_bytes());
    verifying_key
        .verify(message.as_bytes(), &signature)
        .expect("valid signature should verify");
}

#[test]
fn hash_mismatch_indicates_spoofing() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let server_id = derive_server_id(verifying_key.as_bytes());

    let mut other_key_bytes = *verifying_key.as_bytes();
    other_key_bytes[0] ^= 0b0001_0000;
    let other_id = derive_server_id(&other_key_bytes);

    assert_ne!(server_id, other_id);
}
