use uuid::Uuid;
use zann_crypto::*;

#[test]
fn rewrap_preserves_the_vault_key_and_leaves_source_usable_until_commit() {
    let old = SecretKey::generate();
    let new = SecretKey::generate();
    let key = SecretKey::generate();
    let id = Uuid::now_v7();
    let original = encrypt_vault_key(&old, id, &key).expect("source");
    let candidate = rewrap_vault_key(&old, &new, id, &original).expect("verified candidate");
    assert!(
        decrypt_vault_key(&new, id, &candidate)
            .expect("new key")
            .as_bytes()
            == key.as_bytes()
    );
    assert!(decrypt_vault_key(&old, id, &candidate).is_err());
    assert!(decrypt_vault_key(&old, id, &original).is_ok());
    assert!(rewrap_vault_key(&new, &old, id, &original).is_err());
    assert!(rewrap_vault_key(&old, &new, Uuid::now_v7(), &original).is_err());
}

#[test]
fn candidate_verification_rejects_corruption_wrong_aad_and_wrong_plaintext() {
    let key = SecretKey::generate();
    let mut candidate = encrypt_blob(&key, b"synthetic new key", b"purpose").expect("candidate");
    candidate.ciphertext[0] ^= 1;
    let commit = verify_blob_plaintext(&key, &candidate, b"purpose", b"synthetic new key");
    assert!(commit.is_err());
    let valid = encrypt_blob(&key, b"actual", b"purpose").expect("candidate");
    assert_eq!(
        verify_blob_plaintext(&key, &valid, b"purpose", b"expected"),
        Err(CryptoError::VerificationFailed)
    );
    assert!(verify_blob_plaintext(&key, &valid, b"wrong purpose", b"actual").is_err());
}
