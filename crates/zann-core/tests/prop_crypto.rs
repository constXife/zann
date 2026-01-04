use proptest::collection::vec;
use proptest::prelude::*;
use zann_core::crypto::{decrypt_blob, encrypt_blob, EncryptedBlob, SecretKey};

proptest! {
    #[test]
    fn encrypt_decrypt_roundtrip(plaintext in vec(any::<u8>(), 0..512), aad in vec(any::<u8>(), 0..128)) {
        let key = SecretKey::generate();
        let blob = encrypt_blob(&key, &plaintext, &aad).expect("encrypt");
        let decrypted = decrypt_blob(&key, &blob, &aad).expect("decrypt");
        prop_assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn blob_bytes_roundtrip(plaintext in vec(any::<u8>(), 0..512), aad in vec(any::<u8>(), 0..128)) {
        let key = SecretKey::generate();
        let blob = encrypt_blob(&key, &plaintext, &aad).expect("encrypt");
        let bytes = blob.to_bytes();
        let parsed = EncryptedBlob::from_bytes(&bytes).expect("parse");
        let decrypted = decrypt_blob(&key, &parsed, &aad).expect("decrypt");
        prop_assert_eq!(decrypted, plaintext);
    }
}
