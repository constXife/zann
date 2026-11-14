use zann_crypto::ipc_signatures::{verify, IpcSigningKey};

#[test]
fn ipc_identity_matches_rfc8032_test_one_and_rejects_tampering() {
    // RFC 8032 §7.1, TEST 1 (empty message).
    let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .unwrap()
        .try_into()
        .unwrap();
    let key = IpcSigningKey::from_seed(seed);
    assert_eq!(
        hex::encode(key.public_key()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let signature = key.sign(b"");
    assert_eq!(hex::encode(signature), "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    assert!(verify(&key.public_key(), b"", &signature));
    assert!(!verify(&key.public_key(), b"modified", &signature));
    assert!(!verify(
        &IpcSigningKey::generate().public_key(),
        b"",
        &signature
    ));
    assert!(!verify(&[0; 32], b"", &signature));
    assert!(!verify(&key.public_key(), b"", &signature[..63]));
}
