use serde::Deserialize;
use uuid::Uuid;
use zann_crypto::*;

#[derive(Deserialize)]
struct PasswordVectors {
    synthetic_only: bool,
    params: Params,
    salt_base64: String,
    pepper: String,
    vectors: Vec<PasswordVector>,
    service_token: String,
    expected_service_token_hash: String,
    expected_kdf_fingerprint: String,
}
#[derive(Deserialize)]
struct Params {
    algorithm: String,
    iterations: u32,
    memory_kb: u32,
    parallelism: u32,
}
#[derive(Deserialize)]
struct PasswordVector {
    nfc: String,
    nfd: String,
    expected_key_hex: String,
    expected_password_hash: String,
}

#[test]
fn password_kdf_and_server_hashes_match_frozen_unicode_vectors() {
    let fixture: PasswordVectors = serde_json::from_str(include_str!(
        "../../../tests/fixtures/crypto/v1_passwords.json"
    ))
    .expect("synthetic fixture");
    assert!(fixture.synthetic_only);
    let params = KdfParams {
        algorithm: fixture.params.algorithm,
        iterations: fixture.params.iterations,
        memory_kb: fixture.params.memory_kb,
        parallelism: fixture.params.parallelism,
    };
    assert_eq!(
        kdf_fingerprint(&fixture.salt_base64, &params).expect("fingerprint"),
        fixture.expected_kdf_fingerprint
    );
    for vector in fixture.vectors {
        for password in [&vector.nfc, &vector.nfd] {
            let key = derive_auth_hash(password, &fixture.salt_base64, &params).expect("derive");
            assert_eq!(hex::encode(key), vector.expected_key_hex);
            assert_eq!(
                hash_password(&key, &fixture.pepper, &params).expect("hash"),
                vector.expected_password_hash
            );
            assert!(verify_password(
                &vector.expected_password_hash,
                password,
                &fixture.salt_base64,
                &params,
                &fixture.pepper
            )
            .expect("verify"));
        }
    }
    assert_eq!(
        hash_service_token(&fixture.service_token, &fixture.pepper, &params).expect("token hash"),
        fixture.expected_service_token_hash
    );
    assert_ne!(
        hash_service_token("synthetic-opaque-Å-token", &fixture.pepper, &params)
            .expect("opaque token"),
        fixture.expected_service_token_hash
    );
}

#[test]
fn nfc_does_not_trim_fold_case_or_apply_compatibility_normalization() {
    let params = KdfParams {
        algorithm: "argon2id".into(),
        iterations: 1,
        memory_kb: 8,
        parallelism: 1,
    };
    let salt = "c3ludGhldGljLW5mYy10ZXN0LXNhbHQ=";
    let base = derive_auth_hash("Pass", salt, &params).expect("derive");
    for different in [" Pass", "Pass ", "pass", "Ｐass", "Pass\u{a0}"] {
        assert!(derive_auth_hash(different, salt, &params).expect("derive") != base);
    }
}

#[derive(Deserialize)]
struct RotationVector {
    synthetic_only: bool,
    key_hex: String,
    vault_id: String,
    item_id: String,
    plaintext_utf8: String,
    aad_hex: String,
    envelope_hex: String,
}

#[test]
fn rotation_candidate_aad_and_ciphertext_match_the_frozen_v1_vector() {
    let fixture: RotationVector = serde_json::from_str(include_str!(
        "../../../tests/fixtures/crypto/v1_rotation.json"
    ))
    .expect("synthetic fixture");
    assert!(fixture.synthetic_only);
    let vault_id = Uuid::parse_str(&fixture.vault_id).expect("vault UUID");
    let item_id = Uuid::parse_str(&fixture.item_id).expect("item UUID");
    let key = SecretKey::from_bytes(
        hex::decode(fixture.key_hex)
            .expect("key")
            .try_into()
            .expect("32 bytes"),
    );
    let ciphertext = hex::decode(fixture.envelope_hex).expect("envelope");
    assert_eq!(
        hex::encode(rotation_candidate_aad(vault_id, item_id)),
        fixture.aad_hex
    );
    assert_eq!(
        decrypt_rotation_candidate(&key, vault_id, item_id, &ciphertext).expect("candidate"),
        fixture.plaintext_utf8.as_bytes()
    );
    assert!(decrypt_rotation_candidate(&key, vault_id, Uuid::now_v7(), &ciphertext).is_err());
    assert!(decrypt_payload_bytes(&key, vault_id, item_id, &ciphertext).is_err());
}
