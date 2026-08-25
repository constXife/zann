use serde::Deserialize;
use uuid::Uuid;
use zann_crypto::{
    decrypt_payload, decrypt_payload_bytes, decrypt_vault_key, derive_auth_hash, kdf_fingerprint,
    payload_aad, payload_checksum, vault_key_aad, EncryptedBlob, KdfParams, SecretKey,
    VaultCryptoError,
};

const FIXTURE_JSON: &str = include_str!("../../../tests/fixtures/crypto/v1_local_vault.json");

#[derive(Debug, Deserialize)]
struct Fixture {
    synthetic_only: bool,
    kdf: KdfFixture,
    vault: VaultFixture,
    payload: PayloadFixture,
    aad: AadFixture,
}

#[derive(Debug, Deserialize)]
struct KdfFixture {
    password: String,
    salt_base64: String,
    params: KdfParamsFixture,
    expected_key_hex: String,
    expected_fingerprint: String,
}

#[derive(Debug, Deserialize)]
struct KdfParamsFixture {
    algorithm: String,
    iterations: u32,
    memory_kb: u32,
    parallelism: u32,
}

#[derive(Debug, Deserialize)]
struct VaultFixture {
    vault_id: String,
    vault_key_hex: String,
    vault_key_enc_hex: String,
}

#[derive(Debug, Deserialize)]
struct PayloadFixture {
    item_id: String,
    plaintext_utf8: String,
    payload_enc_hex: String,
    checksum_blake3: String,
}

#[derive(Debug, Deserialize)]
struct AadFixture {
    vault_key_hex: String,
    payload_hex: String,
}

fn fixture() -> Fixture {
    let fixture: Fixture = serde_json::from_str(FIXTURE_JSON).expect("valid crypto fixture");
    assert!(
        fixture.synthetic_only,
        "compatibility fixtures must never contain production secrets"
    );
    fixture
}

fn kdf_params(fixture: &Fixture) -> KdfParams {
    KdfParams {
        algorithm: fixture.kdf.params.algorithm.clone(),
        iterations: fixture.kdf.params.iterations,
        memory_kb: fixture.kdf.params.memory_kb,
        parallelism: fixture.kdf.params.parallelism,
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("valid fixture hex")
}

fn secret_key(value: &str) -> SecretKey {
    let bytes: [u8; 32] = decode_hex(value)
        .try_into()
        .expect("fixture key must be 32 bytes");
    SecretKey::from_bytes(bytes)
}

fn ids(fixture: &Fixture) -> (Uuid, Uuid) {
    (
        Uuid::parse_str(&fixture.vault.vault_id).expect("valid vault id"),
        Uuid::parse_str(&fixture.payload.item_id).expect("valid item id"),
    )
}

#[test]
fn v1_local_vault_golden_remains_decryptable() {
    let fixture = fixture();
    let (vault_id, item_id) = ids(&fixture);

    let master_key_bytes = derive_auth_hash(
        &fixture.kdf.password,
        &fixture.kdf.salt_base64,
        &kdf_params(&fixture),
    )
    .expect("derive fixture master key");
    assert_eq!(
        master_key_bytes.as_slice(),
        decode_hex(&fixture.kdf.expected_key_hex)
    );
    assert_eq!(
        kdf_fingerprint(&fixture.kdf.salt_base64, &kdf_params(&fixture))
            .expect("fingerprint fixture KDF"),
        fixture.kdf.expected_fingerprint
    );
    let master_key = SecretKey::from_bytes(master_key_bytes);

    assert_eq!(
        vault_key_aad(vault_id),
        decode_hex(&fixture.aad.vault_key_hex)
    );
    assert_eq!(
        payload_aad(vault_id, item_id),
        decode_hex(&fixture.aad.payload_hex)
    );

    let vault_key_enc = decode_hex(&fixture.vault.vault_key_enc_hex);
    let vault_blob = EncryptedBlob::from_bytes(&vault_key_enc).expect("valid vault-key blob");
    assert_eq!(vault_blob.to_bytes(), vault_key_enc);
    let vault_key = decrypt_vault_key(&master_key, vault_id, &vault_key_enc)
        .expect("decrypt fixture vault key");
    assert_eq!(
        vault_key.as_bytes().as_slice(),
        decode_hex(&fixture.vault.vault_key_hex)
    );

    let payload_enc = decode_hex(&fixture.payload.payload_enc_hex);
    let payload_blob = EncryptedBlob::from_bytes(&payload_enc).expect("valid payload blob");
    assert_eq!(payload_blob.to_bytes(), payload_enc);
    let plaintext = decrypt_payload_bytes(&vault_key, vault_id, item_id, &payload_enc)
        .expect("decrypt fixture payload bytes");
    assert_eq!(plaintext, fixture.payload.plaintext_utf8.as_bytes());

    let payload = decrypt_payload(&vault_key, vault_id, item_id, &payload_enc)
        .expect("decode fixture payload");
    assert_eq!(payload.v, 1);
    assert_eq!(payload.type_id, "login");
    assert_eq!(payload.fields["password"].value, "fixture-secret");
    assert_eq!(
        payload_checksum(&payload_enc),
        fixture.payload.checksum_blake3
    );
}

#[test]
fn v1_local_vault_golden_rejects_wrong_password_and_aad() {
    let fixture = fixture();
    let (vault_id, item_id) = ids(&fixture);
    let vault_key_enc = decode_hex(&fixture.vault.vault_key_enc_hex);
    let payload_enc = decode_hex(&fixture.payload.payload_enc_hex);

    let wrong_master_key = SecretKey::from_bytes(
        derive_auth_hash(
            "wrong-test-master-password",
            &fixture.kdf.salt_base64,
            &kdf_params(&fixture),
        )
        .expect("derive wrong fixture key"),
    );
    assert!(matches!(
        decrypt_vault_key(&wrong_master_key, vault_id, &vault_key_enc),
        Err(VaultCryptoError::DecryptFailed)
    ));

    let master_key = secret_key(&fixture.kdf.expected_key_hex);
    let wrong_vault_id =
        Uuid::parse_str("11111111-1111-4111-8111-111111111112").expect("valid wrong vault id");
    assert!(matches!(
        decrypt_vault_key(&master_key, wrong_vault_id, &vault_key_enc),
        Err(VaultCryptoError::DecryptFailed)
    ));

    let vault_key = secret_key(&fixture.vault.vault_key_hex);
    let wrong_item_id =
        Uuid::parse_str("22222222-2222-4222-8222-222222222223").expect("valid wrong item id");
    assert_eq!(
        decrypt_payload_bytes(&vault_key, vault_id, wrong_item_id, &payload_enc),
        Err(VaultCryptoError::DecryptFailed)
    );
    assert_eq!(
        decrypt_payload_bytes(&vault_key, wrong_vault_id, item_id, &payload_enc),
        Err(VaultCryptoError::DecryptFailed)
    );
}

#[test]
fn v1_local_vault_golden_detects_payload_tampering() {
    let fixture = fixture();
    let (vault_id, item_id) = ids(&fixture);
    let vault_key = secret_key(&fixture.vault.vault_key_hex);
    let payload_enc = decode_hex(&fixture.payload.payload_enc_hex);
    let mut tampered_payload = payload_enc.clone();
    *tampered_payload.last_mut().expect("non-empty payload blob") ^= 0x01;

    assert_ne!(
        payload_checksum(&tampered_payload),
        fixture.payload.checksum_blake3
    );
    assert_eq!(
        decrypt_payload_bytes(&vault_key, vault_id, item_id, &tampered_payload),
        Err(VaultCryptoError::DecryptFailed)
    );

    let mut invalid_envelope = payload_enc;
    invalid_envelope[0] ^= 0x01;
    assert_eq!(
        decrypt_payload_bytes(&vault_key, vault_id, item_id, &invalid_envelope),
        Err(VaultCryptoError::InvalidBlob)
    );
}
