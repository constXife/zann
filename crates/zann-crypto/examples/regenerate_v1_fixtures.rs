//! Explicit, synthetic-only fixture regeneration for an intentional v1 review.
//! Existing v1_local_vault.json is retained verbatim to detect envelope drift.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;
use std::{fs, path::Path};
use uuid::Uuid;
use zann_crypto::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let destination = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/crypto");
    let params = KdfParams {
        algorithm: "argon2id".into(),
        iterations: 2,
        memory_kb: 19456,
        parallelism: 1,
    };
    let salt = STANDARD.encode(b"synthetic-v1-nfc-salt-32-bytes!!!!");
    let pepper = "synthetic-v1-pepper";
    let pairs = [
        ("cyrillic", "мой пароль", "мои\u{306} пароль"),
        ("diacritics", "café secret", "cafe\u{301} secret"),
        ("symbols", "Å-secret-🔐", "A\u{30a}-secret-🔐"),
    ];
    let vectors: Vec<_> = pairs.into_iter().map(|(name, nfc, nfd)| {
        let key = derive_auth_hash(nfc, &salt, &params).expect("synthetic KDF");
        json!({"name": name, "nfc": nfc, "nfd": nfd, "expected_key_hex": hex::encode(key),
            "expected_password_hash": hash_password(&key, pepper, &params).expect("synthetic hash")})
    }).collect();
    let token = "synthetic-opaque-A\u{30a}-token";
    let passwords = json!({"synthetic_only": true, "params": {"algorithm": params.algorithm,
        "iterations": params.iterations, "memory_kb": params.memory_kb, "parallelism": params.parallelism},
        "salt_base64": salt, "pepper": pepper, "vectors": vectors, "service_token": token,
        "expected_service_token_hash": hash_service_token(token, pepper, &params)?,
        "expected_kdf_fingerprint": kdf_fingerprint(&salt, &params)?});
    fs::write(
        destination.join("v1_passwords.json"),
        serde_json::to_string_pretty(&passwords)? + "\n",
    )?;

    let key = SecretKey::from_bytes([0x22; 32]);
    let vault_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111")?;
    let item_id = Uuid::parse_str("22222222-2222-4222-8222-222222222222")?;
    let candidate = "synthetic-rotation-candidate";
    let rotation = json!({"synthetic_only": true, "key_hex": hex::encode(key.as_bytes()),
        "vault_id": vault_id.to_string(), "item_id": item_id.to_string(), "plaintext_utf8": candidate,
        "aad_hex": hex::encode(rotation_candidate_aad(vault_id, item_id)),
        "envelope_hex": hex::encode(encrypt_rotation_candidate(&key, vault_id, item_id, candidate.as_bytes())?)});
    fs::write(
        destination.join("v1_rotation.json"),
        serde_json::to_string_pretty(&rotation)? + "\n",
    )?;

    // Independent fixture constants pin the documented, existing keystore
    // protocol. Production adapters must match these frozen values.
    let aad = "zann:dwk:wrap:v1";
    let context = "zann 2026-08-08 fido2 device wrapping key";
    let dwk = [3u8; 32];
    let master = [7u8; 32];
    let hmac_output = [9u8; 32];
    let device = json!({"synthetic_only": true, "dwk_aad_utf8": aad, "fido_context": context,
        "dwk_base64": STANDARD.encode(dwk), "master_key_base64": STANDARD.encode(master),
        "wrapped_master_key_base64": STANDARD.encode(encrypt_blob(&SecretKey::from_bytes(dwk), &master, aad.as_bytes())?.to_bytes()),
        "hmac_output_base64": STANDARD.encode(hmac_output),
        "expected_dwk_base64": STANDARD.encode(blake3::derive_key(context, &hmac_output))});
    fs::write(
        destination.join("v1_device_unlock.json"),
        serde_json::to_string_pretty(&device)? + "\n",
    )?;
    Ok(())
}
