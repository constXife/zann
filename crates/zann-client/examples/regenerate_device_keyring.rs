//! Explicit synthetic fixture authoring for an intentional Pre-GA keyring cutover.
use base64::{engine::general_purpose::STANDARD, Engine};
use zann_client::{app::unlock::DeviceUnlock, sync::AccountKeyOrigin};
use zann_crypto::SecretKey;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = format!(
        "synthetic fixture {}",
        STANDARD.encode(SecretKey::generate().as_bytes())
    );
    let (mut keyring, root) = DeviceUnlock::create(&password)?;
    let account = SecretKey::generate();
    let cache = SecretKey::generate();
    for (storage, key, origin) in [
        (
            "10000000-0000-4000-8000-000000000001",
            &account,
            AccountKeyOrigin::AccountPassword,
        ),
        (
            "10000000-0000-4000-8000-000000000002",
            &cache,
            AccountKeyOrigin::LocalCacheKey,
        ),
    ] {
        keyring.insert_account(
            &root,
            storage.into(),
            "synthetic-fixture-server".into(),
            "20000000-0000-4000-8000-000000000001".into(),
            key,
            origin,
        )?;
    }
    let fixture = serde_json::json!({"synthetic_only":true,"password":password,
        "expected_root_base64":STANDARD.encode(root.as_bytes()),
        "expected_account_base64":STANDARD.encode(account.as_bytes()),
        "expected_cache_base64":STANDARD.encode(cache.as_bytes()),"keyring":keyring});
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/crypto/v1_device_keyring.json");
    std::fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(&fixture)?),
    )?;
    Ok(())
}
