use std::collections::HashMap;
use std::fs;

use tempfile::tempdir;
use zann_client::config::save_config;
use zann_client::constants::CONFIG_FILENAME;
use zann_client::state::{CliConfig, CliContext, IdentityConfig, TokenEntry};
use zann_core::api::auth::KdfParams;

#[test]
fn save_config_preserves_identity_when_missing() {
    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join(CONFIG_FILENAME);

    let identity = IdentityConfig {
        kdf_salt: "salt".to_string(),
        kdf_params: KdfParams {
            algorithm: "argon2id".to_string(),
            iterations: 3,
            memory_kb: 65536,
            parallelism: 4,
        },
        salt_fingerprint: Some("sha256:abc".to_string()),
        first_seen_at: Some("2026-01-31T00:00:00Z".to_string()),
        email: Some("test@example.com".to_string()),
    };

    let initial_config = CliConfig {
        current_context: Some("old".to_string()),
        contexts: HashMap::new(),
        identity: Some(identity.clone()),
    };

    let initial_contents = serde_json::to_string_pretty(&initial_config).expect("serialize initial");
    fs::write(&config_path, initial_contents).expect("write initial config");

    let mut contexts = HashMap::new();
    contexts.insert(
        "new".to_string(),
        CliContext {
            addr: "http://localhost:8080".to_string(),
            needs_salt_update: false,
            server_id: Some("server-id".to_string()),
            server_fingerprint: Some("fp".to_string()),
            expected_master_key_fp: None,
            tokens: HashMap::from([(
                "session".to_string(),
                TokenEntry {
                    access_token: "token".to_string(),
                    refresh_token: Some("refresh".to_string()),
                    access_expires_at: Some("2026-01-31T00:00:00Z".to_string()),
                    service_account_token: None,
                },
            )]),
            current_token: Some("session".to_string()),
            storage_id: Some("storage".to_string()),
        },
    );

    let updated_config = CliConfig {
        current_context: Some("new".to_string()),
        contexts,
        identity: None,
    };

    save_config(dir.path(), &updated_config).expect("save config");

    let saved_contents = fs::read_to_string(&config_path).expect("read saved config");
    let saved: CliConfig = serde_json::from_str(&saved_contents).expect("deserialize saved config");

    assert_eq!(saved.current_context.as_deref(), Some("new"));
    assert!(saved.contexts.contains_key("new"));
    let saved_identity = saved.identity.expect("identity preserved");
    assert_eq!(saved_identity.kdf_salt, identity.kdf_salt);
    assert_eq!(saved_identity.kdf_params.algorithm, identity.kdf_params.algorithm);
    assert_eq!(saved_identity.kdf_params.iterations, identity.kdf_params.iterations);
    assert_eq!(saved_identity.kdf_params.memory_kb, identity.kdf_params.memory_kb);
    assert_eq!(saved_identity.kdf_params.parallelism, identity.kdf_params.parallelism);
    assert_eq!(saved_identity.salt_fingerprint, identity.salt_fingerprint);
    assert_eq!(saved_identity.first_seen_at, identity.first_seen_at);
    assert_eq!(saved_identity.email, identity.email);
}
