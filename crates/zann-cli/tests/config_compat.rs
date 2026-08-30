use std::fs;
use std::path::Path;

use assert_cmd::Command;
use serde_json::{json, Value};
use tempfile::TempDir;

fn fixture(name: &str) -> &'static str {
    match name {
        "empty" => include_str!("../../../tests/fixtures/client-config/v1/empty.json"),
        "cli-keyring" => {
            include_str!("../../../tests/fixtures/client-config/v1/cli-keyring.json")
        }
        "desktop-plaintext-future" => {
            include_str!("../../../tests/fixtures/client-config/v1/desktop-plaintext-future.json")
        }
        "local-identity-nullable" => {
            include_str!("../../../tests/fixtures/client-config/v1/local-identity-nullable.json")
        }
        "malformed" => {
            include_str!("../../../tests/fixtures/client-config/v1/malformed.json")
        }
        other => panic!("unknown config fixture: {other}"),
    }
}

fn home_with_fixture(name: &str) -> TempDir {
    let home = tempfile::tempdir().expect("tempdir");
    let config_dir = home.path().join(".zann");
    fs::create_dir_all(&config_dir).expect("create config dir");
    fs::write(config_dir.join("config.json"), fixture(name)).expect("write config fixture");
    home
}

fn zann(home: &Path) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("zann"));
    command
        .env("HOME", home)
        .env_remove("ZANN_TOKEN_FILE")
        .env_remove("ZANN_SERVICE_TOKEN");
    command
}

fn saved_value(home: &TempDir) -> Value {
    let contents =
        fs::read_to_string(home.path().join(".zann/config.json")).expect("read saved config");
    serde_json::from_str(&contents).expect("saved config is JSON")
}

#[test]
fn characterizes_legacy_read_matrix() {
    for readable in [
        "empty",
        "cli-keyring",
        "desktop-plaintext-future",
        "local-identity-nullable",
    ] {
        let home = home_with_fixture(readable);

        zann(home.path())
            .args(["config", "current-context"])
            .assert()
            .success();
    }

    let malformed = home_with_fixture("malformed");
    zann(malformed.path())
        .args(["config", "current-context"])
        .assert()
        .failure();
}

#[test]
fn characterizes_legacy_save_projection() {
    let home = home_with_fixture("desktop-plaintext-future");

    // Every CLI config command writes the whole typed config back, including a
    // read-only command such as current-context.
    zann(home.path())
        .args(["config", "current-context"])
        .assert()
        .success();

    // This captures the current lossy projection explicitly: secrets owned by
    // the desktop/client, desktop storage preferences, and unknown fields are
    // all removed by the CLI writer.
    assert_eq!(
        saved_value(&home),
        json!({
            "current_context": "desktop",
            "contexts": {
                "desktop": {
                    "addr": "https://desktop.example.test",
                    "needs_salt_update": true,
                    "server_fingerprint": "sha256:desktop-server",
                    "tokens": {
                        "session": {
                            "access_expires_at": "2031-02-03T04:05:06Z"
                        }
                    },
                    "current_token": "session",
                    "vault": "vault-cli-only"
                }
            },
            "identity": {
                "email": "desktop@example.test",
                "kdf_salt": "ZGVza3RvcC1maXh0dXJlLXNhbHQ=",
                "kdf_params": {
                    "algorithm": "argon2id",
                    "iterations": 3,
                    "memory_kb": 65536,
                    "parallelism": 4
                },
                "salt_fingerprint": "sha256:desktop-salt",
                "first_seen_at": "2026-02-03T04:05:06Z"
            }
        })
    );
}
