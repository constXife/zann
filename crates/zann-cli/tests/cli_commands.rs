use assert_cmd::Command;
use mockito::{Matcher, Server};
use predicates::prelude::*;
use serde_json::json;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn base_cmd(home: &Path) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("zann"));
    cmd.env("HOME", home);
    // Clap reads these, so a developer machine with Zann configured would feed
    // its own server and token into every test. Overriding HOME alone is not
    // isolation.
    for name in [
        "ZANN_ADDR",
        "ZANN_TOKEN",
        "ZANN_TOKEN_FILE",
        "ZANN_SERVER_FINGERPRINT",
        "ZANN_SERVICE_TOKEN",
    ] {
        cmd.env_remove(name);
    }
    cmd
}

fn shared_payload(value: &str) -> serde_json::Value {
    json!({
        "v": 1,
        "typeId": "kv",
        "fields": {
            "password": {
                "kind": "password",
                "value": value
            }
        }
    })
}

fn legacy_secret_payload(value: &str) -> serde_json::Value {
    json!({
        "value": value,
        "policy": "default"
    })
}

fn system_info_body(server_fingerprint: &str) -> serde_json::Value {
    json!({
        "version": "1.0.0",
        "build_commit": null,
        "server_id": "server-id",
        "identity": {
            "public_key": "public-key",
            "timestamp": 1_700_000_000,
            "signature": "signature"
        },
        "server_name": "Test server",
        "server_fingerprint": server_fingerprint,
        "auth_methods": [1, 99],
        "personal_vaults_enabled": true,
        "internal_users_present": true,
        "future_metadata": {"accepted": true}
    })
}

#[test]
fn server_info_command_fetches_info() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();

    let info_body = system_info_body("sha256:test");
    server
        .mock("GET", "/v1/system/info")
        .with_status(200)
        .with_body(info_body.to_string())
        .create();

    base_cmd(home_dir.path())
        .args(["--addr", &server.url(), "--insecure", "server", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("server_fingerprint"))
        .stdout(predicate::str::contains("\"version\": \"1.0.0\""))
        .stdout(predicate::str::contains("99"));
}

#[test]
fn whoami_command_uses_access_token() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();

    let whoami_body = json!({
        "id": "user-1",
        "email": "user@example.com"
    });
    server
        .mock("GET", "/v1/users/me")
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(whoami_body.to_string())
        .create();

    base_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--token",
            "token",
            "--insecure",
            "whoami",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("user@example.com"));
}

#[test]
fn list_command_returns_items() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();

    let list_body = json!({
        "items": [{
            "id": "00000000-0000-0000-0000-000000000001",
            "path": "alpha/one",
            "updated_at": "2024-01-01T00:00:00Z"
        }]
    });
    server
        .mock("GET", "/v1/vaults/vault-1/items")
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(list_body.to_string())
        .create();

    let item_body = json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "path": "alpha/one",
        "payload": shared_payload("secret")
    });
    server
        .mock(
            "GET",
            "/v1/vaults/vault-1/items/00000000-0000-0000-0000-000000000001",
        )
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(item_body.to_string())
        .create();

    base_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--token",
            "token",
            "--insecure",
            "list",
            "--vault",
            "vault-1",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("alpha/one"));
}

#[test]
fn get_command_returns_payload() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    let item_id = "00000000-0000-0000-0000-000000000001";

    let payload = shared_payload("secret");
    let list_body = json!({
        "items": [{
            "id": item_id,
            "path": "alpha/one",
            "updated_at": "2024-01-01T00:00:00Z"
        }]
    });
    server
        .mock("GET", "/v1/vaults/vault-1/items")
        .match_query(Matcher::UrlEncoded("prefix".into(), "alpha/one".into()))
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(list_body.to_string())
        .create();

    let item_body = json!({
        "id": item_id,
        "path": "alpha/one",
        "payload": payload
    });
    let item_path = format!("/v1/vaults/vault-1/items/{item_id}");
    server
        .mock("GET", item_path.as_str())
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(item_body.to_string())
        .create();

    base_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--token",
            "token",
            "--insecure",
            "get",
            "alpha/one",
            "--vault",
            "vault-1",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"password\""))
        .stdout(predicate::str::contains("secret"));
}

#[test]
fn get_command_supports_legacy_secret_payload_shape() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    let item_id = "00000000-0000-0000-0000-000000000001";

    let list_body = json!({
        "items": [{
            "id": item_id,
            "path": "/alpha/one",
            "updated_at": "2024-01-01T00:00:00Z"
        }]
    });
    server
        .mock("GET", "/v1/vaults/vault-1/items")
        .match_query(Matcher::UrlEncoded("prefix".into(), "alpha/one".into()))
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(list_body.to_string())
        .create();

    let item_body = json!({
        "id": item_id,
        "path": "/alpha/one",
        "payload": legacy_secret_payload("secret")
    });
    let item_path = format!("/v1/vaults/vault-1/items/{item_id}");
    server
        .mock("GET", item_path.as_str())
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(item_body.to_string())
        .create();

    base_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--token",
            "token",
            "--insecure",
            "get",
            "alpha/one",
            "password",
            "--vault",
            "vault-1",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret"));
}

#[test]
fn set_password_command_uses_secret_endpoint() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();

    server
        .mock("PUT", "/v1/vaults/vault-1/secrets/alpha/one")
        .match_header("authorization", "Bearer token")
        .match_body(Matcher::Json(json!({ "value": "secret-value" })))
        .with_status(200)
        .with_body(
            json!({
                "path": "/alpha/one",
                "vault_id": "vault-1",
                "value": "secret-value",
                "policy": "default",
                "version": 1,
                "created": true
            })
            .to_string(),
        )
        .create();

    base_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--token",
            "token",
            "--insecure",
            "set",
            "alpha/one",
            "password",
            "secret-value",
            "--vault",
            "vault-1",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Updated: alpha/one field 'password'",
        ));
}

#[test]
fn list_command_supports_legacy_secret_payload_shape() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();

    let list_body = json!({
        "items": [{
            "id": "00000000-0000-0000-0000-000000000001",
            "path": "/alpha/one",
            "updated_at": "2024-01-01T00:00:00Z"
        }]
    });
    server
        .mock("GET", "/v1/vaults/vault-1/items")
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(list_body.to_string())
        .create();

    let item_body = json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "path": "/alpha/one",
        "payload": legacy_secret_payload("secret")
    });
    server
        .mock(
            "GET",
            "/v1/vaults/vault-1/items/00000000-0000-0000-0000-000000000001",
        )
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(item_body.to_string())
        .create();

    base_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--token",
            "token",
            "--insecure",
            "list",
            "--vault",
            "vault-1",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("/alpha/one"))
        .stdout(predicate::str::contains("\"password\""))
        .stdout(predicate::str::contains("secret"));
}

#[test]
fn set_non_password_command_uses_shared_item_flow() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();

    server
        .mock("GET", "/v1/vaults/vault-1/items")
        .match_query(Matcher::UrlEncoded("prefix".into(), "alpha/one".into()))
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(json!({ "items": [] }).to_string())
        .create();

    server
        .mock("POST", "/v1/shared/items")
        .match_header("authorization", "Bearer token")
        .match_body(Matcher::Json(json!({
            "vault_id": "vault-1",
            "path": "alpha/one",
            "type_id": "secret",
            "payload": {
                "v": 1,
                "typeId": "secret",
                "fields": {
                    "username": {
                        "kind": "text",
                        "value": "alice"
                    }
                }
            }
        })))
        .with_status(200)
        .with_body(
            json!({
                "id": "00000000-0000-0000-0000-000000000010",
                "path": "alpha/one"
            })
            .to_string(),
        )
        .create();

    base_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--token",
            "token",
            "--insecure",
            "set",
            "alpha/one",
            "username",
            "alice",
            "--vault",
            "vault-1",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Created: alpha/one with field 'username'",
        ));
}

#[test]
fn materialize_command_writes_files() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();

    let list_body = json!({
        "items": [{
            "id": "00000000-0000-0000-0000-000000000001",
            "path": "alpha/one",
            "updated_at": "2024-01-01T00:00:00Z"
        }]
    });
    server
        .mock("GET", "/v1/vaults/vault-1/items")
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(list_body.to_string())
        .create();

    let item_body = json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "path": "alpha/one",
        "payload": shared_payload("secret")
    });
    server
        .mock(
            "GET",
            "/v1/vaults/vault-1/items/00000000-0000-0000-0000-000000000001",
        )
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(item_body.to_string())
        .create();

    let out_dir = tempdir().expect("tempdir");

    base_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--token",
            "token",
            "--insecure",
            "materialize",
            "--vault",
            "vault-1",
            "--out",
            out_dir.path().to_str().expect("path"),
            "--field",
            "password",
        ])
        .assert()
        .success();

    let target = out_dir.path().join("alpha/one");
    let contents = fs::read_to_string(target).expect("secret");
    assert_eq!(contents, "secret");
}

#[test]
fn materialize_command_supports_legacy_secret_payload_shape() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();

    let list_body = json!({
        "items": [{
            "id": "00000000-0000-0000-0000-000000000001",
            "path": "/alpha/one",
            "updated_at": "2024-01-01T00:00:00Z"
        }]
    });
    server
        .mock("GET", "/v1/vaults/vault-1/items")
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(list_body.to_string())
        .create();

    let item_body = json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "path": "/alpha/one",
        "payload": legacy_secret_payload("secret")
    });
    server
        .mock(
            "GET",
            "/v1/vaults/vault-1/items/00000000-0000-0000-0000-000000000001",
        )
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(item_body.to_string())
        .create();

    let out_dir = tempdir().expect("tempdir");

    base_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--token",
            "token",
            "--insecure",
            "materialize",
            "--vault",
            "vault-1",
            "--out",
            out_dir.path().to_str().expect("path"),
            "--field",
            "password",
        ])
        .assert()
        .success();

    let target = out_dir.path().join("alpha/one");
    let contents = fs::read_to_string(target).expect("secret");
    assert_eq!(contents, "secret");
}

#[test]
fn render_command_renders_template() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    let item_id = "00000000-0000-0000-0000-000000000001";

    let list_body = json!({
        "items": [{
            "id": item_id,
            "path": "alpha/one",
            "updated_at": "2024-01-01T00:00:00Z"
        }]
    });
    server
        .mock("GET", "/v1/vaults/vault-1/items")
        .match_query(Matcher::UrlEncoded("prefix".into(), "alpha/one".into()))
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(list_body.to_string())
        .create();

    let item_body = json!({
        "id": item_id,
        "path": "alpha/one",
        "payload": shared_payload("secret")
    });
    let item_path = format!("/v1/vaults/vault-1/items/{item_id}");
    server
        .mock("GET", item_path.as_str())
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(item_body.to_string())
        .create();

    let template_dir = tempdir().expect("tempdir");
    let template_path = template_dir.path().join("template.txt");
    fs::write(&template_path, "db={{ alpha/one#password }}").expect("template");

    let out_path = template_dir.path().join("out.txt");

    base_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--token",
            "token",
            "--insecure",
            "render",
            "--vault",
            "vault-1",
            "--template",
            template_path.to_str().expect("template"),
            "--out",
            out_path.to_str().expect("out"),
        ])
        .assert()
        .success();

    let contents = fs::read_to_string(out_path).expect("output");
    assert_eq!(contents, "db=secret");
}

#[test]
fn render_command_supports_legacy_secret_payload_shape() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    let item_id = "00000000-0000-0000-0000-000000000001";

    let list_body = json!({
        "items": [{
            "id": item_id,
            "path": "/alpha/one",
            "updated_at": "2024-01-01T00:00:00Z"
        }]
    });
    server
        .mock("GET", "/v1/vaults/vault-1/items")
        .match_query(Matcher::UrlEncoded("prefix".into(), "alpha/one".into()))
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(list_body.to_string())
        .create();

    let item_body = json!({
        "id": item_id,
        "path": "/alpha/one",
        "payload": legacy_secret_payload("secret")
    });
    let item_path = format!("/v1/vaults/vault-1/items/{item_id}");
    server
        .mock("GET", item_path.as_str())
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(item_body.to_string())
        .create();

    let template_dir = tempdir().expect("tempdir");
    let template_path = template_dir.path().join("template.txt");
    fs::write(&template_path, "db={{ alpha/one#password }}").expect("template");

    let out_path = template_dir.path().join("out.txt");

    base_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--token",
            "token",
            "--insecure",
            "render",
            "--vault",
            "vault-1",
            "--template",
            template_path.to_str().expect("template"),
            "--out",
            out_path.to_str().expect("out"),
        ])
        .assert()
        .success();

    let contents = fs::read_to_string(out_path).expect("output");
    assert_eq!(contents, "db=secret");
}

#[test]
fn run_command_passes_secret_to_process() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    let item_id = "00000000-0000-0000-0000-000000000001";

    let info_body = system_info_body("sha256:run");
    server
        .mock("GET", "/v1/system/info")
        .with_status(200)
        .with_body(info_body.to_string())
        .create();

    let auth_body = json!({
        "service_account_id": "service-1",
        "owner_user_id": "owner-1",
        "access_token": "access-1",
        "expires_in": 3600,
        "vault_keys": []
    });
    server
        .mock("POST", "/v1/auth/service-account")
        .match_body(Matcher::Json(json!({ "token": "zann_sa_test" })))
        .with_status(200)
        .with_body(auth_body.to_string())
        .create();

    let list_body = json!({
        "items": [{
            "id": item_id,
            "path": "alpha/one",
            "updated_at": "2024-01-01T00:00:00Z"
        }]
    });
    server
        .mock("GET", "/v1/vaults/vault-1/items")
        .match_query(Matcher::UrlEncoded("prefix".into(), "alpha/one".into()))
        .match_header("authorization", "Bearer access-1")
        .with_status(200)
        .with_body(list_body.to_string())
        .create();

    let item_body = json!({
        "id": item_id,
        "path": "alpha/one",
        "payload": shared_payload("secret")
    });
    let item_path = format!("/v1/vaults/vault-1/items/{item_id}");
    server
        .mock("GET", item_path.as_str())
        .match_header("authorization", "Bearer access-1")
        .with_status(200)
        .with_body(item_body.to_string())
        .create();

    base_cmd(home_dir.path())
        .env("ZANN_SERVICE_TOKEN", "zann_sa_test")
        .env("ZANN_SERVER_FINGERPRINT", "sha256:run")
        .args([
            "--addr",
            &server.url(),
            "--insecure",
            "run",
            "--vault",
            "vault-1",
            "alpha/one",
            "--",
            "sh",
            "-c",
            "test \"$password\" = \"secret\"",
        ])
        .assert()
        .success();
}

/// `zann-ffi` writes `email` and `salt_fingerprint` as null when it creates an
/// identity before any account exists. The CLI used to demand strings there, so
/// a `config.json` written by the desktop or COSMIC client made every command
/// fail with `invalid type: null, expected a string`.
#[test]
fn reads_a_config_written_by_the_facade() {
    let home_dir = tempdir().expect("tempdir");
    let home = home_dir.path();
    let zann_dir = home.join(".zann");
    fs::create_dir_all(&zann_dir).expect("create .zann");
    fs::write(
        zann_dir.join("config.json"),
        serde_json::to_string_pretty(&json!({
            "identity": {
                "kdf_salt": "c2FsdA==",
                "kdf_params": {
                    "algorithm": "argon2id",
                    "iterations": 3,
                    "memory_kb": 65536,
                    "parallelism": 4
                },
                "salt_fingerprint": null,
                "first_seen_at": null,
                "email": null
            }
        }))
        .expect("render config"),
    )
    .expect("write config");

    base_cmd(home)
        .args(["config", "current-context"])
        .assert()
        .success();
}
