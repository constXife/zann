use assert_cmd::Command;
use mockito::{Matcher, Server};
use predicates::prelude::*;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::{tempdir, TempDir};

fn base_cmd(home: &Path) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("zann"));
    cmd.env("HOME", home);
    // Clap reads these, so a developer machine with Zann configured would feed
    // its own server and token into every test. Overriding HOME alone is not
    // isolation.
    for name in [
        "ZANN_ADDR",
        "ZANN_TOKEN_FILE",
        "ZANN_SERVER_FINGERPRINT",
        "ZANN_SERVICE_TOKEN",
    ] {
        cmd.env_remove(name);
    }
    cmd
}

fn authenticated_cmd(home: &Path) -> Command {
    let token_file = home.join("test-token");
    fs::write(&token_file, "token\n").expect("token file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600))
            .expect("private token file");
    }
    let mut cmd = base_cmd(home);
    cmd.arg("--token-file").arg(token_file);
    cmd
}

fn private_tempdir() -> TempDir {
    let directory = tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private tempdir");
    }
    directory
}

#[cfg(unix)]
fn executable_script(directory: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = directory.join(name);
    fs::write(&path, body).expect("hook script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("hook permissions");
    path
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
fn global_token_value_flag_is_rejected_without_echoing_value() {
    let home_dir = tempdir().expect("tempdir");
    let secret = "must-not-appear-in-stderr";

    base_cmd(home_dir.path())
        .args(["--token", secret, "version"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument '--token'"))
        .stderr(predicate::str::contains(secret).not());
}

#[test]
fn context_token_value_flag_is_rejected_without_echoing_value() {
    let home_dir = tempdir().expect("tempdir");
    let secret = "must-not-appear-in-stderr";

    base_cmd(home_dir.path())
        .args(["config", "set-context", "ci", "--token", secret])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument '--token'"))
        .stderr(predicate::str::contains(secret).not());
}

#[test]
fn secret_get_prints_only_the_value_by_default() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    server
        .mock("GET", "/v1/vaults/infra/secrets/services/api/database")
        .match_header("authorization", "Bearer token")
        .with_status(200)
        .with_body(
            json!({
                "item_id": "00000000-0000-0000-0000-000000000001",
                "path": "/services/api/database",
                "vault_id": "vault-id",
                "value": "database-password",
                "policy": "default",
                "version": 3
            })
            .to_string(),
        )
        .create();

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--insecure",
            "secret",
            "get",
            "services/api/database",
            "--vault",
            "infra",
        ])
        .assert()
        .success()
        .stdout(predicate::eq("database-password"));
}

#[test]
fn secret_get_previous_uses_the_explicit_grace_selector() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    server
        .mock("GET", "/v1/vaults/infra/secrets/services/api/database")
        .match_query(Matcher::UrlEncoded("version".into(), "previous".into()))
        .with_status(200)
        .with_body(
            json!({
                "item_id": "00000000-0000-0000-0000-000000000001",
                "path": "/services/api/database",
                "vault_id": "vault-id",
                "value": "previous-password",
                "policy": "default",
                "version": 2
            })
            .to_string(),
        )
        .create();

    authenticated_cmd(home_dir.path())
        .arg("--addr")
        .arg(server.url())
        .arg("--insecure")
        .arg("secret")
        .arg("get")
        .arg("services/api/database")
        .arg("--vault")
        .arg("infra")
        .arg("--previous")
        .assert()
        .success()
        .stdout(predicate::eq("previous-password"));
}

#[test]
fn secret_list_prints_paginated_metadata_without_values() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    server
        .mock("GET", "/v1/vaults/infra/secrets")
        .match_header("authorization", "Bearer token")
        .match_query(Matcher::AllOf(vec![
            Matcher::UrlEncoded("prefix".into(), "services/api".into()),
            Matcher::UrlEncoded("limit".into(), "25".into()),
            Matcher::UrlEncoded("cursor".into(), "opaque|cursor".into()),
        ]))
        .with_status(200)
        .with_body(
            json!({
                "secrets": [{
                    "path": "/services/api/database",
                    "version": 3,
                    "updated_at": "2026-08-29T12:00:00Z",
                    "value": "must-not-be-printed"
                }],
                "next_cursor": "next|cursor"
            })
            .to_string(),
        )
        .create();

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--insecure",
            "secret",
            "list",
            "--vault",
            "infra",
            "--prefix",
            "/services/api/",
            "--limit",
            "25",
            "--cursor",
            "opaque|cursor",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("/services/api/database"))
        .stdout(predicate::str::contains("\"next_cursor\": \"next|cursor\""))
        .stdout(predicate::str::contains("must-not-be-printed").not());
}

#[test]
fn secret_ensure_uses_policy_and_can_print_json() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    server
        .mock("POST", "/v1/vaults/infra/secrets/ensure")
        .match_header("authorization", "Bearer token")
        .match_body(Matcher::Json(json!({
            "path": "services/api/database",
            "policy": "strong",
            "meta": null
        })))
        .with_status(200)
        .with_body(
            json!({
                "item_id": "00000000-0000-0000-0000-000000000001",
                "path": "/services/api/database",
                "vault_id": "vault-id",
                "value": "generated-password",
                "policy": "strong",
                "version": 1,
                "created": true
            })
            .to_string(),
        )
        .create();

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--insecure",
            "secret",
            "ensure",
            "services/api/database",
            "--vault",
            "infra",
            "--policy",
            "strong",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"created\": true"))
        .stdout(predicate::str::contains("generated-password"));
}

#[test]
fn secret_set_reads_the_exact_value_from_a_file() {
    let home_dir = tempdir().expect("tempdir");
    let value_file = home_dir.path().join("new-secret");
    fs::write(&value_file, "line one\nline two\n").expect("secret value file");
    let mut server = Server::new();
    server
        .mock("PUT", "/v1/vaults/infra/secrets/services/api/database")
        .match_header("authorization", "Bearer token")
        .match_body(Matcher::Json(json!({
            "value": "line one\nline two\n",
            "policy": "strong",
            "meta": null
        })))
        .with_status(200)
        .with_body(
            json!({
                "item_id": "00000000-0000-0000-0000-000000000001",
                "path": "/services/api/database",
                "vault_id": "vault-id",
                "value": "line one\nline two\n",
                "policy": "strong",
                "version": 2,
                "created": false
            })
            .to_string(),
        )
        .create();

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--insecure",
            "secret",
            "set",
            "services/api/database",
            "--vault",
            "infra",
            "--value-file",
            value_file.to_str().expect("value file path"),
            "--policy",
            "strong",
        ])
        .assert()
        .success()
        .stdout(predicate::eq("line one\nline two\n"));
}

#[test]
fn secret_set_reads_the_exact_value_from_stdin() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    server
        .mock("PUT", "/v1/vaults/infra/secrets/services/api/key")
        .match_header("authorization", "Bearer token")
        .match_body(Matcher::Json(json!({
            "value": "stdin-secret\n",
            "policy": null,
            "meta": null
        })))
        .with_status(200)
        .with_body(
            json!({
                "item_id": "00000000-0000-0000-0000-000000000001",
                "path": "/services/api/key",
                "vault_id": "vault-id",
                "value": "stdin-secret\n",
                "policy": "default",
                "version": 1,
                "created": true
            })
            .to_string(),
        )
        .create();

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--insecure",
            "secret",
            "set",
            "services/api/key",
            "--vault",
            "infra",
            "--stdin",
        ])
        .write_stdin("stdin-secret\n")
        .assert()
        .success()
        .stdout(predicate::eq("stdin-secret\n"));
}

#[test]
fn secret_set_requires_exactly_one_non_argv_value_source() {
    let home_dir = tempdir().expect("tempdir");
    let value_file = home_dir.path().join("new-secret");
    fs::write(&value_file, "secret").expect("secret value file");

    base_cmd(home_dir.path())
        .args(["secret", "set", "services/api/key", "--vault", "infra"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--value-file"))
        .stderr(predicate::str::contains("--stdin"));

    base_cmd(home_dir.path())
        .args([
            "secret",
            "set",
            "services/api/key",
            "--vault",
            "infra",
            "--stdin",
            "--value-file",
            value_file.to_str().expect("value file path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn secret_rotate_reports_previous_and_new_versions() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    server
        .mock("POST", "/v1/vaults/infra/secrets/rotate")
        .match_header("authorization", "Bearer token")
        .match_body(Matcher::Json(json!({
            "path": "services/api/database",
            "policy": "strong",
            "meta": null
        })))
        .with_status(200)
        .with_body(
            json!({
                "item_id": "00000000-0000-0000-0000-000000000001",
                "path": "/services/api/database",
                "vault_id": "vault-id",
                "value": "rotated-password",
                "policy": "strong",
                "version": 4,
                "previous_version": 3
            })
            .to_string(),
        )
        .create();

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--insecure",
            "secret",
            "rotate",
            "services/api/database",
            "--vault",
            "infra",
            "--policy",
            "strong",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("rotated-password"))
        .stdout(predicate::str::contains("\"version\": 4"))
        .stdout(predicate::str::contains("\"previous_version\": 3"));
}

#[cfg(unix)]
#[test]
fn coordinated_rotation_passes_values_on_stdin_then_commits() {
    let home_dir = tempdir().expect("tempdir");
    let hook_dir = tempdir().expect("hook dir");
    let hook_output = hook_dir.path().join("input.json");
    let hook = executable_script(
        hook_dir.path(),
        "capture-hook",
        "#!/bin/sh\nset -eu\ntest \"${ZANN_SERVICE_TOKEN+x}\" != x\ninput=$(cat)\nprintf '%s' \"$input\" > \"$1\"\n",
    );
    let item_id = "00000000-0000-0000-0000-000000000001";
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
    let mut server = Server::new();
    server
        .mock("GET", "/v1/vaults/infra/secrets/services/api/database")
        .with_status(200)
        .with_body(
            json!({
                "item_id": item_id,
                "path": "/services/api/database",
                "vault_id": "vault-id",
                "value": "previous-password",
                "policy": "database",
                "version": 3
            })
            .to_string(),
        )
        .create();
    server
        .mock(
            "POST",
            "/v1/shared/items/00000000-0000-0000-0000-000000000001/rotate/start",
        )
        .match_body(Matcher::Json(json!({"policy": "database"})))
        .with_status(200)
        .with_body(
            json!({
                "state": "rotating",
                "candidate": "candidate-password",
                "previous_version": 3,
                "expires_at": expires_at,
                "recover_until": null
            })
            .to_string(),
        )
        .create();
    server
        .mock(
            "POST",
            "/v1/shared/items/00000000-0000-0000-0000-000000000001/rotate/commit",
        )
        .with_status(200)
        .with_body(json!({"status": "committed", "version": 4}).to_string())
        .create();

    authenticated_cmd(home_dir.path())
        .env("ZANN_SERVICE_TOKEN", "must-not-reach-hook")
        .arg("--addr")
        .arg(server.url())
        .arg("--insecure")
        .arg("rotate")
        .arg("services/api/database")
        .arg("--vault")
        .arg("infra")
        .arg("--policy")
        .arg("database")
        .arg("--exec")
        .arg(hook)
        .arg("--exec-arg")
        .arg(&hook_output)
        .arg("--timeout-seconds")
        .arg("10")
        .assert()
        .success()
        .stdout(predicate::str::contains("committed version 4"))
        .stdout(predicate::str::contains("candidate-password").not())
        .stderr(predicate::str::contains("previous-password").not());

    let input: serde_json::Value =
        serde_json::from_slice(&fs::read(hook_output).expect("hook input")).expect("hook json");
    assert_eq!(input["previous"], "previous-password");
    assert_eq!(input["candidate"], "candidate-password");
}

#[cfg(unix)]
#[test]
fn coordinated_rotation_aborts_on_hook_failure_without_echoing_values() {
    let home_dir = tempdir().expect("tempdir");
    let hook_dir = tempdir().expect("hook dir");
    let hook = executable_script(
        hook_dir.path(),
        "failing-hook",
        "#!/bin/sh\ncat >/dev/null\nexit 7\n",
    );
    let item_id = "00000000-0000-0000-0000-000000000001";
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
    let mut server = Server::new();
    server
        .mock("GET", "/v1/vaults/infra/secrets/services/api/database")
        .with_status(200)
        .with_body(
            json!({
                "item_id": item_id,
                "path": "/services/api/database",
                "vault_id": "vault-id",
                "value": "previous-password",
                "policy": "database",
                "version": 3
            })
            .to_string(),
        )
        .create();
    server
        .mock(
            "POST",
            "/v1/shared/items/00000000-0000-0000-0000-000000000001/rotate/start",
        )
        .with_status(200)
        .with_body(
            json!({
                "state": "rotating",
                "candidate": "candidate-password",
                "previous_version": 3,
                "expires_at": expires_at,
                "recover_until": null
            })
            .to_string(),
        )
        .create();
    server
        .mock(
            "POST",
            "/v1/shared/items/00000000-0000-0000-0000-000000000001/rotate/abort",
        )
        .match_body(Matcher::Json(json!({
            "reason": "rotation hook exited unsuccessfully",
            "force": false
        })))
        .with_status(200)
        .with_body(
            json!({
                "state": "active",
                "started_at": null,
                "started_by": null,
                "expires_at": null,
                "recover_until": null,
                "aborted_reason": "rotation hook exited unsuccessfully"
            })
            .to_string(),
        )
        .create();

    authenticated_cmd(home_dir.path())
        .arg("--addr")
        .arg(server.url())
        .arg("--insecure")
        .arg("rotate")
        .arg("services/api/database")
        .arg("--vault")
        .arg("infra")
        .arg("--exec")
        .arg(hook)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "rotation hook exited unsuccessfully",
        ))
        .stderr(predicate::str::contains("previous-password").not())
        .stderr(predicate::str::contains("candidate-password").not());
}

#[cfg(unix)]
#[test]
fn coordinated_rotation_keeps_candidate_recoverable_when_commit_fails() {
    let home_dir = tempdir().expect("tempdir");
    let hook_dir = tempdir().expect("hook dir");
    let hook = executable_script(
        hook_dir.path(),
        "successful-hook",
        "#!/bin/sh\ncat >/dev/null\nexit 0\n",
    );
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
    let mut server = Server::new();
    server
        .mock("GET", "/v1/vaults/infra/secrets/services/api/database")
        .with_status(200)
        .with_body(
            json!({
                "item_id": "00000000-0000-0000-0000-000000000001",
                "path": "/services/api/database",
                "vault_id": "vault-id",
                "value": "previous-password",
                "policy": "database",
                "version": 3
            })
            .to_string(),
        )
        .create();
    server
        .mock(
            "POST",
            "/v1/shared/items/00000000-0000-0000-0000-000000000001/rotate/start",
        )
        .with_status(200)
        .with_body(
            json!({
                "state": "rotating",
                "candidate": "candidate-password",
                "previous_version": 3,
                "expires_at": expires_at,
                "recover_until": null
            })
            .to_string(),
        )
        .create();
    server
        .mock(
            "POST",
            "/v1/shared/items/00000000-0000-0000-0000-000000000001/rotate/commit",
        )
        .with_status(503)
        .with_body(r#"{"error":"db_error","detail":"candidate-password"}"#)
        .create();
    let abort = server
        .mock(
            "POST",
            "/v1/shared/items/00000000-0000-0000-0000-000000000001/rotate/abort",
        )
        .expect(0)
        .create();

    authenticated_cmd(home_dir.path())
        .arg("--addr")
        .arg(server.url())
        .arg("--insecure")
        .arg("rotate")
        .arg("services/api/database")
        .arg("--vault")
        .arg("infra")
        .arg("--exec")
        .arg(hook)
        .assert()
        .failure()
        .stderr(predicate::str::contains("rotation remains recoverable"))
        .stderr(predicate::str::contains("candidate-password").not())
        .stderr(predicate::str::contains("previous-password").not());
    abort.assert();
}

#[test]
fn secret_command_does_not_echo_untrusted_error_bodies() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    let sentinel = "must-not-appear-from-server-body";
    server
        .mock("GET", "/v1/vaults/infra/secrets/services/api")
        .with_status(500)
        .with_body(json!({"error": sentinel}).to_string())
        .create();

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--insecure",
            "secret",
            "get",
            "services/api",
            "--vault",
            "infra",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("machine_secrets:get:server"))
        .stderr(predicate::str::contains(sentinel).not());
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

    authenticated_cmd(home_dir.path())
        .args(["--addr", &server.url(), "--insecure", "whoami"])
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

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
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

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
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

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
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
                "item_id": "00000000-0000-0000-0000-000000000001",
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

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
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

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
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

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
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
fn materialize_command_requires_explicit_field() {
    let home_dir = tempdir().expect("tempdir");
    let out_dir = private_tempdir();

    base_cmd(home_dir.path())
        .args([
            "materialize",
            "--vault",
            "vault-1",
            "--out",
            out_dir.path().to_str().expect("path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--field"));
}

#[test]
fn materialize_command_accepts_only_machine_secret_value_field() {
    let home_dir = tempdir().expect("tempdir");
    let out_dir = private_tempdir();

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            "http://127.0.0.1:1",
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
        .failure()
        .stderr(predicate::str::contains(
            "machine-secret materialization requires --field value",
        ));
}

#[test]
fn materialize_command_writes_files() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();

    let list_body = json!({
        "secrets": [{
            "path": "/alpha/one",
            "version": 1,
            "updated_at": "2024-01-01T00:00:00Z"
        }]
    });
    server
        .mock("GET", "/v1/vaults/vault-1/secrets")
        .match_header("authorization", "Bearer token")
        .match_query(Matcher::UrlEncoded("limit".into(), "100".into()))
        .with_status(200)
        .with_body(list_body.to_string())
        .create();

    let batch_body = json!([{
        "path": "alpha/one",
        "status": "ok",
        "secret": {
            "item_id": "00000000-0000-0000-0000-000000000001",
            "path": "/alpha/one",
            "vault_id": "vault-1",
            "value": "secret",
            "policy": "default",
            "version": 1
        }
    }]);
    server
        .mock("POST", "/v1/vaults/vault-1/secrets/batch/get")
        .match_header("authorization", "Bearer token")
        .match_body(Matcher::Json(json!({"paths": ["alpha/one"]})))
        .with_status(200)
        .with_body(batch_body.to_string())
        .create();

    let out_dir = private_tempdir();

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--insecure",
            "materialize",
            "--vault",
            "vault-1",
            "--out",
            out_dir.path().to_str().expect("path"),
            "--field",
            "value",
        ])
        .assert()
        .success();

    let target = out_dir.path().join("alpha/one");
    let contents = fs::read_to_string(target).expect("secret");
    assert_eq!(contents, "secret");
}

#[test]
fn materialize_command_fails_closed_on_partial_batch_error() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();

    let list_body = json!({
        "secrets": [{
            "path": "/alpha/one",
            "version": 1,
            "updated_at": "2024-01-01T00:00:00Z"
        }, {
            "path": "/alpha/two",
            "version": 1,
            "updated_at": "2024-01-01T00:00:01Z"
        }]
    });
    server
        .mock("GET", "/v1/vaults/vault-1/secrets")
        .match_header("authorization", "Bearer token")
        .match_query(Matcher::UrlEncoded("limit".into(), "100".into()))
        .with_status(200)
        .with_body(list_body.to_string())
        .create();

    let batch_body = json!([{
        "path": "alpha/one",
        "status": "ok",
        "secret": {
            "item_id": "00000000-0000-0000-0000-000000000001",
            "path": "/alpha/one",
            "vault_id": "vault-1",
            "value": "secret",
            "policy": "default",
            "version": 1
        }
    }, {
        "path": "alpha/two",
        "status": "error",
        "error": {"error": "not_found"}
    }]);
    server
        .mock("POST", "/v1/vaults/vault-1/secrets/batch/get")
        .match_header("authorization", "Bearer token")
        .match_body(Matcher::Json(json!({
            "paths": ["alpha/one", "alpha/two"]
        })))
        .with_status(200)
        .with_body(batch_body.to_string())
        .create();

    let out_dir = private_tempdir();

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--insecure",
            "materialize",
            "--vault",
            "vault-1",
            "--out",
            out_dir.path().to_str().expect("path"),
            "--field",
            "value",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "one or more machine secrets were unavailable during materialization",
        ));

    assert!(!out_dir.path().join("alpha/one").exists());
    assert!(!out_dir.path().join("alpha/two").exists());
}

#[test]
fn materialize_command_chunks_batch_reads_at_sixty_four() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    let paths = (0..65)
        .map(|index| format!("batch/item-{index:03}"))
        .collect::<Vec<_>>();
    let summaries = paths
        .iter()
        .map(|path| {
            json!({
                "path": format!("/{path}"),
                "version": 1,
                "updated_at": "2024-01-01T00:00:00Z"
            })
        })
        .collect::<Vec<_>>();
    server
        .mock("GET", "/v1/vaults/vault-1/secrets")
        .match_header("authorization", "Bearer token")
        .match_query(Matcher::UrlEncoded("limit".into(), "100".into()))
        .with_status(200)
        .with_body(json!({"secrets": summaries}).to_string())
        .create();

    for chunk in paths.chunks(64) {
        let response = chunk
            .iter()
            .enumerate()
            .map(|(index, path)| {
                json!({
                    "path": path,
                    "status": "ok",
                    "secret": {
                        "item_id": "00000000-0000-0000-0000-000000000001",
                        "path": format!("/{path}"),
                        "vault_id": "vault-1",
                        "value": format!("secret-{index}"),
                        "policy": "default",
                        "version": 1
                    }
                })
            })
            .collect::<Vec<_>>();
        server
            .mock("POST", "/v1/vaults/vault-1/secrets/batch/get")
            .match_header("authorization", "Bearer token")
            .match_body(Matcher::Json(json!({"paths": chunk})))
            .with_status(200)
            .with_body(serde_json::to_string(&response).expect("batch response"))
            .expect(1)
            .create();
    }

    let out_dir = private_tempdir();
    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
            "--insecure",
            "materialize",
            "--vault",
            "vault-1",
            "--out",
            out_dir.path().to_str().expect("path"),
            "--field",
            "value",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read_to_string(out_dir.path().join("batch/item-000")).expect("first secret"),
        "secret-0"
    );
    assert_eq!(
        fs::read_to_string(out_dir.path().join("batch/item-064")).expect("last secret"),
        "secret-0"
    );
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

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
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

    authenticated_cmd(home_dir.path())
        .args([
            "--addr",
            &server.url(),
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
