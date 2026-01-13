use assert_cmd::Command;
use mockito::{Matcher, Server};
use predicates::prelude::*;
use serde_json::json;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn base_cmd(home: &Path) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("zann-cli"));
    cmd.env("HOME", home);
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

#[test]
fn server_info_command_fetches_info() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();

    let info_body = json!({
        "server_fingerprint": "sha256:test",
        "auth_methods": []
    });
    server
        .mock("GET", "/v1/system/info")
        .with_status(200)
        .with_body(info_body.to_string())
        .create();

    base_cmd(home_dir.path())
        .args(["--addr", &server.url(), "--insecure", "server", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("server_fingerprint"));
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
        .mock("GET", "/v1/vaults/vault-1/items/00000000-0000-0000-0000-000000000001")
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
        .mock("GET", "/v1/vaults/vault-1/items/00000000-0000-0000-0000-000000000001")
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
fn run_command_passes_secret_to_process() {
    let home_dir = tempdir().expect("tempdir");
    let mut server = Server::new();
    let item_id = "00000000-0000-0000-0000-000000000001";

    let info_body = json!({
        "server_fingerprint": "sha256:run",
        "auth_methods": []
    });
    server
        .mock("GET", "/v1/system/info")
        .with_status(200)
        .with_body(info_body.to_string())
        .create();

    let auth_body = json!({
        "access_token": "access-1",
        "expires_in": 3600
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
