use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn cli_help_includes_usage() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("zann"));

    cmd.env_remove("ZANN_TOKEN")
        .env_remove("ZANN_TOKEN_FILE")
        .env_remove("ZANN_SERVICE_TOKEN")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage"));
}
