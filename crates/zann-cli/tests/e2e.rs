use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn cli_help_includes_usage() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("zann-cli"));

    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage"));
}
