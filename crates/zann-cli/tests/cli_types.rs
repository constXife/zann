use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;

fn base_cmd(home: &Path) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("zann-cli"));
    cmd.env("HOME", home)
        .env("ZANN_MASTER_PASSWORD", "test-password");
    cmd
}

#[test]
fn types_lists_builtin_types() {
    let home_dir = tempfile::tempdir().expect("tempdir");
    let home = home_dir.path();

    base_cmd(home)
        .args(["types"])
        .assert()
        .success()
        .stdout(predicate::str::contains("login"))
        .stdout(predicate::str::contains("note"))
        .stdout(predicate::str::contains("card"))
        .stdout(predicate::str::contains("identity"))
        .stdout(predicate::str::contains("api"))
        .stdout(predicate::str::contains("kv"));
}
