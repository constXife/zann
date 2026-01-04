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
fn generate_password_default() {
    let home_dir = tempfile::tempdir().expect("tempdir");
    let home = home_dir.path();

    base_cmd(home)
        .args(["generate", "password"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^[A-Za-z0-9!@#$%^&*_\-+=?]{24}$").unwrap());
}

#[test]
fn generate_password_alnum() {
    let home_dir = tempfile::tempdir().expect("tempdir");
    let home = home_dir.path();

    base_cmd(home)
        .args(["generate", "password", "--policy", "alnum"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^[A-Za-z0-9]{24}$").unwrap());
}

#[test]
fn generate_password_invalid_policy() {
    let home_dir = tempfile::tempdir().expect("tempdir");
    let home = home_dir.path();

    base_cmd(home)
        .args(["generate", "password", "--policy", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid policy"));
}
