use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn http_requires_insecure_flag() {
    let home_dir = tempfile::tempdir().expect("tempdir");
    let home = home_dir.path();

    Command::new(assert_cmd::cargo::cargo_bin!("zann-cli"))
        .env("HOME", home)
        .args(["server", "info", "http://example.com"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "refusing to use http:// without --insecure",
        ));
}
