use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn http_requires_insecure_flag() {
    let home_dir = tempfile::tempdir().expect("tempdir");
    let home = home_dir.path();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("zann"));
    // See cli_commands.rs: inherited ZANN_* vars otherwise leak into the run.
    for (key, _) in std::env::vars() {
        if key.starts_with("ZANN_") {
            cmd.env_remove(key);
        }
    }
    cmd.env("HOME", home)
        .args(["server", "info", "http://example.com"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "refusing to use http:// without --insecure",
        ));
}
