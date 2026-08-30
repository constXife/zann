use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn http_requires_insecure_flag() {
    let home_dir = tempfile::tempdir().expect("tempdir");
    let home = home_dir.path();

    Command::new(assert_cmd::cargo::cargo_bin!("zann"))
        .env("HOME", home)
        // See cli_commands.rs: HOME alone does not isolate a test from a
        // developer machine that has Zann configured.
        .env_remove("ZANN_ADDR")
        .env_remove("ZANN_TOKEN_FILE")
        .env_remove("ZANN_SERVER_FINGERPRINT")
        .env_remove("ZANN_SERVICE_TOKEN")
        .args(["server", "info", "http://example.com"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "refusing to use http:// without --insecure",
        ));
}
