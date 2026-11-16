use assert_cmd::Command;
#[test]
fn offline_conversion_accepts_relative_private_output_without_context_or_home() {
    let dir = tempfile::tempdir().unwrap();
    let input = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/passkey-exchange/bitwarden.json");
    let result = Command::new(assert_cmd::cargo::cargo_bin!("zann"))
        .current_dir(dir.path())
        .env_remove("HOME")
        .env_remove("ZANN_TOKEN_FILE")
        .args([
            "passkey",
            "--format",
            "bitwarden",
            "--input",
            input.to_str().unwrap(),
            "--output",
            "portable.json",
            "--accept-plaintext",
            "--account-id",
            "00112233-4455-6677-8899-aabbccddeeff",
            "--username",
            "synthetic",
            "--email",
            "synthetic@example.test",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&result.get_output().stdout);
    assert!(stdout.contains("Converted 1"));
    assert!(!stdout.contains("synthetic-login-secret"));
    let file = dir.path().join("portable.json");
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(
        value["accounts"][0]["items"][0]["credentials"][0]["type"],
        "passkey"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
#[test]
fn missing_plaintext_acknowledgment_does_not_touch_output() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("output.json");
    Command::new(assert_cmd::cargo::cargo_bin!("zann"))
        .args([
            "passkey",
            "--format",
            "cxf",
            "--input",
            "missing.json",
            "--output",
            file.to_str().unwrap(),
            "--account-id",
            "00112233-4455-6677-8899-aabbccddeeff",
            "--username",
            "synthetic",
            "--email",
            "synthetic@example.test",
        ])
        .assert()
        .failure();
    assert!(!file.exists());
}
