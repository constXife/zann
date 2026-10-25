use assert_cmd::Command;
use std::fs;

fn run(home: &std::path::Path) -> assert_cmd::assert::Assert {
    Command::new(assert_cmd::cargo::cargo_bin!("zann"))
        .env("HOME", home)
        .env_remove("ZANN_TOKEN_FILE")
        .env_remove("ZANN_SERVICE_TOKEN")
        .args(["config", "current-context"])
        .assert()
}
#[test]
fn cli_migrates_legacy_metadata_without_rewriting_its_source() {
    for fixture in [
        include_bytes!("../../../tests/fixtures/client-config/v1/empty.json").as_slice(),
        include_bytes!("../../../tests/fixtures/client-config/v1/local-identity-nullable.json")
            .as_slice(),
    ] {
        let home = tempfile::tempdir().expect("home");
        let root = home.path().join(".zann");
        fs::create_dir(&root).expect("root");
        let source = root.join("config.json");
        fs::write(&source, fixture).expect("legacy metadata");
        run(home.path()).success();
        assert_eq!(fs::read(&source).expect("source"), fixture);
        let config: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("client-config.json")).expect("v2"))
                .expect("JSON");
        assert_eq!(config["schema_version"], 2);
    }
}
#[test]
fn malformed_legacy_config_fails_without_a_new_writer() {
    let home = tempfile::tempdir().expect("home");
    let root = home.path().join(".zann");
    fs::create_dir(&root).expect("root");
    let input = include_bytes!("../../../tests/fixtures/client-config/v1/malformed.json");
    fs::write(root.join("config.json"), input).expect("legacy");
    run(home.path()).failure();
    assert!(!root.join("client-config.json").exists());
    assert_eq!(fs::read(root.join("config.json")).expect("source"), input);
}
