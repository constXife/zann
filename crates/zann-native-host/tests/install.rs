use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

#[test]
fn manifests_are_scoped_private_and_installation_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("client's vault");
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    for browser in ["chromium", "firefox"] {
        let destination = dir.path().join(browser);
        fs::create_dir(&destination).unwrap();
        let id = if browser == "chromium" {
            "abcdefghijklmnopabcdefghijklmnop"
        } else {
            "zann@example.test"
        };
        zann_native_host::install(&root, &destination, browser, id).unwrap();
        zann_native_host::install(&root, &destination, browser, id).unwrap();
        let path = destination.join("com.rlyeh.zann.json");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if browser == "chromium" {
            assert_eq!(
                manifest["allowed_origins"],
                serde_json::json!([format!("chrome-extension://{id}/")])
            );
            assert!(manifest.get("allowed_extensions").is_none());
        } else {
            assert_eq!(manifest["allowed_extensions"], serde_json::json!([id]));
        }
        let wrapper = std::path::Path::new(manifest["path"].as_str().unwrap());
        assert_eq!(
            fs::metadata(wrapper).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(fs::read_to_string(wrapper).unwrap().contains("'\\''"));
        assert!(zann_native_host::install(&root, &destination, browser, "*").is_err());
        fs::write(&path, b"operator-owned content").unwrap();
        assert!(zann_native_host::install(&root, &destination, browser, id).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"operator-owned content");
    }
}
