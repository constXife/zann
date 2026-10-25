use super::{
    ensure_file_size, ensure_private_directory, materialize_shared, normalize_output_path,
    publish_delivery_generation, write_atomic_private,
};
use crate::modules::system::{CliState, CommandContext};
use mockito::{Matcher, Server};
use serde_json::json;
use std::path::PathBuf;
use tempfile::tempdir;
use zann_client::delivery::DeliveryPlan;
use zann_client::secrets::{BatchResult, SecretResponse};

#[test]
fn normalize_output_path_allows_simple() {
    let path = normalize_output_path("alpha/one").expect("valid path");
    assert_eq!(path, PathBuf::from("alpha/one"));
}

#[test]
fn normalize_output_path_rejects_traversal() {
    assert!(normalize_output_path("../etc").is_err());
    assert!(normalize_output_path("foo/../bar").is_err());
    assert!(normalize_output_path("foo/.hidden").is_err());
    assert!(normalize_output_path("foo/line\nbreak").is_err());
    assert!(normalize_output_path("/").is_err());
    let path = normalize_output_path("/etc").expect("leading slash normalized");
    assert_eq!(path, PathBuf::from("etc"));
}

#[test]
fn materialized_values_are_bounded() {
    assert!(ensure_file_size(&"x".repeat(super::MAX_MATERIALIZED_FILE_BYTES)).is_ok());
    assert!(ensure_file_size(&"x".repeat(super::MAX_MATERIALIZED_FILE_BYTES + 1)).is_err());
}

#[test]
fn delivery_retention_prunes_only_after_publication() {
    let directory = tempdir().expect("tempdir");
    let out = directory.path().join("delivery");
    let plan = DeliveryPlan::from_yaml(
        "version: 1\nvault: infra\nfiles:\n  - secret: service/password\n    target: password\n",
    )
    .expect("plan");

    let first_results = vec![delivery_result("first")];
    let first = publish_delivery_generation(&out, plan.files(), &first_results, 1, false)
        .expect("first generation");
    assert!(out.join("generations").join(&first).exists());

    let second_results = vec![delivery_result("second")];
    let second = publish_delivery_generation(&out, plan.files(), &second_results, 1, false)
        .expect("second generation");
    assert!(!out.join("generations").join(first).exists());
    assert_eq!(
        std::fs::read_to_string(out.join("current")).expect("current"),
        format!("{second}\n")
    );
    assert_eq!(
        std::fs::read_to_string(out.join("generations").join(second).join("password"))
            .expect("secret"),
        "second"
    );
}

#[test]
fn delivery_can_reuse_an_exact_complete_generation() {
    let directory = tempdir().expect("tempdir");
    let out = directory.path().join("delivery");
    let plan = DeliveryPlan::from_yaml(
        "version: 1\nvault: infra\nfiles:\n  - secret: service/password\n    target: password\n",
    )
    .expect("plan");
    let first_results = vec![delivery_result("same")];
    let first = publish_delivery_generation(&out, plan.files(), &first_results, 2, true)
        .expect("first generation");
    let second_results = vec![delivery_result("same")];
    let second = publish_delivery_generation(&out, plan.files(), &second_results, 2, true)
        .expect("unchanged generation");

    assert_eq!(first, second);
    assert_eq!(
        std::fs::read_dir(out.join("generations"))
            .expect("generations")
            .count(),
        1
    );
}

fn delivery_result(value: &str) -> BatchResult {
    BatchResult {
        path: "service/password".to_string(),
        status: "ok".to_string(),
        secret: Some(SecretResponse {
            item_id: "00000000-0000-0000-0000-000000000001".to_string(),
            path: "/service/password".to_string(),
            vault_id: "infra".to_string(),
            value: value.to_string(),
            policy: "default".to_string(),
            meta: None,
            version: 1,
            previous_version: None,
            created: None,
        }),
        error: None,
    }
}

#[cfg(unix)]
#[test]
fn atomic_writer_replaces_inode_with_private_permissions() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory = tempdir().expect("tempdir");
    let target = directory.path().join("secret");
    std::fs::write(&target, "old").expect("old secret");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).expect("permissions");
    let old_inode = std::fs::metadata(&target).expect("metadata").ino();

    write_atomic_private(&target, b"new").expect("atomic write");

    let metadata = std::fs::metadata(&target).expect("metadata");
    assert_ne!(metadata.ino(), old_inode);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::read_to_string(&target).expect("secret"), "new");
    assert!(std::fs::read_dir(directory.path())
        .expect("directory")
        .all(|entry| !entry
            .expect("entry")
            .file_name()
            .to_string_lossy()
            .starts_with(".zann.tmp.")));
}

#[cfg(unix)]
#[test]
fn writer_and_directory_setup_reject_symlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = tempdir().expect("tempdir");
    let real_file = directory.path().join("real-secret");
    let linked_file = directory.path().join("linked-secret");
    std::fs::write(&real_file, "old").expect("real secret");
    symlink(&real_file, &linked_file).expect("file symlink");

    assert!(write_atomic_private(&linked_file, b"new").is_err());
    assert_eq!(
        std::fs::read_to_string(&real_file).expect("real secret"),
        "old"
    );

    let real_directory = directory.path().join("real-directory");
    let linked_directory = directory.path().join("linked-directory");
    std::fs::create_dir(&real_directory).expect("real directory");
    symlink(&real_directory, &linked_directory).expect("directory symlink");
    assert!(ensure_private_directory(&linked_directory, true).is_err());

    let permissive_directory = directory.path().join("permissive-directory");
    std::fs::create_dir(&permissive_directory).expect("permissive directory");
    std::fs::set_permissions(
        &permissive_directory,
        std::fs::Permissions::from_mode(0o755),
    )
    .expect("permissive mode");
    assert!(ensure_private_directory(&permissive_directory, true).is_err());
    assert_eq!(
        std::fs::metadata(&permissive_directory)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

#[tokio::test]
async fn materialize_writes_files() {
    let mut server = Server::new_async().await;
    let vault_id = "vault-1";
    let list_body = json!({
        "secrets": [{
            "path": "/alpha/one",
            "version": 1,
            "updated_at": "2024-01-01T00:00:00Z"
        }]
    });

    let list_mock = server
        .mock("GET", "/v1/vaults/vault-1/secrets")
        .match_query(Matcher::UrlEncoded("limit".into(), "100".into()))
        .with_status(200)
        .with_body(list_body.to_string())
        .create_async()
        .await;

    let batch_body = json!([{
        "path": "alpha/one",
        "status": "ok",
        "secret": {
            "item_id": "00000000-0000-0000-0000-000000000001",
            "path": "/alpha/one",
            "vault_id": "vault-1",
            "value": "secret",
            "policy": "default",
            "version": 1
        }
    }]);
    let batch_mock = server
        .mock("POST", "/v1/vaults/vault-1/secrets/batch/get")
        .match_body(Matcher::Json(json!({"paths": ["alpha/one"]})))
        .with_status(200)
        .with_body(batch_body.to_string())
        .create_async()
        .await;

    let out_dir = tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(out_dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private output directory");
    }
    let identity = crate::test_support::system_info(crate::test_support::FINGERPRINT);
    let _identity = server
        .mock("GET", "/v1/system/info")
        .with_status(200)
        .with_body(identity.to_string())
        .create_async()
        .await;
    let server_url = server.url();
    let client = zann_client::server::ServerProbe::new(&server_url)
        .await
        .expect("probe")
        .confirm_ephemeral(crate::test_support::FINGERPRINT)
        .expect("trust");
    let config_root = tempdir().expect("config root");
    let (repository, store, client_id) = crate::test_support::configuration(config_root.path());
    let mut config = CliState::from_repository(repository, store, client_id).expect("config");
    let mut ctx = CommandContext {
        client: &client,
        addr: &server_url,
        allow_insecure: true,
        access_token: zeroize::Zeroizing::new("token".to_string()),
        context_name: None,
        token_name: None,
        config: &mut config,
    };
    materialize_shared(
        &mut ctx,
        vault_id,
        None,
        out_dir.path(),
        "value",
        false,
        100,
    )
    .await
    .expect("materialize ok");

    let target = out_dir.path().join("alpha/one");
    let contents = std::fs::read_to_string(target).expect("secret");
    assert_eq!(contents, "secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let directory_mode = std::fs::metadata(out_dir.path().join("alpha"))
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(out_dir.path().join("alpha/one"))
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }
    list_mock.assert_async().await;
    batch_mock.assert_async().await;
}
