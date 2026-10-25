use crate::cli_args::*;
use crate::modules::system::{handle_config_command, CliState};
use crate::test_support::configuration;
use zann_client::config::{CredentialKind, CredentialStore};

#[test]
fn config_commands_share_the_v2_writer_and_credential_store() {
    let root = tempfile::tempdir().expect("tempdir");
    let (repository, store, client) = configuration(root.path());
    let mut state = CliState::from_repository(repository, store.clone(), client).expect("state");
    let token_file = root.path().join("token");
    std::fs::write(&token_file, "test-bearer\n").expect("token file");
    handle_config_command(
        ConfigArgs {
            command: ConfigCommand::SetContext(SetContextArgs {
                name: "ci".into(),
                addr: Some("https://example.com".into()),
                token_file: Some(token_file.display().to_string()),
                token_name: Some("main".into()),
                vault: Some("shared".into()),
            }),
        },
        &mut state,
    )
    .expect("configure");
    let context = state.context("ci").expect("context");
    assert_eq!(context.current_token.as_deref(), Some("main"));
    assert_eq!(context.vault.as_deref(), Some("shared"));
    let id = context.id.clone();
    let snapshot = state.repository.snapshot().expect("snapshot");
    let credential_id = &snapshot.config().connections[&id].credential_profiles()["main"]
        .credentials()[&CredentialKind::Access];
    assert_eq!(
        store
            .get(credential_id)
            .expect("stored")
            .expect("secret")
            .expose_secret(),
        "test-bearer"
    );
    let bytes = std::fs::read_to_string(root.path().join("client-config.json")).expect("v2");
    assert!(!bytes.contains("test-bearer"));
    assert!(!root.path().join("config.json").exists());
    handle_config_command(
        ConfigArgs {
            command: ConfigCommand::UseToken(UseTokenArgs {
                name: "main".into(),
                context: None,
            }),
        },
        &mut state,
    )
    .expect("select profile");
    assert!(state
        .repository
        .set_active_credential_profile(
            state.repository.snapshot().expect("snapshot").revision(),
            &id,
            "missing"
        )
        .is_err());
    handle_config_command(
        ConfigArgs {
            command: ConfigCommand::RemoveToken(RemoveTokenArgs {
                name: "main".into(),
                context: None,
            }),
        },
        &mut state,
    )
    .expect("remove profile");
    assert!(state.context("ci").expect("context").tokens.is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(root.path().join("client-config.json"))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
