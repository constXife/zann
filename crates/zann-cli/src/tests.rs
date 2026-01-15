use crate::cli_args::*;
use crate::modules::auth::{
    clear_keyring_mock, load_access_token, lock_keyring_tests_sync,
};
use crate::modules::system::{handle_config_command, CliConfig};

#[test]
fn config_commands_manage_contexts_and_tokens() {
    let _guard = lock_keyring_tests_sync();
    clear_keyring_mock();
    let mut config = CliConfig::default();

    handle_config_command(
        ConfigArgs {
            command: ConfigCommand::SetContext(SetContextArgs {
                name: "cfg".to_string(),
                addr: Some("https://example.com".to_string()),
                token: Some("token-main".to_string()),
                token_name: Some("main".to_string()),
                vault: Some("vault-1".to_string()),
            }),
        },
        &mut config,
    )
    .expect("set-context");

    let context = config.contexts.get("cfg").expect("context");
    assert_eq!(config.current_context.as_deref(), Some("cfg"));
    assert_eq!(context.current_token.as_deref(), Some("main"));
    assert_eq!(context.vault.as_deref(), Some("vault-1"));
    assert_eq!(
        load_access_token("cfg", "main")
            .expect("load token")
            .as_deref(),
        Some("token-main")
    );

    handle_config_command(
        ConfigArgs {
            command: ConfigCommand::UseContext(UseContextArgs {
                name: "cfg".to_string(),
            }),
        },
        &mut config,
    )
    .expect("use-context");

    handle_config_command(
        ConfigArgs {
            command: ConfigCommand::UseToken(UseTokenArgs {
                name: "main".to_string(),
                context: None,
            }),
        },
        &mut config,
    )
    .expect("use-token");

    handle_config_command(
        ConfigArgs {
            command: ConfigCommand::ListTokens(ListTokensArgs { context: None }),
        },
        &mut config,
    )
    .expect("list-tokens");

    handle_config_command(
        ConfigArgs {
            command: ConfigCommand::ShowToken(ShowTokenArgs {
                name: "main".to_string(),
                show_service_token: false,
                context: None,
            }),
        },
        &mut config,
    )
    .expect("show-token");

    handle_config_command(
        ConfigArgs {
            command: ConfigCommand::CurrentContext,
        },
        &mut config,
    )
    .expect("current-context");

    handle_config_command(
        ConfigArgs {
            command: ConfigCommand::GetContexts,
        },
        &mut config,
    )
    .expect("get-contexts");

    handle_config_command(
        ConfigArgs {
            command: ConfigCommand::RemoveToken(RemoveTokenArgs {
                name: "main".to_string(),
                context: None,
            }),
        },
        &mut config,
    )
    .expect("remove-token");

    let context = config.contexts.get("cfg").expect("context");
    assert!(context.tokens.is_empty());
    assert!(context.current_token.is_none());
}
