use crate::cli_args::*;
use crate::modules::auth::{
    clear_keyring_mock, handle_login_command, handle_logout, load_access_token, load_refresh_token,
    lock_keyring_tests_async, lock_keyring_tests_sync, store_access_token, store_refresh_token,
};
use crate::modules::system::{handle_config_command, CliConfig, CliContext, TokenEntry};
use mockito::{Matcher, Server};
use serde_json::json;
use std::collections::HashMap;

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

#[tokio::test]
async fn login_internal_stores_tokens() {
    let _guard = lock_keyring_tests_async().await;
    clear_keyring_mock();
    let mut server = Server::new_async().await;
    let fingerprint = "sha256:test";

    let info_body = json!({
        "server_fingerprint": fingerprint,
        "auth_methods": []
    });
    server
        .mock("GET", "/v1/system/info")
        .with_status(200)
        .with_body(info_body.to_string())
        .create_async()
        .await;

    let prelogin_body = json!({
        "kdf_salt": "salt",
        "kdf_params": {
            "algorithm": "argon2id",
            "iterations": 2,
            "memory_kb": 65536,
            "parallelism": 1
        },
        "salt_fingerprint": "kdf-1"
    });
    server
        .mock("GET", "/v1/auth/prelogin")
        .match_query(Matcher::UrlEncoded(
            "email".into(),
            "user@example.com".into(),
        ))
        .with_status(200)
        .with_body(prelogin_body.to_string())
        .create_async()
        .await;

    let login_body = json!({
        "access_token": "access-1",
        "refresh_token": "refresh-1",
        "expires_in": 3600
    });
    server
        .mock("POST", "/v1/auth/login")
        .with_status(200)
        .with_body(login_body.to_string())
        .create_async()
        .await;

    let mut config = CliConfig::default();
    config.contexts.insert(
        "ctx-login".to_string(),
        CliContext {
            addr: server.url(),
            needs_salt_update: false,
            server_fingerprint: Some(fingerprint.to_string()),
            tokens: HashMap::new(),
            current_token: None,
            vault: None,
        },
    );
    let client = reqwest::Client::new();
    handle_login_command(
        LoginArgs {
            command: Some(LoginCommand::Internal(LoginInternalArgs {
                email: "user@example.com".to_string(),
                password: Some("pass".to_string()),
                device_name: None,
                device_platform: None,
                context: Some("ctx-login".to_string()),
            })),
        },
        Some(server.url()),
        None,
        true,
        &client,
        &mut config,
    )
    .await
    .expect("login ok");

    let context = config.contexts.get("ctx-login").expect("context");
    assert_eq!(config.current_context.as_deref(), Some("ctx-login"));
    assert_eq!(context.current_token.as_deref(), Some("session"));
    assert_eq!(
        load_access_token("ctx-login", "session")
            .expect("load access")
            .as_deref(),
        Some("access-1")
    );
    assert_eq!(
        load_refresh_token("ctx-login", "session")
            .expect("load refresh")
            .as_deref(),
        Some("refresh-1")
    );
}

#[tokio::test]
async fn logout_removes_tokens() {
    let _guard = lock_keyring_tests_async().await;
    clear_keyring_mock();
    let mut server = Server::new_async().await;
    server
        .mock("POST", "/v1/auth/logout")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let mut config = CliConfig::default();
    let context_name = "ctx-logout";
    let mut context = CliContext {
        addr: server.url(),
        needs_salt_update: false,
        server_fingerprint: None,
        tokens: HashMap::new(),
        current_token: Some("session".to_string()),
        vault: None,
    };
    context.tokens.insert(
        "session".to_string(),
        TokenEntry {
            access_expires_at: None,
        },
    );
    config.contexts.insert(context_name.to_string(), context);
    config.current_context = Some(context_name.to_string());

    store_access_token(context_name, "session", "access-2").expect("store access");
    store_refresh_token(context_name, "session", "refresh-2").expect("store refresh");

    let client = reqwest::Client::new();
    handle_logout(
        LogoutArgs {
            context: Some(context_name.to_string()),
            token_name: None,
        },
        Some(server.url()),
        None,
        true,
        &client,
        &mut config,
    )
    .await
    .expect("logout ok");

    let context = config.contexts.get(context_name).expect("context");
    assert!(context.tokens.is_empty());
    assert!(context.current_token.is_none());
    assert!(load_access_token(context_name, "session")
        .expect("load access")
        .is_none());
    assert!(load_refresh_token(context_name, "session")
        .expect("load refresh")
        .is_none());
}
