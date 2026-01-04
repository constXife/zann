use clap::Parser;
use std::io::{self, Write};
use zann_core::{EncryptedPayload, FieldValue};

mod cli_args;
mod cli_command;
mod modules;

use crate::cli_args::*;
use crate::cli_command::handle_command;
use crate::modules::auth::{
    ensure_access_token, exchange_service_account_token, verify_server_fingerprint,
};
use crate::modules::auth::{handle_login_command, handle_logout};
use crate::modules::system::http::fetch_system_info;
use crate::modules::system::CommandContext;
use crate::modules::system::{handle_config_command, load_config, save_config};
use crate::modules::system::{handle_run_command, handle_server_command, handle_types_command};
use tracing_subscriber::EnvFilter;

pub(crate) const DEFAULT_ADDR: &str = "https://127.0.0.1:8080";
pub(crate) const REFRESH_SKEW_SECONDS: i64 = 30;
pub(crate) const TOKEN_SESSION: &str = "session";
pub(crate) const TOKEN_OIDC: &str = "oidc";
pub(crate) const TOKEN_MANUAL: &str = "manual";
pub(crate) const SERVER_FINGERPRINT_ENV: &str = "ZANN_SERVER_FINGERPRINT";
const SERVER_URL_ENV: &str = "ZANN_SERVER_URL";
const SERVICE_TOKEN_ENV: &str = "ZANN_SERVICE_TOKEN";
pub(crate) const SERVICE_ACCOUNT_PREFIX: &str = "zann_sa_";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose)?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(cli.insecure)
        .build()?;
    let mut config = load_config()?;
    if cli.token.is_some() && cli.token_file.is_some() {
        anyhow::bail!("use --token or --token-file, not both");
    }
    let mut addr_arg = cli.addr.clone();
    if addr_arg.is_none() {
        addr_arg = std::env::var(SERVER_URL_ENV)
            .ok()
            .or_else(|| std::env::var("ZANN_SERVER").ok());
    }
    let mut token_arg = cli.token.clone();
    if token_arg.is_none() {
        token_arg = cli.token_file.as_deref().map(read_token_file).transpose()?;
    }
    if token_arg.is_none() {
        token_arg = std::env::var(SERVICE_TOKEN_ENV).ok();
    }
    let context_arg = cli.context.clone();
    let token_name_arg = cli.token_name.clone();
    let command = cli.command;

    match command {
        Command::Config(args) => {
            handle_config_command(args, &mut config)?;
            save_config(&config)?;
        }
        Command::Login(args) => {
            handle_login_command(
                args,
                addr_arg,
                context_arg,
                cli.insecure,
                &client,
                &mut config,
            )
            .await?;
            save_config(&config)?;
        }
        Command::Logout(args) => {
            handle_logout(
                args,
                addr_arg,
                context_arg,
                cli.insecure,
                &client,
                &mut config,
            )
            .await?;
            save_config(&config)?;
        }
        Command::Server(args) => {
            handle_server_command(args, addr_arg, context_arg, cli.insecure, &client, &config)
                .await?;
        }
        Command::Run(args) => {
            handle_run_command(
                args,
                addr_arg,
                token_arg,
                token_name_arg,
                context_arg,
                cli.insecure,
                &client,
                &mut config,
            )
            .await?;
            save_config(&config)?;
        }
        Command::Types(_args) => {
            handle_types_command();
        }
        command => {
            let context_name = context_arg.or_else(|| config.current_context.clone());
            let context = context_name
                .as_deref()
                .and_then(|name| config.contexts.get(name))
                .cloned();
            let addr = addr_arg
                .or_else(|| context.as_ref().map(|ctx| ctx.addr.clone()))
                .unwrap_or_else(|| DEFAULT_ADDR.to_string());
            crate::modules::system::ensure_secure_addr(&addr, cli.insecure)?;

            let token_name = token_name_arg
                .or_else(|| context.as_ref().and_then(|ctx| ctx.current_token.clone()));
            let mut access_token = if let Some(token) = token_arg.clone() {
                token
            } else {
                let context_name = context_name
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("context not set"))?;
                let token_name = token_name
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("token name not set"))?;
                ensure_access_token(&client, &addr, context_name, token_name, &mut config).await?
            };

            if access_token.starts_with(SERVICE_ACCOUNT_PREFIX) {
                let info = fetch_system_info(&client, &addr).await?;
                verify_server_fingerprint(
                    &config,
                    context_name.as_deref(),
                    &addr,
                    &info.server_fingerprint,
                )?;
                let auth = exchange_service_account_token(&client, &addr, &access_token).await?;
                access_token = auth.access_token;
            }

            let mut ctx = CommandContext {
                client: &client,
                addr: &addr,
                allow_insecure: cli.insecure,
                access_token,
                context_name,
                token_name,
                config: &mut config,
            };

            handle_command(command, &mut ctx).await?;
            save_config(ctx.config)?;
        }
    }

    Ok(())
}

fn read_token_file(path: &str) -> anyhow::Result<String> {
    let contents = std::fs::read_to_string(path)?;
    let token = contents.trim();
    if token.is_empty() {
        anyhow::bail!("token file is empty: {}", path);
    }
    Ok(token.to_string())
}

fn init_logging(verbosity: u8) -> anyhow::Result<()> {
    let filter = match verbosity {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(filter)?)
        .with_target(false)
        .init();
    Ok(())
}

fn prompt_login_command() -> anyhow::Result<LoginCommand> {
    let method = prompt_line("Login method (internal/oidc-device): ")?;
    match method.trim() {
        "internal" => {
            let email = prompt_line("Email: ")?;
            let password = prompt_password("Password: ")?;
            Ok(LoginCommand::Internal(LoginInternalArgs {
                email,
                password: Some(password),
                device_name: None,
                device_platform: None,
                context: None,
            }))
        }
        "oidc-device" | "oidc" => Ok(LoginCommand::OidcDevice(LoginOidcArgs { context: None })),
        _ => anyhow::bail!("unknown login method"),
    }
}

fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    let mut input = String::new();
    print!("{prompt}");
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub(crate) fn prompt_password(prompt: &str) -> anyhow::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let password = rpassword::read_password()?;
    if password.trim().is_empty() {
        anyhow::bail!("password is required");
    }
    Ok(password)
}

pub(crate) fn find_field<'a>(payload: &'a EncryptedPayload, key: &str) -> Option<&'a FieldValue> {
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    if let Some(item) = payload.fields.get(key) {
        return Some(item);
    }
    payload.fields.iter().find_map(|(field_key, value)| {
        if field_key.eq_ignore_ascii_case(key) {
            Some(value)
        } else {
            None
        }
    })
}
