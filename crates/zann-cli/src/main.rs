use clap::Parser;
use zann_core::{EncryptedPayload, FieldValue};

mod cli_args;
mod cli_command;
mod modules;

use crate::cli_args::*;
use crate::cli_command::handle_command;
use crate::modules::system::authentication::{access_token, connect};
use crate::modules::system::{handle_config_command, handle_run_command, CliState, CommandContext};
use tracing_subscriber::EnvFilter;

const SERVER_URL_ENV: &str = "ZANN_SERVER_URL";
const SERVICE_TOKEN_ENV: &str = "ZANN_SERVICE_TOKEN";
const REPO_URL: &str = "https://github.com/constXife/zann";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose)?;
    if let Command::Materialize(args) = &cli.command {
        crate::modules::shared::validate_materialize_field(&args.field)?;
    }
    if matches!(cli.command, Command::Version) {
        print_version();
        return Ok(());
    }
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .ok_or_else(|| anyhow::anyhow!("home directory is not set"))?;
    let mut state = CliState::open(std::path::PathBuf::from(home).join(".zann"))?;
    let addr_arg = cli.addr.or_else(|| std::env::var(SERVER_URL_ENV).ok());
    let token_arg = cli
        .token_file
        .as_deref()
        .map(read_token_file)
        .transpose()?
        .or_else(|| std::env::var(SERVICE_TOKEN_ENV).ok());
    match cli.command {
        Command::Config(args) => handle_config_command(args, &mut state)?,
        Command::Server(args) => match args.command {
            ServerCommand::Info(args) => {
                let addr = args
                    .addr
                    .or(addr_arg)
                    .or_else(|| {
                        cli.context
                            .as_deref()
                            .or(state.current_context.as_deref())
                            .and_then(|name| state.contexts.get(name))
                            .map(|context| context.addr.clone())
                    })
                    .ok_or_else(|| anyhow::anyhow!("server address not set"))?;
                if addr.starts_with("http://") && !cli.insecure {
                    anyhow::bail!("refusing to use http:// without --insecure");
                }
                let info = zann_client::probe::probe_system_info(&addr).await?;
                println!("{}", serde_json::to_string_pretty(&info)?);
            }
        },
        command => {
            let context_name = cli.context.or_else(|| state.current_context.clone());
            let context = context_name
                .as_deref()
                .map(|name| state.context(name))
                .transpose()?;
            let addr = addr_arg
                .or_else(|| context.map(|context| context.addr.clone()))
                .ok_or_else(|| anyhow::anyhow!("server address not set"))?;
            let token_name = cli
                .token_name
                .or_else(|| context.and_then(|context| context.current_token.clone()));
            let client = connect(&mut state, context_name.as_deref(), &addr, cli.insecure).await?;
            let token = access_token(
                &client,
                &state,
                context_name.as_deref(),
                token_name.as_deref(),
                token_arg,
            )
            .await?;
            let mut ctx = CommandContext {
                client: &client,
                addr: &addr,
                allow_insecure: cli.insecure,
                access_token: token,
                context_name,
                token_name,
                config: &mut state,
            };
            match command {
                Command::Run(args) => handle_run_command(args, &mut ctx).await?,
                command => handle_command(command, &mut ctx).await?,
            }
        }
    }
    Ok(())
}

fn print_version() {
    println!(
        "zann {} (token-based; tokens are issued by the server)\nDocs: {}",
        env!("CARGO_PKG_VERSION"),
        REPO_URL
    );
}

fn read_token_file(path: &str) -> anyhow::Result<String> {
    use std::io::Read;
    let mut contents = String::new();
    std::fs::File::open(path)?
        .take(65_537)
        .read_to_string(&mut contents)?;
    if contents.len() > 65_536 {
        anyhow::bail!("token file exceeds the credential size limit");
    }
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

#[cfg(test)]
#[path = "../tests/unit/config.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;
