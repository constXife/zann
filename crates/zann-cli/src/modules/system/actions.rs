use std::io::{self, Write};

use crate::cli_args::*;
use crate::modules::auth::{
    exchange_service_account_token, load_service_token, verify_server_fingerprint,
};
use crate::modules::shared::{
    fetch_shared_item, flatten_payload, is_valid_env_key, resolve_path_for_context,
    resolve_shared_item_id,
};
use crate::modules::system::http::{fetch_system_info, generate_password};
use crate::modules::system::resolve_addr;
use crate::modules::system::CliConfig;
use crate::{DEFAULT_ADDR, SERVICE_ACCOUNT_PREFIX};

pub(crate) async fn handle_server_command(
    args: ServerArgs,
    addr_arg: Option<String>,
    context_arg: Option<String>,
    client: &reqwest::Client,
    config: &CliConfig,
) -> anyhow::Result<()> {
    match args.command {
        ServerCommand::Fingerprint(args) => {
            let addr = resolve_addr(args.addr, addr_arg, context_arg, config)?;
            let info = fetch_system_info(client, &addr).await?;
            println!("{}", info.server_fingerprint);
        }
    }
    Ok(())
}

pub(crate) async fn handle_run_command(
    args: RunArgs,
    addr_arg: Option<String>,
    token_arg: Option<String>,
    token_name_arg: Option<String>,
    context_arg: Option<String>,
    client: &reqwest::Client,
    config: &mut CliConfig,
) -> anyhow::Result<()> {
    if args.command.is_empty() {
        anyhow::bail!("command is required after --");
    }

    let context_name = context_arg.or_else(|| config.current_context.clone());
    let context = context_name
        .as_deref()
        .and_then(|name| config.contexts.get(name))
        .cloned();
    let addr = addr_arg
        .or_else(|| context.as_ref().map(|ctx| ctx.addr.clone()))
        .unwrap_or_else(|| DEFAULT_ADDR.to_string());
    let token_name =
        token_name_arg.or_else(|| context.as_ref().and_then(|ctx| ctx.current_token.clone()));
    let mut service_account_token = token_arg
        .clone()
        .filter(|value| value.starts_with(SERVICE_ACCOUNT_PREFIX));
    if service_account_token.is_none() {
        if let (Some(context_name), Some(token_name)) =
            (context_name.as_deref(), token_name.as_deref())
        {
            service_account_token = load_service_token(context_name, token_name)?;
        }
    }
    let service_account_token = service_account_token
        .ok_or_else(|| anyhow::anyhow!("service account token required for zann run"))?;

    let info = fetch_system_info(client, &addr).await?;
    verify_server_fingerprint(
        config,
        context_name.as_deref(),
        &addr,
        &info.server_fingerprint,
    )?;
    let auth = exchange_service_account_token(client, &addr, &service_account_token).await?;
    let access_token = auth.access_token.clone();

    let (vault_id, path) = resolve_path_for_context(
        &args.path,
        args.vault,
        context_name.as_deref(),
        config,
        client,
        &addr,
        &access_token,
    )
    .await?;
    let item_id =
        resolve_shared_item_id(client, &addr, &access_token, &vault_id, None, Some(&path))
            .await
            .map_err(|_| anyhow::anyhow!("secret not found: {}", path))?;
    let item = fetch_shared_item(client, &addr, &access_token, item_id).await?;
    let mut env_values = std::collections::HashMap::new();
    for (key, value) in flatten_payload(&item.payload) {
        if !is_valid_env_key(&key) {
            eprintln!(
                "Warning: Key \"{}\" is not a valid shell identifier. Skipped.",
                key
            );
            continue;
        }
        env_values.insert(key, value);
    }

    let mut cmd = std::process::Command::new(&args.command[0]);
    if args.command.len() > 1 {
        cmd.args(&args.command[1..]);
    }
    for (key, value) in env_values {
        cmd.env(key, value);
    }

    let status = cmd.status()?;
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    Ok(())
}

pub(crate) fn handle_types_command() {
    println!("TYPE       DESCRIPTION");
    println!("login      Username/password credentials");
    println!("note       Secure text note");
    println!("card       Credit/debit card");
    println!("identity   Personal information");
    println!("api        API keys and tokens");
    println!("kv         Generic key/value payload");
}

pub(crate) fn handle_generate_command(args: GenerateArgs) -> anyhow::Result<()> {
    match args.command {
        GenerateCommand::Password(args) => {
            let password = generate_password(args.policy.as_deref())?;
            print!("{password}");
            io::stdout().flush()?;
        }
    }
    Ok(())
}
