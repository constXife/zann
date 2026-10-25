use super::CommandContext;
use crate::cli_args::RunArgs;
use crate::modules::shared::{
    fetch_shared_item, flatten_payload, is_valid_env_key, payload_or_error,
    resolve_path_for_context, resolve_shared_item_id,
};
pub(crate) async fn handle_run_command(
    args: RunArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    if args.command.is_empty() {
        anyhow::bail!("command is required after --");
    }
    let (vault_id, path) = resolve_path_for_context(
        &args.path,
        args.vault,
        ctx.context_name.as_deref(),
        ctx.config,
        ctx.client,
        ctx.addr,
        &ctx.access_token,
    )
    .await?;
    let item_id = resolve_shared_item_id(
        ctx.client,
        ctx.addr,
        &ctx.access_token,
        &vault_id,
        None,
        Some(&path),
    )
    .await
    .map_err(|_| anyhow::anyhow!("secret not found: {}", path))?;
    let item =
        fetch_shared_item(ctx.client, ctx.addr, &ctx.access_token, &vault_id, item_id).await?;
    let mut env_values = std::collections::HashMap::new();
    let payload = payload_or_error(&item)?;
    for (key, value) in flatten_payload(&payload) {
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
