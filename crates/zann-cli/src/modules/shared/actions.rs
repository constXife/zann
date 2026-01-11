use std::io::{self, Write};

use crate::cli_args::*;
use crate::find_field;
use crate::modules::shared::{
    fetch_shared_item, fetch_shared_items, flatten_payload, format_env_flat, format_kv_flat,
    print_list_table, resolve_path_arg, resolve_shared_item_id, resolve_vault_arg,
    secret_not_found_error,
};
use crate::modules::shared::{
    materialize_shared, render_shared_template, SharedListJsonItem, SharedListJsonResponse,
};
use crate::modules::system::CommandContext;

pub(crate) async fn handle_list(
    args: SharedListArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    let vault_id = resolve_vault_arg(args.vault, ctx).await?;
    let response = fetch_shared_items(
        ctx.client,
        ctx.addr,
        &ctx.access_token,
        &vault_id,
        args.prefix.as_deref(),
        args.limit,
        args.cursor.as_deref(),
    )
    .await?;
    match args.format {
        ListFormat::Json => {
            let items: Vec<SharedListJsonItem> = response
                .items
                .iter()
                .map(|item| SharedListJsonItem {
                    path: item.path.clone(),
                    fields: flatten_payload(&item.payload),
                })
                .collect();
            let output = SharedListJsonResponse {
                items,
                next_cursor: response.next_cursor.clone(),
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        ListFormat::Table => {
            print_list_table(&response.items);
        }
    }
    Ok(())
}

pub(crate) async fn handle_get(args: GetArgs, ctx: &mut CommandContext<'_>) -> anyhow::Result<()> {
    let (vault_id, path) = resolve_path_arg(&args.path, args.vault, ctx).await?;
    let item_id = resolve_shared_item_id(
        ctx.client,
        ctx.addr,
        &ctx.access_token,
        &vault_id,
        None,
        Some(&path),
    )
    .await
    .map_err(|_| secret_not_found_error(&path))?;
    let item = fetch_shared_item(ctx.client, ctx.addr, &ctx.access_token, item_id).await?;
    let payload = &item.payload;

    if let Some(key) = args.key.as_deref() {
        let value = find_field(payload, key)
            .map(|item| item.value.clone())
            .ok_or_else(|| anyhow::anyhow!("field '{}' not found", key))?;
        print!("{value}");
        io::stdout().flush()?;
        return Ok(());
    }

    match args.format {
        GetFormat::Json => {
            let output = flatten_payload(payload);
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        GetFormat::Kv => {
            let output = format_kv_flat(payload);
            print!("{output}");
            io::stdout().flush()?;
        }
        GetFormat::Env => {
            let output = format_env_flat(payload);
            print!("{output}");
            io::stdout().flush()?;
        }
    }
    Ok(())
}

pub(crate) async fn handle_materialize(
    args: SharedMaterializeArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    let vault_id = resolve_vault_arg(args.vault, ctx).await?;
    materialize_shared(
        ctx.client,
        ctx.addr,
        &ctx.access_token,
        &vault_id,
        args.prefix.as_deref(),
        &args.out,
        args.field.as_deref(),
        args.skip_unchanged,
        !args.no_atomic,
        args.limit,
    )
    .await?;
    Ok(())
}

pub(crate) async fn handle_render(
    args: RenderArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    render_shared_template(args, ctx).await?;
    Ok(())
}
