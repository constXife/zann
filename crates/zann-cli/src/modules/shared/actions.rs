use std::collections::HashMap;
use std::io::{self, Read, Write};

use serde_json::Value as JsonValue;
use zann_core::{EncryptedPayload, FieldKind, FieldValue};

use crate::cli_args::*;
use crate::find_field;
use crate::modules::shared::{
    create_shared_item, delete_shared_item, fetch_shared_item, fetch_shared_items, flatten_payload,
    format_env_flat, format_kv_flat, payload_or_error, print_list_table, resolve_path_arg,
    resolve_shared_item_id, resolve_vault_arg, secret_not_found_error, set_secret_value,
    update_shared_item,
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
                .map(|item| {
                    Ok(SharedListJsonItem {
                        path: item.path.clone(),
                        fields: flatten_payload(payload_or_error(item)?),
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
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
    let item =
        fetch_shared_item(ctx.client, ctx.addr, &ctx.access_token, &vault_id, item_id).await?;
    let payload = payload_or_error(&item)?;

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

pub(crate) async fn handle_create(
    args: CreateArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    let vault_id = resolve_vault_arg(args.vault, ctx).await?;
    let payload = build_payload_from_args(&args.field, args.stdin, &args.type_id)?;

    let item = create_shared_item(
        ctx.client,
        ctx.addr,
        &ctx.access_token,
        &vault_id,
        &args.path,
        &args.type_id,
        payload,
    )
    .await?;

    println!("Created: {} (id: {})", item.path, item.id);
    Ok(())
}

pub(crate) async fn handle_update(
    args: UpdateArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
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

    let type_id = args.type_id.as_deref().unwrap_or("secret");
    let payload = build_payload_from_args(&args.field, args.stdin, type_id)?;

    let item = update_shared_item(
        ctx.client,
        ctx.addr,
        &ctx.access_token,
        &item_id.to_string(),
        payload,
    )
    .await?;

    println!("Updated: {} (version: {})", item.path, item.id);
    Ok(())
}

pub(crate) async fn handle_set(args: SetArgs, ctx: &mut CommandContext<'_>) -> anyhow::Result<()> {
    let (vault_id, path) = resolve_path_arg(&args.path, args.vault, ctx).await?;

    if args.key == "password" {
        set_secret_value(
            ctx.client,
            ctx.addr,
            &ctx.access_token,
            &vault_id,
            &path,
            &args.value,
        )
        .await?;
        println!("Updated: {} field '{}'", path, args.key);
        return Ok(());
    }

    let existing = resolve_shared_item_id(
        ctx.client,
        ctx.addr,
        &ctx.access_token,
        &vault_id,
        None,
        Some(&path),
    )
    .await;

    let mut fields = HashMap::new();
    fields.insert(
        args.key.clone(),
        FieldValue {
            kind: FieldKind::Text,
            value: args.value,
            meta: None,
        },
    );

    match existing {
        Ok(item_id) => {
            let item =
                fetch_shared_item(ctx.client, ctx.addr, &ctx.access_token, &vault_id, item_id)
                    .await?;
            let existing_payload = payload_or_error(&item)?;

            let mut merged_fields = existing_payload.fields.clone();
            merged_fields.extend(fields);

            let payload = EncryptedPayload {
                v: existing_payload.v,
                type_id: existing_payload.type_id.clone(),
                fields: merged_fields,
                extra: existing_payload.extra.clone(),
            };

            let updated = update_shared_item(
                ctx.client,
                ctx.addr,
                &ctx.access_token,
                &item_id.to_string(),
                serde_json::to_value(payload)?,
            )
            .await?;
            println!(
                "Updated: {} field '{}' (version: {})",
                updated.path, args.key, updated.id
            );
        }
        Err(_) => {
            let payload = EncryptedPayload {
                v: 1,
                type_id: "secret".to_string(),
                fields,
                extra: None,
            };

            let created = create_shared_item(
                ctx.client,
                ctx.addr,
                &ctx.access_token,
                &vault_id,
                &path,
                "secret",
                serde_json::to_value(payload)?,
            )
            .await?;
            println!(
                "Created: {} with field '{}' (id: {})",
                created.path, args.key, created.id
            );
        }
    }
    Ok(())
}

pub(crate) async fn handle_delete(
    args: DeleteArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
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

    delete_shared_item(
        ctx.client,
        ctx.addr,
        &ctx.access_token,
        &item_id.to_string(),
    )
    .await?;

    println!("Deleted: {}", path);
    Ok(())
}

fn build_payload_from_args(
    fields: &[String],
    stdin: bool,
    type_id: &str,
) -> anyhow::Result<JsonValue> {
    if stdin && !fields.is_empty() {
        anyhow::bail!("Cannot use both --field and --stdin");
    }

    if stdin {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        let value: JsonValue = serde_json::from_str(&input)?;
        return Ok(value);
    }

    if fields.is_empty() {
        anyhow::bail!("Provide at least one --field KEY VALUE or use --stdin");
    }

    let mut map = HashMap::new();
    for chunk in fields.chunks(2) {
        let key = &chunk[0];
        let value = &chunk[1];
        map.insert(
            key.clone(),
            FieldValue {
                kind: FieldKind::Text,
                value: value.clone(),
                meta: None,
            },
        );
    }

    let payload = EncryptedPayload {
        v: 1,
        type_id: type_id.to_string(),
        fields: map,
        extra: None,
    };

    Ok(serde_json::to_value(payload)?)
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
