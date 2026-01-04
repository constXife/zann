use uuid::Uuid;

use crate::modules::shared::parse_selector_if_present;
use crate::modules::shared::{fetch_shared_items, fetch_vaults};
use crate::modules::system::CliConfig;
use crate::modules::system::CommandContext;

pub(crate) async fn resolve_shared_item_id(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
    vault_id: &str,
    item_id: Option<Uuid>,
    path: Option<&str>,
) -> anyhow::Result<Uuid> {
    if let Some(item_id) = item_id {
        return Ok(item_id);
    }
    let path = path.ok_or_else(|| anyhow::anyhow!("--path or --item-id is required"))?;
    resolve_shared_item_id_by_path(client, addr, access_token, vault_id, path).await
}

pub(crate) async fn resolve_vault_for_context(
    vault: Option<String>,
    context_name: Option<&str>,
    config: &CliConfig,
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
) -> anyhow::Result<String> {
    if let Some(vault) = vault {
        return Ok(vault);
    }
    if let Some(context_name) = context_name {
        if let Some(context) = config.contexts.get(context_name) {
            if let Some(vault) = context.vault.clone() {
                return Ok(vault);
            }
        }
    }
    let vaults = fetch_vaults(client, addr, access_token).await?;
    if vaults.vaults.len() == 1 {
        return Ok(vaults.vaults[0].id.clone());
    }
    anyhow::bail!("vault not set: pass --vault or set context vault")
}

pub(crate) async fn resolve_vault_arg(
    vault: Option<String>,
    ctx: &CommandContext<'_>,
) -> anyhow::Result<String> {
    resolve_vault_for_context(
        vault,
        ctx.context_name.as_deref(),
        ctx.config,
        ctx.client,
        ctx.addr,
        &ctx.access_token,
    )
    .await
}

pub(crate) async fn resolve_path_arg(
    path: &str,
    vault: Option<String>,
    ctx: &CommandContext<'_>,
) -> anyhow::Result<(String, String)> {
    resolve_path_for_context(
        path,
        vault,
        ctx.context_name.as_deref(),
        ctx.config,
        ctx.client,
        ctx.addr,
        &ctx.access_token,
    )
    .await
}

pub(crate) async fn resolve_path_for_context(
    path: &str,
    vault: Option<String>,
    context_name: Option<&str>,
    config: &CliConfig,
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
) -> anyhow::Result<(String, String)> {
    if let Some(selector) = parse_selector_if_present(path)? {
        return Ok((selector.vault, selector.path));
    }
    let vault_id =
        resolve_vault_for_context(vault, context_name, config, client, addr, access_token).await?;
    Ok((vault_id, path.to_string()))
}

async fn resolve_shared_item_id_by_path(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
    vault_id: &str,
    path: &str,
) -> anyhow::Result<Uuid> {
    let response = fetch_shared_items(
        client,
        addr,
        access_token,
        vault_id,
        Some(path),
        Some(200),
        None,
    )
    .await?;
    let item = response
        .items
        .iter()
        .find(|item| item.path == path)
        .ok_or_else(|| anyhow::anyhow!("shared item not found: {}", path))?;
    Ok(Uuid::parse_str(&item.id)?)
}
