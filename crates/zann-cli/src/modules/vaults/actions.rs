use super::http::{create_vault, delete_vault, get_vault, list_vaults};
use crate::cli_args::*;
use crate::modules::system::http::{parse_base64, print_empty_response, print_json_response};
use crate::modules::system::CommandContext;
use crate::modules::vaults::CreateVaultRequest;

pub(crate) async fn handle_vault(
    args: VaultArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    match args.command {
        VaultCommand::List(args) => {
            let response = list_vaults(ctx, args.limit, args.offset, args.sort).await?;
            print_json_response(response).await?;
        }
        VaultCommand::Create(args) => {
            let vault_key_enc = args
                .vault_key_base64
                .as_deref()
                .map(parse_base64)
                .transpose()?;
            let tags = if args.tag.is_empty() {
                None
            } else {
                Some(args.tag)
            };
            let payload = CreateVaultRequest {
                slug: args.slug,
                name: args.name,
                kind: args.kind,
                cache_policy: args.cache_policy,
                vault_key_enc,
                tags,
            };
            let response = create_vault(ctx, payload).await?;
            print_json_response(response).await?;
        }
        VaultCommand::Get(args) => {
            let response = get_vault(ctx, &args.id_or_slug).await?;
            print_json_response(response).await?;
        }
        VaultCommand::Delete(args) => {
            let response = delete_vault(ctx, &args.id_or_slug).await?;
            print_empty_response(response, "Vault deleted").await?;
        }
    }
    Ok(())
}
