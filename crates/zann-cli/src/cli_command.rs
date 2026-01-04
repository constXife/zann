use crate::cli_args::*;
use crate::modules::system::CommandContext;
use reqwest::Method;

use crate::modules::devices::handle_device;
use crate::modules::groups::handle_group;
use crate::modules::items::handle_item;
use crate::modules::shared::{
    handle_get, handle_list, handle_materialize, handle_render, handle_rotate, handle_versions,
};
use crate::modules::system::http::print_json_response;
use crate::modules::system::http::send_request;
use crate::modules::users::handle_user;
use crate::modules::vaults::handle_vault;

pub(crate) async fn handle_command(
    command: Command,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    match command {
        Command::Device(args) => handle_device(args, ctx).await?,
        Command::List(args) => handle_list(args, ctx).await?,
        Command::Get(args) => handle_get(args, ctx).await?,
        Command::Rotate(args) => handle_rotate(args, ctx).await?,
        Command::Versions(args) => handle_versions(args, ctx).await?,
        Command::Materialize(args) => handle_materialize(args, ctx).await?,
        Command::Render(args) => handle_render(args, ctx).await?,
        Command::Whoami => {
            let url = format!("{}/v1/users/me", ctx.addr.trim_end_matches('/'));
            let response = send_request(ctx, Method::GET, url, None).await?;
            print_json_response(response).await?;
        }
        Command::User(args) => handle_user(args, ctx).await?,
        Command::Group(args) => handle_group(args, ctx).await?,
        Command::Vault(args) => handle_vault(args, ctx).await?,
        Command::Item(args) => handle_item(args, ctx).await?,
        Command::Server(_) | Command::Run(_) => {}
        Command::Types(_) => {}
        Command::Config(_) | Command::Login(_) | Command::Logout(_) => {
            unreachable!()
        }
    }

    Ok(())
}
