use crate::cli_args::*;
use crate::modules::system::CommandContext;
use reqwest::Method;

use crate::modules::shared::{handle_get, handle_list, handle_materialize, handle_render};
use crate::modules::system::http::print_json_response;
use crate::modules::system::http::send_request;

pub(crate) async fn handle_command(
    command: Command,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    match command {
        Command::List(args) => handle_list(args, ctx).await?,
        Command::Get(args) => handle_get(args, ctx).await?,
        Command::Materialize(args) => handle_materialize(args, ctx).await?,
        Command::Render(args) => handle_render(args, ctx).await?,
        Command::Whoami => {
            let url = format!("{}/v1/users/me", ctx.addr.trim_end_matches('/'));
            let response = send_request(ctx, Method::GET, url, None).await?;
            print_json_response(response).await?;
        }
        Command::Server(_) | Command::Run(_) => {}
        Command::Config(_) | Command::Login(_) | Command::Logout(_) => {
            unreachable!()
        }
    }

    Ok(())
}
