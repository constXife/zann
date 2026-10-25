use crate::cli_args::*;
use crate::modules::system::CommandContext;

use crate::modules::delivery::handle_delivery_command;
use crate::modules::secrets::{handle_rotation_hook, handle_secret_command};
use crate::modules::shared::{
    handle_create, handle_delete, handle_get, handle_list, handle_materialize, handle_render,
    handle_set, handle_update,
};

pub(crate) async fn handle_command(
    command: Command,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    match command {
        Command::List(args) => handle_list(args, ctx).await?,
        Command::Get(args) => handle_get(args, ctx).await?,
        Command::Secret(args) => handle_secret_command(args, ctx).await?,
        Command::Delivery(args) => handle_delivery_command(args, ctx).await?,
        Command::Rotate(args) => handle_rotation_hook(args, ctx).await?,
        Command::Materialize(args) => handle_materialize(args, ctx).await?,
        Command::Render(args) => handle_render(args, ctx).await?,
        Command::Create(args) => handle_create(args, ctx).await?,
        Command::Update(args) => handle_update(args, ctx).await?,
        Command::Set(args) => handle_set(args, ctx).await?,
        Command::Delete(args) => handle_delete(args, ctx).await?,
        Command::Whoami => {
            let response = ctx.client.me(&ctx.access_token).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Command::Server(_) | Command::Run(_) | Command::Version => {}
        Command::Config(_) => {
            unreachable!()
        }
    }

    Ok(())
}
