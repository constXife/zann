use super::http::{current_device, list_devices, revoke_device};
use crate::cli_args::*;
use crate::modules::system::http::{print_empty_response, print_json_response};
use crate::modules::system::CommandContext;

pub(crate) async fn handle_device(
    args: DeviceArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    match args.command {
        DeviceCommand::List(args) => {
            let response = list_devices(ctx, args.limit, args.offset, args.sort).await?;
            print_json_response(response).await?;
        }
        DeviceCommand::Current(_) => {
            let response = current_device(ctx).await?;
            print_json_response(response).await?;
        }
        DeviceCommand::Revoke(args) => {
            let response = revoke_device(ctx, &args.id).await?;
            print_empty_response(response, "Device revoked").await?;
        }
    }
    Ok(())
}
