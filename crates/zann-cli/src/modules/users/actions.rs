use super::http::{
    block_user, create_user, delete_user, get_user, list_users, reset_password, unblock_user,
};
use crate::cli_args::*;
use crate::modules::system::http::{print_empty_response, print_json_response};
use crate::modules::system::CommandContext;
use crate::modules::users::{CreateUserRequest, ResetPasswordRequest};

pub(crate) async fn handle_user(
    args: UserArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    match args.command {
        UserCommand::List(args) => {
            let response = list_users(ctx, args.status, args.limit, args.offset, args.sort).await?;
            print_json_response(response).await?;
        }
        UserCommand::Create(args) => {
            let payload = CreateUserRequest {
                email: args.email,
                password: args.password,
                full_name: args.full_name,
            };
            let response = create_user(ctx, payload).await?;
            print_json_response(response).await?;
        }
        UserCommand::Get(args) => {
            let response = get_user(ctx, &args.id).await?;
            print_json_response(response).await?;
        }
        UserCommand::Delete(args) => {
            let response = delete_user(ctx, &args.id).await?;
            print_empty_response(response, "User deleted").await?;
        }
        UserCommand::Block(args) => {
            let response = block_user(ctx, &args.id).await?;
            print_json_response(response).await?;
        }
        UserCommand::Unblock(args) => {
            let response = unblock_user(ctx, &args.id).await?;
            print_json_response(response).await?;
        }
        UserCommand::ResetPassword(args) => {
            let payload = ResetPasswordRequest {
                password: args.password,
            };
            let response = reset_password(ctx, &args.id, payload).await?;
            print_json_response(response).await?;
        }
    }
    Ok(())
}
