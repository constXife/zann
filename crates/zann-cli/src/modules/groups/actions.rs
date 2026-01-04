use super::http::{
    add_member, create_group, delete_group, get_group, list_groups, remove_member, update_group,
};
use crate::cli_args::*;
use crate::modules::groups::{AddMemberRequest, CreateGroupRequest, UpdateGroupRequest};
use crate::modules::system::http::{print_empty_response, print_json_response};
use crate::modules::system::CommandContext;

pub(crate) async fn handle_group(
    args: GroupArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    match args.command {
        GroupCommand::List(args) => {
            let response = list_groups(ctx, args.limit, args.offset, args.sort).await?;
            print_json_response(response).await?;
        }
        GroupCommand::Create(args) => {
            let payload = CreateGroupRequest {
                slug: args.slug,
                name: args.name,
            };
            let response = create_group(ctx, payload).await?;
            print_json_response(response).await?;
        }
        GroupCommand::Get(args) => {
            let response = get_group(ctx, &args.slug).await?;
            print_json_response(response).await?;
        }
        GroupCommand::Update(args) => {
            let payload = UpdateGroupRequest {
                slug: args.new_slug,
                name: args.name,
            };
            let response = update_group(ctx, &args.slug, payload).await?;
            print_json_response(response).await?;
        }
        GroupCommand::Delete(args) => {
            let response = delete_group(ctx, &args.slug).await?;
            print_empty_response(response, "Group deleted").await?;
        }
        GroupCommand::AddMember(args) => {
            let payload = AddMemberRequest {
                user_id: args.user_id,
            };
            let response = add_member(ctx, &args.slug, payload).await?;
            print_json_response(response).await?;
        }
        GroupCommand::RemoveMember(args) => {
            let response = remove_member(ctx, &args.slug, &args.user_id).await?;
            print_empty_response(response, "Member removed").await?;
        }
    }
    Ok(())
}
