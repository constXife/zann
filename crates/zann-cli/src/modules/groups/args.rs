use clap::{Args, Subcommand};
use uuid::Uuid;

#[derive(Args)]
pub struct GroupArgs {
    #[command(subcommand)]
    pub command: GroupCommand,
}

#[derive(Subcommand)]
pub enum GroupCommand {
    List(GroupListArgs),
    Create(GroupCreateArgs),
    Get(GroupGetArgs),
    Update(GroupUpdateArgs),
    Delete(GroupDeleteArgs),
    AddMember(GroupAddMemberArgs),
    RemoveMember(GroupRemoveMemberArgs),
}

#[derive(Args)]
pub struct GroupListArgs {
    #[arg(long)]
    pub limit: Option<i64>,
    #[arg(long)]
    pub offset: Option<i64>,
    #[arg(long)]
    pub sort: Option<String>,
}

#[derive(Args)]
pub struct GroupCreateArgs {
    #[arg(long)]
    pub slug: String,
    #[arg(long)]
    pub name: String,
}

#[derive(Args)]
pub struct GroupGetArgs {
    pub slug: String,
}

#[derive(Args)]
pub struct GroupUpdateArgs {
    pub slug: String,
    #[arg(long)]
    pub new_slug: Option<String>,
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Args)]
pub struct GroupDeleteArgs {
    pub slug: String,
}

#[derive(Args)]
pub struct GroupAddMemberArgs {
    pub slug: String,
    pub user_id: Uuid,
}

#[derive(Args)]
pub struct GroupRemoveMemberArgs {
    pub slug: String,
    pub user_id: Uuid,
}
