#![allow(dead_code)]

use crate::settings;
use zann_db::PgPool;

mod create;
mod list;
mod models;
mod revoke;
mod rotate;

pub(super) const SERVICE_ACCOUNT_PREFIX: &str = "zann_sa_";
pub(super) const SERVICE_ACCOUNT_PREFIX_LEN: usize = 12;
pub(super) const SYSTEM_OWNER_EMAIL: &str = "system@zann.internal";

pub(crate) async fn run(
    settings: &settings::Settings,
    db: &PgPool,
    args: &[String],
) -> Result<(), String> {
    let mut args = args.iter().cloned();
    let command = args.next().ok_or_else(|| tokens_usage("missing command"))?;
    match command.as_str() {
        "create" => create::tokens_create(settings, db, args).await,
        "list" => list::tokens_list(db, args).await,
        "revoke" => revoke::tokens_revoke(db, args).await,
        "rotate" => rotate::tokens_rotate(settings, db, args).await,
        _ => Err(tokens_usage("unknown command")),
    }
}

pub(super) fn tokens_usage(error: &str) -> String {
    format!(
        "{error}\n\
Usage:\n\
  zann-server tokens create --name <name> --vault <vault_id_or_slug> --prefix <path> [--prefix <path> ...] --ops <read|read_history|read_previous|history_read> --ttl <30d> --issued-by-email <email> [--owner-email <email>]\n\
  zann-server tokens create --name <name> --token-file <path> --ttl <30d> --issued-by-email <email> [--owner-email <email>]\n\
  (use --prefix / for full-vault access; cannot be combined with other prefixes)\n\
  zann-server tokens list [--owner-email <email>]\n\
  zann-server tokens revoke <token_id>\n\
  zann-server tokens rotate <token_id>\n"
    )
}
