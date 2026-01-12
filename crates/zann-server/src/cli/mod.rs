use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

pub mod init;
pub mod tokens;

#[derive(Parser)]
#[command(name = "zann-server")]
#[command(about = "Zann Server CLI")]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run database migrations
    Migrate,
    /// Print OpenAPI spec (optionally to a file)
    Openapi(OpenApiArgs),
    /// Initial setup (first user + vault)
    Init(init::InitArgs),
    /// Manage service account tokens
    Token(tokens::TokenArgs),
}

#[derive(Args)]
struct OpenApiArgs {
    #[arg(long, short)]
    out: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum RunMode {
    Server,
    Migrate,
    OpenApi { out: Option<PathBuf> },
    Init(init::InitArgs),
    Token(tokens::TokenArgs),
}

pub fn parse_args() -> RunMode {
    let cli = Cli::parse();
    match cli.command {
        None => RunMode::Server,
        Some(Command::Migrate) => RunMode::Migrate,
        Some(Command::Openapi(args)) => RunMode::OpenApi { out: args.out },
        Some(Command::Init(args)) => RunMode::Init(args),
        Some(Command::Token(args)) => RunMode::Token(args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tokens::TokenCommand;
    use std::path::PathBuf;

    #[test]
    fn parse_default_command_is_server() {
        let cli = Cli::parse_from(["zann-server"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn parse_openapi_with_out_path() {
        let cli = Cli::parse_from(["zann-server", "openapi", "-o", "spec.json"]);
        let Some(Command::Openapi(args)) = cli.command else {
            panic!("expected openapi command");
        };
        assert_eq!(args.out, Some(PathBuf::from("spec.json")));
    }

    #[test]
    fn parse_token_create_defaults_ops() {
        let cli = Cli::parse_from(["zann-server", "token", "create", "ci", "prod:/"]);
        let Some(Command::Token(token_args)) = cli.command else {
            panic!("expected token command");
        };
        let TokenCommand::Create(args) = token_args.command else {
            panic!("expected token create command");
        };
        assert_eq!(args.name, "ci");
        assert_eq!(args.target, "prod:/");
        assert_eq!(args.ops, "read");
        assert!(args.issued_by_email.is_none());
    }

    #[test]
    fn parse_token_create_with_ops_and_metadata() {
        let cli = Cli::parse_from([
            "zann-server",
            "token",
            "create",
            "ci-prod",
            "prod:apps,infra",
            "read,read_history",
            "--ttl",
            "30d",
            "--issued-by-email",
            "admin@example.com",
        ]);
        let Some(Command::Token(token_args)) = cli.command else {
            panic!("expected token command");
        };
        let TokenCommand::Create(args) = token_args.command else {
            panic!("expected token create command");
        };
        assert_eq!(args.ops, "read,read_history");
        assert_eq!(args.ttl.as_deref(), Some("30d"));
        assert_eq!(args.issued_by_email.as_deref(), Some("admin@example.com"));
    }

    #[test]
    fn parse_init_command() {
        let cli = Cli::parse_from([
            "zann-server",
            "init",
            "--email",
            "admin@example.com",
            "--password",
            "secret",
            "--vault-name",
            "Production",
            "--vault-slug",
            "prod",
        ]);
        let Some(Command::Init(args)) = cli.command else {
            panic!("expected init command");
        };
        assert_eq!(args.email, "admin@example.com");
        assert_eq!(args.vault_slug, "prod");
    }

    #[test]
    fn parse_token_create_requires_target() {
        let result = Cli::try_parse_from(["zann-server", "token", "create", "ci-prod"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_init_requires_flags() {
        let result = Cli::try_parse_from(["zann-server", "init", "--email", "admin@example.com"]);
        assert!(result.is_err());
    }
}
