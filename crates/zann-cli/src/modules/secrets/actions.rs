use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use zann_client::secrets::{
    BatchResult, SecretListResponse, SecretResponse, SecretSetRequest, SecretsClient,
    SecretsClientError, SecretsClientErrorKind, SecretsTransportSecurity, MAX_SECRET_VALUE_BYTES,
};
use zeroize::Zeroizing;

use crate::modules::secrets::args::{
    SecretArgs, SecretCommand, SecretEnsureArgs, SecretGetArgs, SecretListArgs,
    SecretListOutputFormat, SecretOutputFormat, SecretRotateArgs, SecretSetArgs,
};
use crate::modules::shared::resolve_vault_arg;
use crate::modules::system::http::refresh_service_account_access_token;
use crate::modules::system::CommandContext;

pub(crate) async fn handle_secret_command(
    args: SecretArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    match args.command {
        SecretCommand::List(args) => handle_list(args, ctx).await,
        SecretCommand::Get(args) => handle_get(args, ctx).await,
        SecretCommand::Set(args) => handle_set(args, ctx).await,
        SecretCommand::Ensure(args) => handle_ensure(args, ctx).await,
        SecretCommand::Rotate(args) => handle_rotate(args, ctx).await,
    }
}

async fn handle_list(args: SecretListArgs, ctx: &mut CommandContext<'_>) -> anyhow::Result<()> {
    let vault = resolve_vault_arg(args.vault, ctx).await?;
    let response = list_with_refresh(
        ctx,
        &vault,
        args.prefix.as_deref(),
        args.limit,
        args.cursor.as_deref(),
    )
    .await?;
    match args.format {
        SecretListOutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        SecretListOutputFormat::Table => print_list_table(&response),
    }
    Ok(())
}

async fn handle_set(args: SecretSetArgs, ctx: &mut CommandContext<'_>) -> anyhow::Result<()> {
    let vault = resolve_vault_arg(args.vault, ctx).await?;
    let payload = SecretSetRequest {
        value: read_secret_value(args.value_file.as_deref(), args.stdin)?,
        policy: args.policy,
        meta: None,
    };
    let response = match secrets_client(ctx)?.set(&vault, &args.path, &payload).await {
        Err(error) if should_refresh(&error) => {
            if !refresh_service_account_access_token(ctx).await? {
                return Err(error.into());
            }
            secrets_client(ctx)?
                .set(&vault, &args.path, &payload)
                .await?
        }
        result => result?,
    };
    print_response(&response, args.format)
}

async fn handle_get(args: SecretGetArgs, ctx: &mut CommandContext<'_>) -> anyhow::Result<()> {
    let vault = resolve_vault_arg(args.vault, ctx).await?;
    let response = get_with_refresh(ctx, &vault, &args.path, args.previous).await?;
    print_response(&response, args.format)
}

pub(crate) async fn get_with_refresh(
    ctx: &mut CommandContext<'_>,
    vault: &str,
    path: &str,
    previous: bool,
) -> anyhow::Result<SecretResponse> {
    match get_once(&secrets_client(ctx)?, vault, path, previous).await {
        Err(error) if should_refresh(&error) => {
            if !refresh_service_account_access_token(ctx).await? {
                return Err(error.into());
            }
            Ok(get_once(&secrets_client(ctx)?, vault, path, previous).await?)
        }
        result => Ok(result?),
    }
}

async fn get_once(
    client: &SecretsClient,
    vault: &str,
    path: &str,
    previous: bool,
) -> Result<SecretResponse, SecretsClientError> {
    if previous {
        client.get_previous(vault, path).await
    } else {
        client.get(vault, path).await
    }
}

async fn handle_ensure(args: SecretEnsureArgs, ctx: &mut CommandContext<'_>) -> anyhow::Result<()> {
    let vault = resolve_vault_arg(args.vault, ctx).await?;
    let response = match secrets_client(ctx)?
        .ensure(&vault, &args.path, args.policy.as_deref(), None)
        .await
    {
        Err(error) if should_refresh(&error) => {
            if !refresh_service_account_access_token(ctx).await? {
                return Err(error.into());
            }
            secrets_client(ctx)?
                .ensure(&vault, &args.path, args.policy.as_deref(), None)
                .await?
        }
        result => result?,
    };
    print_response(&response, args.format)
}

async fn handle_rotate(args: SecretRotateArgs, ctx: &mut CommandContext<'_>) -> anyhow::Result<()> {
    let vault = resolve_vault_arg(args.vault, ctx).await?;
    let response = match secrets_client(ctx)?
        .rotate(&vault, &args.path, args.policy.as_deref(), None)
        .await
    {
        Err(error) if should_refresh(&error) => {
            if !refresh_service_account_access_token(ctx).await? {
                return Err(error.into());
            }
            secrets_client(ctx)?
                .rotate(&vault, &args.path, args.policy.as_deref(), None)
                .await?
        }
        result => result?,
    };
    print_response(&response, args.format)
}

pub(crate) async fn batch_get_with_refresh(
    ctx: &mut CommandContext<'_>,
    vault: &str,
    paths: &[String],
) -> anyhow::Result<Vec<BatchResult>> {
    match secrets_client(ctx)?.batch_get(vault, paths).await {
        Err(error) if should_refresh(&error) => {
            if !refresh_service_account_access_token(ctx).await? {
                return Err(error.into());
            }
            Ok(secrets_client(ctx)?.batch_get(vault, paths).await?)
        }
        result => Ok(result?),
    }
}

pub(crate) async fn list_with_refresh(
    ctx: &mut CommandContext<'_>,
    vault: &str,
    prefix: Option<&str>,
    limit: usize,
    cursor: Option<&str>,
) -> anyhow::Result<SecretListResponse> {
    match secrets_client(ctx)?
        .list(vault, prefix, limit, cursor)
        .await
    {
        Err(error) if should_refresh(&error) => {
            if !refresh_service_account_access_token(ctx).await? {
                return Err(error.into());
            }
            Ok(secrets_client(ctx)?
                .list(vault, prefix, limit, cursor)
                .await?)
        }
        result => Ok(result?),
    }
}

pub(crate) fn secrets_client(
    ctx: &CommandContext<'_>,
) -> Result<SecretsClient, SecretsClientError> {
    let security = if ctx.allow_insecure {
        SecretsTransportSecurity::AllowLoopbackHttp
    } else {
        SecretsTransportSecurity::RequireTls
    };
    SecretsClient::new(ctx.addr, ctx.access_token.clone(), security)
}

pub(crate) fn should_refresh(error: &SecretsClientError) -> bool {
    error.kind() == SecretsClientErrorKind::Unauthorized
}

fn read_secret_value(value_file: Option<&Path>, use_stdin: bool) -> anyhow::Result<String> {
    match (value_file, use_stdin) {
        (Some(path), false) => {
            if !std::fs::metadata(path)
                .map_err(|error| anyhow::anyhow!("failed to inspect secret value file: {error}"))?
                .is_file()
            {
                anyhow::bail!("secret value source is not a regular file");
            }
            let file = open_secret_value_file(path)
                .map_err(|error| anyhow::anyhow!("failed to open secret value file: {error}"))?;
            if !file
                .metadata()
                .map_err(|error| anyhow::anyhow!("failed to inspect secret value file: {error}"))?
                .is_file()
            {
                anyhow::bail!("secret value source is not a regular file");
            }
            read_bounded_utf8(file)
        }
        (None, true) => read_bounded_utf8(io::stdin().lock()),
        _ => anyhow::bail!("exactly one of --stdin or --value-file is required"),
    }
}

fn open_secret_value_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NONBLOCK);
    }
    options.open(path)
}

fn read_bounded_utf8(reader: impl Read) -> anyhow::Result<String> {
    let mut value = Zeroizing::new(String::new());
    let limit = u64::try_from(MAX_SECRET_VALUE_BYTES + 1)
        .map_err(|_| anyhow::anyhow!("invalid secret value limit"))?;
    reader
        .take(limit)
        .read_to_string(&mut value)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidData {
                anyhow::anyhow!("secret value must be valid UTF-8")
            } else {
                anyhow::anyhow!("failed to read secret value: {error}")
            }
        })?;
    if value.len() > MAX_SECRET_VALUE_BYTES {
        anyhow::bail!("secret value exceeds {MAX_SECRET_VALUE_BYTES} bytes");
    }
    Ok(std::mem::take(&mut *value))
}

fn print_response(response: &SecretResponse, format: SecretOutputFormat) -> anyhow::Result<()> {
    match format {
        SecretOutputFormat::Value => {
            print!("{}", response.value);
            io::stdout().flush()?;
        }
        SecretOutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(response)?);
        }
    }
    Ok(())
}

fn print_list_table(response: &SecretListResponse) {
    let path_width = response
        .secrets
        .iter()
        .map(|secret| secret.path.len())
        .max()
        .unwrap_or("PATH".len())
        .max("PATH".len());
    println!(
        "{:<path_width$}  {:>7}  UPDATED_AT",
        "PATH",
        "VERSION",
        path_width = path_width
    );
    for secret in &response.secrets {
        println!(
            "{:<path_width$}  {:>7}  {}",
            secret.path,
            secret.version,
            secret.updated_at,
            path_width = path_width
        );
    }
    if let Some(cursor) = response.next_cursor.as_deref() {
        eprintln!("next_cursor: {cursor}");
    }
}

#[cfg(test)]
mod tests {
    use super::{read_bounded_utf8, MAX_SECRET_VALUE_BYTES};
    use std::io::Cursor;

    #[test]
    fn secret_value_reader_preserves_whitespace() {
        let value =
            read_bounded_utf8(Cursor::new(b" line one\nline two\n")).expect("valid secret value");
        assert_eq!(value, " line one\nline two\n");
    }

    #[test]
    fn secret_value_reader_rejects_oversized_and_non_utf8_input() {
        assert!(read_bounded_utf8(Cursor::new(vec![b'x'; MAX_SECRET_VALUE_BYTES + 1])).is_err());
        assert!(read_bounded_utf8(Cursor::new(vec![0xff, 0xfe])).is_err());
    }
}
