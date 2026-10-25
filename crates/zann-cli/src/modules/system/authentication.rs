//! Terminal trust confirmation and credential selection. Protocol and credential
//! operations are owned by zann-client.
use super::{CliState, CommandContext};
use std::io::{self, IsTerminal, Write};
use zann_client::config::CredentialSecret;
use zann_client::server::{ServerClient, ServerProbe};
use zeroize::Zeroizing;

pub async fn connect(
    state: &mut CliState,
    name: Option<&str>,
    addr: &str,
    allow_insecure: bool,
) -> anyhow::Result<ServerClient> {
    if addr.starts_with("http://") && !allow_insecure {
        anyhow::bail!("refusing plaintext HTTP without --insecure");
    }
    let context = name.map(|name| state.context(name)).transpose()?;
    let id = context.map(|context| context.id.clone());
    if context
        .is_some_and(|context| addr.trim_end_matches('/') != context.addr.trim_end_matches('/'))
    {
        anyhow::bail!("endpoint differs from the configured connection");
    }
    let probe = ServerProbe::new(addr).await?;
    let fingerprint = &probe.info().server_fingerprint;
    if let Ok(expected) = std::env::var("ZANN_SERVER_FINGERPRINT") {
        if expected != *fingerprint {
            anyhow::bail!("server fingerprint does not match ZANN_SERVER_FINGERPRINT");
        }
    } else if context.and_then(|context| context.server_fingerprint.as_ref()) != Some(fingerprint) {
        eprintln!("Server fingerprint: {fingerprint}");
        if !io::stdin().is_terminal() {
            anyhow::bail!(
                "server identity requires interactive confirmation or ZANN_SERVER_FINGERPRINT"
            );
        }
        print!("Trust this server identity? (y/N): ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "yes" | "Y") {
            anyhow::bail!("server trust declined");
        }
    }
    let confirmed = fingerprint.clone();
    let client = if let Some(id) = id {
        probe.bind_confirmed(&state.repository, &id, &confirmed)?
    } else {
        probe.confirm_ephemeral(&confirmed)?
    };
    state.reload()?;
    Ok(client)
}
pub async fn access_token(
    client: &ServerClient,
    state: &CliState,
    context: Option<&str>,
    profile: Option<&str>,
    explicit: Option<String>,
) -> anyhow::Result<Zeroizing<String>> {
    let secret = if let Some(value) = explicit {
        client
            .authenticate_token(&CredentialSecret::new(value)?)
            .await?
    } else {
        let profile = profile.ok_or_else(|| anyhow::anyhow!("token profile not set"))?;
        client
            .profile_access(
                &state.repository,
                state.credentials.as_ref(),
                &state
                    .context(context.ok_or_else(|| anyhow::anyhow!("context not set"))?)?
                    .id,
                profile,
                false,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("credential missing"))?
    };
    Ok(Zeroizing::new(secret.expose_secret().to_string()))
}
pub async fn refresh_service_account_access_token(
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<bool> {
    let (Some(context), Some(profile)) = (&ctx.context_name, &ctx.token_name) else {
        return Ok(false);
    };
    let secret = ctx
        .client
        .profile_access(
            &ctx.config.repository,
            ctx.config.credentials.as_ref(),
            &ctx.config.context(context)?.id,
            profile,
            true,
        )
        .await?;
    if let Some(secret) = secret {
        ctx.access_token = Zeroizing::new(secret.expose_secret().to_string());
        return Ok(true);
    }
    Ok(false)
}
