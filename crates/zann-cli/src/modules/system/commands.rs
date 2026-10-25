use super::CliState;
use crate::cli_args::{ConfigArgs, ConfigCommand};
use crate::read_token_file;
use zann_client::config::{
    ConnectionId, ConnectionMetadata, CredentialActivation, CredentialKind, CredentialSecret,
};
use zann_client::server::token_bundle;

pub(crate) fn handle_config_command(args: ConfigArgs, state: &mut CliState) -> anyhow::Result<()> {
    match args.command {
        ConfigCommand::SetContext(args) => {
            let addr = args
                .addr
                .or_else(|| {
                    state
                        .contexts
                        .get(&args.name)
                        .map(|context| context.addr.clone())
                })
                .ok_or_else(|| anyhow::anyhow!("--addr is required for a new context"))?;
            let id = ConnectionId::deterministic(&args.name, &addr);
            if state
                .contexts
                .get(&args.name)
                .is_some_and(|context| context.id != id)
            {
                anyhow::bail!("changing a configured endpoint requires an explicit rebind");
            }
            state
                .repository
                .upsert_connection(id.clone(), ConnectionMetadata::new(&args.name, addr))?;
            if let Some(path) = args.token_file {
                let token = CredentialSecret::new(read_token_file(&path)?)?;
                let profile = args.token_name.as_deref().unwrap_or("manual");
                let revision = state.repository.snapshot()?.revision();
                state.repository.replace_credential_bundle(
                    revision,
                    &id,
                    profile,
                    token_bundle(token),
                    CredentialActivation::MakeActive,
                    state.credentials.as_ref(),
                )?;
            }
            if let Some(vault) = args.vault {
                state.repository.set_cli_default_vault(&id, vault)?;
            }
            state
                .repository
                .set_active_connection(&state.client_id, Some(id))?;
        }
        ConfigCommand::UseContext(args) => {
            let id = state.context(&args.name)?.id.clone();
            state
                .repository
                .set_active_connection(&state.client_id, Some(id))?;
        }
        ConfigCommand::UseToken(args) => {
            let name = state.selected_name(args.context)?;
            let id = state.context(&name)?.id.clone();
            state.repository.set_active_credential_profile(
                state.repository.snapshot()?.revision(),
                &id,
                &args.name,
            )?;
        }
        ConfigCommand::ListTokens(args) => {
            let name = state.selected_name(args.context)?;
            let context = state.context(&name)?;
            for profile in &context.tokens {
                println!(
                    "{} {}",
                    if context.current_token.as_ref() == Some(profile) {
                        "*"
                    } else {
                        " "
                    },
                    profile
                );
            }
        }
        ConfigCommand::ShowToken(args) => {
            let name = state.selected_name(args.context)?;
            let id = &state.context(&name)?.id;
            let snapshot = state.repository.snapshot()?;
            let profile = snapshot.config().connections[id]
                .credential_profiles()
                .get(&args.name)
                .ok_or_else(|| anyhow::anyhow!("profile not found"))?;
            let kind = if args.show_service_token {
                CredentialKind::ServiceAccount
            } else {
                CredentialKind::Access
            };
            let credential_id = profile
                .credentials()
                .get(&kind)
                .ok_or_else(|| anyhow::anyhow!("credential not configured"))?;
            let secret = state
                .credentials
                .get(credential_id)?
                .ok_or_else(|| anyhow::anyhow!("credential missing"))?;
            println!("{}", secret.expose_secret());
        }
        ConfigCommand::RemoveToken(args) => {
            let name = state.selected_name(args.context)?;
            let id = state.context(&name)?.id.clone();
            state.repository.remove_credential_profile(
                state.repository.snapshot()?.revision(),
                &id,
                &args.name,
                zann_client::config::ActiveCredentialAfterRemoval::Clear,
                state.credentials.as_ref(),
            )?;
        }
        ConfigCommand::CurrentContext => {
            if let Some(name) = &state.current_context {
                println!("{name}");
            }
        }
        ConfigCommand::GetContexts => {
            for name in state.contexts.keys() {
                println!("{name}");
            }
        }
    }
    state.reload()
}
