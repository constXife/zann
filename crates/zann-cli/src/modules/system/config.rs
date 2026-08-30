use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::types::{CliConfig, CliContext, TokenEntry};
use crate::cli_args::{ConfigArgs, ConfigCommand};
use crate::modules::auth::{
    delete_access_token, delete_service_token, load_access_token, load_service_token,
    store_access_token, store_service_token,
};
use crate::{read_token_file, DEFAULT_ADDR, SERVICE_ACCOUNT_PREFIX, TOKEN_MANUAL};

pub(crate) fn handle_config_command(
    args: ConfigArgs,
    config: &mut CliConfig,
) -> anyhow::Result<()> {
    match args.command {
        ConfigCommand::SetContext(args) => {
            let entry = config
                .contexts
                .entry(args.name.clone())
                .or_insert_with(|| CliContext {
                    addr: DEFAULT_ADDR.to_string(),
                    needs_salt_update: false,
                    server_fingerprint: None,
                    tokens: HashMap::new(),
                    current_token: None,
                    vault: None,
                });
            if let Some(addr) = args.addr {
                entry.addr = addr;
            }
            if let Some(token) = args
                .token_file
                .as_deref()
                .map(read_token_file)
                .transpose()?
            {
                let name = args.token_name.unwrap_or_else(|| TOKEN_MANUAL.to_string());
                let is_service_account = token.starts_with(SERVICE_ACCOUNT_PREFIX);
                entry.tokens.insert(
                    name.clone(),
                    TokenEntry {
                        access_expires_at: None,
                    },
                );
                if is_service_account {
                    store_service_token(&args.name, &name, &token)?;
                } else {
                    store_access_token(&args.name, &name, &token)?;
                }
                entry.current_token = Some(name);
            }
            if let Some(vault) = args.vault {
                entry.vault = Some(vault);
            }
            config.current_context = Some(args.name);
        }
        ConfigCommand::UseContext(args) => {
            if !config.contexts.contains_key(&args.name) {
                anyhow::bail!("context not found: {}", args.name);
            }
            config.current_context = Some(args.name);
        }
        ConfigCommand::UseToken(args) => {
            let context_name = args
                .context
                .clone()
                .or_else(|| config.current_context.clone())
                .ok_or_else(|| anyhow::anyhow!("context not set"))?;
            let context = config
                .contexts
                .get_mut(&context_name)
                .ok_or_else(|| anyhow::anyhow!("context not found: {}", context_name))?;
            if !context.tokens.contains_key(&args.name) {
                anyhow::bail!("token not found: {}", args.name);
            }
            context.current_token = Some(args.name);
        }
        ConfigCommand::ListTokens(args) => {
            let context_name = args
                .context
                .clone()
                .or_else(|| config.current_context.clone())
                .ok_or_else(|| anyhow::anyhow!("context not set"))?;
            let context = config
                .contexts
                .get(&context_name)
                .ok_or_else(|| anyhow::anyhow!("context not found: {}", context_name))?;
            let mut names: Vec<&String> = context.tokens.keys().collect();
            names.sort();
            for name in names {
                let marker = if context.current_token.as_ref() == Some(name) {
                    "*"
                } else {
                    " "
                };
                println!("{marker} {name}");
            }
        }
        ConfigCommand::ShowToken(args) => {
            let context_name = args
                .context
                .clone()
                .or_else(|| config.current_context.clone())
                .ok_or_else(|| anyhow::anyhow!("context not set"))?;
            let context = config
                .contexts
                .get(&context_name)
                .ok_or_else(|| anyhow::anyhow!("context not found: {}", context_name))?;
            let _entry = context
                .tokens
                .get(&args.name)
                .ok_or_else(|| anyhow::anyhow!("token not found: {}", args.name))?;
            if args.show_service_token {
                let token = load_service_token(&context_name, &args.name)?
                    .ok_or_else(|| anyhow::anyhow!("service token not found in keychain"))?;
                println!("{token}");
                return Ok(());
            }
            let token = load_access_token(&context_name, &args.name)?
                .ok_or_else(|| anyhow::anyhow!("access token not found in keychain"))?;
            println!("{token}");
        }
        ConfigCommand::RemoveToken(args) => {
            let context_name = args
                .context
                .clone()
                .or_else(|| config.current_context.clone())
                .ok_or_else(|| anyhow::anyhow!("context not set"))?;
            let context = config
                .contexts
                .get_mut(&context_name)
                .ok_or_else(|| anyhow::anyhow!("context not found: {}", context_name))?;
            context.tokens.remove(&args.name);
            if context.current_token.as_deref() == Some(&args.name) {
                context.current_token = None;
            }
            delete_access_token(&context_name, &args.name)?;
            delete_service_token(&context_name, &args.name)?;
        }
        ConfigCommand::CurrentContext => {
            if let Some(current) = config.current_context.clone() {
                println!("{current}");
            }
        }
        ConfigCommand::GetContexts => {
            let mut names: Vec<_> = config.contexts.keys().cloned().collect();
            names.sort();
            for name in names {
                println!("{name}");
            }
        }
    }
    Ok(())
}

fn config_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| anyhow::anyhow!("HOME is not set"))?;
    Ok(Path::new(&home).join(".zann").join("config.json"))
}

fn known_hosts_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| anyhow::anyhow!("HOME is not set"))?;
    Ok(Path::new(&home).join(".zann").join("known_hosts.json"))
}

pub(crate) fn load_config() -> anyhow::Result<CliConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(CliConfig::default());
    }
    let contents = fs::read_to_string(path)?;
    let config = serde_json::from_str(&contents)?;
    Ok(config)
}

pub(crate) fn save_config(config: &CliConfig) -> anyhow::Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let contents = serde_json::to_string_pretty(config)?;
    write_private(&path, contents.as_bytes())?;
    Ok(())
}

pub(crate) fn resolve_addr(
    arg: Option<String>,
    addr_arg: Option<String>,
    context_arg: Option<String>,
    config: &CliConfig,
) -> anyhow::Result<String> {
    if let Some(addr) = arg.or(addr_arg) {
        return Ok(addr);
    }
    let context_name = context_arg.or_else(|| config.current_context.clone());
    if let Some(context_name) = context_name {
        let Some(context) = config.contexts.get(&context_name) else {
            anyhow::bail!("context not found: {}", context_name);
        };
        return Ok(context.addr.clone());
    }
    Ok(DEFAULT_ADDR.to_string())
}

pub(crate) fn ensure_secure_addr(addr: &str, allow_insecure: bool) -> anyhow::Result<()> {
    if addr.starts_with("http://") && !allow_insecure {
        anyhow::bail!("refusing to use http:// without --insecure");
    }
    Ok(())
}

pub(crate) fn normalize_server_key(addr: &str) -> String {
    addr.trim_end_matches('/').to_string()
}

pub(crate) fn load_known_hosts() -> anyhow::Result<HashMap<String, String>> {
    let path = known_hosts_path()?;
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let contents = fs::read_to_string(path)?;
    let map = serde_json::from_str(&contents)?;
    Ok(map)
}

pub(crate) fn save_known_hosts(entries: &HashMap<String, String>) -> anyhow::Result<()> {
    let path = known_hosts_path()?;
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let contents = serde_json::to_string_pretty(entries)?;
    write_private(&path, contents.as_bytes())?;
    Ok(())
}

/// Owner-only permissions for `~/.zann` state, mirroring
/// `zann_app::secure_file` (the CLI does not depend on `zann-app`).
fn write_private(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("path has no parent directory"))?;
        let tmp_path = parent.join(format!(".{}.tmp", uuid::Uuid::now_v7().simple()));
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;
        let result = (|| -> anyhow::Result<()> {
            file.write_all(contents)?;
            file.sync_all()?;
            std::fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
                .map_err(|err| anyhow::anyhow!(err))?;
            Ok(())
        })();
        drop(file);
        match result {
            Ok(()) => fs::rename(&tmp_path, path).map_err(|err| anyhow::anyhow!(err)),
            Err(err) => {
                let _ = fs::remove_file(&tmp_path);
                Err(err)
            }
        }
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents)?;
        Ok(())
    }
}

fn ensure_private_dir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|err| anyhow::anyhow!(err))?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn saved_config_and_known_hosts_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("zann-cli-perm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        let config = dir.join("config.json");
        let hosts = dir.join("known_hosts.json");

        write_private(&config, b"{}").expect("write config");
        write_private(&hosts, b"{}").expect("write known hosts");

        let assert_private = |path: &Path| {
            let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} must be 0600", path.display());
        };
        assert_private(&config);
        assert_private(&hosts);

        ensure_private_dir(&dir).expect("ensure dir");
        let dir_mode = fs::metadata(&dir).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);

        let _ = fs::remove_dir_all(&dir);
    }
}
