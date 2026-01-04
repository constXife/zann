use std::path::Path;

use crate::constants::{CONFIG_FILENAME, SETTINGS_FILENAME};
use crate::state::{CliConfig, CliContext};
use crate::types::DesktopSettings;

pub fn load_config(root: &Path) -> Result<CliConfig, anyhow::Error> {
    let path = root.join(CONFIG_FILENAME);
    if !path.exists() {
        return Ok(CliConfig::default());
    }
    let contents = std::fs::read_to_string(path)?;
    let config = serde_json::from_str(&contents)?;
    Ok(config)
}

pub fn save_config(root: &Path, config: &CliConfig) -> Result<(), anyhow::Error> {
    let path = root.join(CONFIG_FILENAME);
    let contents = serde_json::to_string_pretty(config)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    Ok(())
}

pub fn load_settings(root: &Path) -> Result<DesktopSettings, anyhow::Error> {
    let path = root.join(SETTINGS_FILENAME);
    if !path.exists() {
        return Ok(DesktopSettings::default());
    }
    let contents = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

pub fn save_settings(root: &Path, settings: DesktopSettings) -> Result<(), anyhow::Error> {
    let path = root.join(SETTINGS_FILENAME);
    let contents = serde_json::to_string_pretty(&settings)?;
    std::fs::write(path, contents)?;
    Ok(())
}

pub fn ensure_context<'a>(config: &'a mut CliConfig, name: &str, addr: &str) -> &'a mut CliContext {
    config
        .contexts
        .entry(name.to_string())
        .or_insert_with(|| CliContext {
            addr: addr.to_string(),
            needs_salt_update: false,
            server_id: None,
            server_fingerprint: None,
            expected_master_key_fp: None,
            tokens: std::collections::HashMap::new(),
            current_token: None,
            storage_id: None,
        })
}
