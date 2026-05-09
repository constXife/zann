use std::path::Path;

use crate::constants::CONFIG_FILENAME;
use crate::state::{CliConfig, CliContext};

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
    let new_value = serde_json::to_value(config)?;
    let merged_value = if let Ok(existing) = std::fs::read_to_string(&path) {
        if let (Ok(mut existing_value), serde_json::Value::Object(new_map)) =
            (serde_json::from_str::<serde_json::Value>(&existing), new_value.clone())
        {
            if let serde_json::Value::Object(existing_map) = &mut existing_value {
                for (key, value) in new_map {
                    if key == "identity" && value.is_null() && existing_map.contains_key("identity") {
                        continue;
                    }
                    existing_map.insert(key, value);
                }
                existing_value
            } else {
                serde_json::Value::Object(new_map)
            }
        } else {
            new_value
        }
    } else {
        new_value
    };
    let contents = serde_json::to_string_pretty(&merged_value)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
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
