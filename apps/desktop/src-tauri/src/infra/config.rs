use std::path::Path;

use crate::constants::{CONFIG_FILENAME, SETTINGS_FILENAME};
use crate::state::{CliConfig, CliContext};
use crate::types::DesktopSettings;
use zann_keystore::RememberedUnlock;

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

/// UI preferences come from `desktop.json`; the remembered unlock comes from
/// the file `zann-keystore` owns, so a key enrolled in another client is
/// visible here too. Older `desktop.json` files carry it inline — those values
/// are adopted once and then dropped on the next write.
pub fn load_settings(root: &Path) -> Result<DesktopSettings, anyhow::Error> {
    let path = root.join(SETTINGS_FILENAME);
    let mut settings = if path.exists() {
        serde_json::from_str::<DesktopSettings>(&std::fs::read_to_string(&path)?)?
    } else {
        DesktopSettings::default()
    };

    let shared = RememberedUnlock::load(root).map_err(|err| anyhow::anyhow!(err.to_string()))?;
    if shared == RememberedUnlock::default() && settings.remembered != RememberedUnlock::default() {
        settings
            .remembered
            .save(root)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    } else {
        settings.remembered = shared;
    }
    Ok(settings)
}

pub fn save_settings(root: &Path, settings: DesktopSettings) -> Result<(), anyhow::Error> {
    settings
        .remembered
        .save(root)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    // The remembered fields are flattened into the API shape the UI reads, but
    // they must not be written back into `desktop.json`: one owner per file.
    let mut value = serde_json::to_value(&settings)?;
    if let serde_json::Value::Object(map) = &mut value {
        for key in ["unlock_source", "hardware_keys", "wrapped_master_key"] {
            map.remove(key);
        }
    }
    std::fs::write(
        root.join(SETTINGS_FILENAME),
        serde_json::to_string_pretty(&value)?,
    )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use zann_keystore::{HardwareKeyEntry, UnlockSource};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("zann-cfg-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn enrolled() -> RememberedUnlock {
        RememberedUnlock {
            unlock_source: UnlockSource::HardwareKey,
            hardware_keys: vec![HardwareKeyEntry {
                label: "YubiKey".to_string(),
                credential_id: "Y2lk".to_string(),
                salt: "c2FsdA==".to_string(),
                wrapped_master_key: "d3JhcHBlZA==".to_string(),
                enrolled_at: "2026-08-08T00:00:00Z".to_string(),
            }],
            wrapped_master_key: None,
        }
    }

    #[test]
    fn an_inline_remembered_unlock_moves_to_the_shared_file() {
        let root = scratch("migrate");
        std::fs::write(
            root.join(SETTINGS_FILENAME),
            serde_json::to_string(&DesktopSettings {
                remember_unlock: true,
                remembered: enrolled(),
                ..DesktopSettings::default()
            })
            .expect("serialize"),
        )
        .expect("write settings");

        let loaded = load_settings(&root).expect("load");
        assert_eq!(loaded.remembered, enrolled());
        assert_eq!(RememberedUnlock::load(&root).expect("shared"), enrolled());
    }

    #[test]
    fn the_shared_file_wins_over_a_stale_desktop_json() {
        let root = scratch("shared-wins");
        enrolled().save(&root).expect("save shared");
        std::fs::write(root.join(SETTINGS_FILENAME), "{\"remember_unlock\":true}")
            .expect("write settings");

        assert_eq!(load_settings(&root).expect("load").remembered, enrolled());
    }

    #[test]
    fn saving_leaves_the_remembered_unlock_out_of_desktop_json() {
        let root = scratch("split");
        save_settings(
            &root,
            DesktopSettings {
                remember_unlock: true,
                remembered: enrolled(),
                ..DesktopSettings::default()
            },
        )
        .expect("save");

        let written = std::fs::read_to_string(root.join(SETTINGS_FILENAME)).expect("read");
        assert!(!written.contains("hardware_keys"));
        assert!(!written.contains("unlock_source"));
        assert!(written.contains("remember_unlock"));
        // ...and it is in the file the other clients read.
        assert_eq!(RememberedUnlock::load(&root).expect("shared"), enrolled());
    }
}
