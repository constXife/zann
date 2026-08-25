use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::State;
use zann_core::crypto::SecretKey;
use zann_core::SecurityProfileRegistry;
use zann_db::{connect_sqlite_file_with_max, migrate_local, SqliteFileLocation, SqlitePool};

use crate::constants::{LOCAL_DB_FILENAME, SECURITY_PROFILES_YAML};
use crate::types::{DesktopSettings, OidcConfigResponse, OidcDiscovery, SystemInfoResponse};
use zann_core::api::auth::PreloginResponse;

pub struct AppState {
    pub pool: SqlitePool,
    pub root: PathBuf,
    pub master_key: tauri::async_runtime::RwLock<Option<Arc<SecretKey>>>,
    pub settings: tauri::async_runtime::RwLock<DesktopSettings>,
    pub security_profiles: SecurityProfileRegistry,
    pub pending_logins: Mutex<HashMap<String, PendingLogin>>,
}

#[derive(Clone)]
pub struct PendingLogin {
    pub server_url: String,
    pub discovery: OidcDiscovery,
    pub oidc_config: OidcConfigResponse,
    pub oauth_state: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub fingerprint_new: Option<String>,
    pub fingerprint_trusted: bool,
    pub pending_result: Option<PendingLoginResult>,
}

#[derive(Clone)]
pub struct PendingLoginResult {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub email: String,
    pub prelogin: PreloginResponse,
    pub info: SystemInfoResponse,
    pub token_name: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct StorageConfig {
    #[serde(default)]
    pub backup_dir: Option<String>,
    #[serde(default)]
    pub backup_retention_days: Option<i64>,
    #[serde(default)]
    pub backup_max_count: Option<usize>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct TokenEntry {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub access_expires_at: Option<String>,
    #[serde(default)]
    pub service_account_token: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CliContext {
    pub addr: String,
    #[serde(default)]
    pub needs_salt_update: bool,
    #[serde(default)]
    pub server_id: Option<String>,
    #[serde(default)]
    pub server_fingerprint: Option<String>,
    #[serde(default)]
    pub expected_master_key_fp: Option<String>,
    #[serde(default)]
    pub tokens: HashMap<String, TokenEntry>,
    #[serde(default)]
    pub current_token: Option<String>,
    #[serde(default)]
    pub storage_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CliConfig {
    #[serde(default)]
    pub current_context: Option<String>,
    #[serde(default)]
    pub contexts: HashMap<String, CliContext>,
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
    #[serde(default)]
    pub storage: StorageConfig,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IdentityConfig {
    pub kdf_salt: String,
    pub kdf_params: zann_core::api::auth::KdfParams,
    #[serde(default)]
    pub salt_fingerprint: Option<String>,
    #[serde(default)]
    pub first_seen_at: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

pub async fn ensure_unlocked(state: &State<'_, AppState>) -> Result<(), String> {
    if state.master_key.read().await.is_some() {
        Ok(())
    } else {
        Err("vault is locked".to_string())
    }
}

pub fn local_root_path() -> Result<PathBuf, anyhow::Error> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("HOME is not set"))?;
    Ok(home.join(".zann"))
}

pub fn local_db_path(root: &Path) -> PathBuf {
    root.join(LOCAL_DB_FILENAME)
}

pub fn build_state() -> Result<AppState, anyhow::Error> {
    let root = local_root_path()?;
    build_state_at_root(root)
}

fn build_state_at_root(root: PathBuf) -> Result<AppState, anyhow::Error> {
    let db_path = local_db_path(&root);
    let location = SqliteFileLocation::from_path(&db_path)?;
    let root = location.root().to_path_buf();
    std::fs::create_dir_all(&root)?;
    let pool = tauri::async_runtime::block_on(connect_sqlite_file_with_max(&location, 5))?;
    tauri::async_runtime::block_on(migrate_local(&pool))?;
    let security_profiles = SecurityProfileRegistry::from_yaml(SECURITY_PROFILES_YAML)?;
    Ok(AppState {
        pool,
        root,
        master_key: tauri::async_runtime::RwLock::new(None),
        settings: tauri::async_runtime::RwLock::new(DesktopSettings::default()),
        security_profiles,
        pending_logins: Mutex::new(HashMap::new()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_state_opens_literal_filesystem_path() {
        let root =
            std::env::temp_dir().join(format!("zann-desktop-path-{} # ? %", uuid::Uuid::now_v7()));
        let db_path = local_db_path(&root);

        let state = build_state_at_root(root.clone()).expect("build desktop state");

        assert_eq!(state.root, root);
        assert!(
            db_path.exists(),
            "SQLite must create the exact path, including URI delimiters"
        );
        drop(state);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn production_state_does_not_stringify_paths_into_sqlite_uris() {
        let source = include_str!("state.rs");
        for forbidden in [
            ["format!(\"sqlite", "://"].concat(),
            ["connect_sqlite_", "path_with_max"].concat(),
            ["connect_sqlite_", "with_max"].concat(),
        ] {
            assert!(!source.contains(&forbidden));
        }
        assert!(source.contains("connect_sqlite_file_with_max"));
    }
}
