//! Backup: export, import, and Apple Passwords CSV import.
//!
//! Lifted out of the Tauri backend so that every client can reach it. The
//! desktop app used to be the only one able to export a vault, while
//! `zann-ffi` shipped `Unimplemented` stubs in place of these functions, which
//! left the COSMIC client with no way to get its own data out.
//!
//! Nothing here touches the OS: callers supply the paths and the unlocked key.
//! See docs/adr/0002-client-strategy.md.

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::future::Future;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use chrono::Utc;
use percent_encoding::percent_decode_str;
use serde::de::{
    self, DeserializeSeed, Deserializer as _, IgnoredAny, MapAccess, SeqAccess, Visitor,
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use url::Url;
use uuid::Uuid;
use zann_core::crypto::SecretKey;
use zann_core::{EncryptedPayload, FieldKind, FieldValue, ItemsService, VaultKind};
use zann_db::local::{LocalItem, LocalItemRepo, LocalStorageRepo, LocalVaultRepo};
use zann_db::services::{LocalServices, MAX_ITEM_NAME_LEN};
use zann_db::SqlitePool;

pub const BACKUP_VERSION: u32 = 1;
const EXPORT_PAGE_LIMIT: i64 = 200;
const APPLE_PASSWORDS_MAX_FILE_BYTES: u64 = 50 * 1024 * 1024;
const APPLE_PASSWORDS_MAX_ROWS: usize = 100_000;
const APPLE_PASSWORDS_REQUIRED_HEADERS: [&str; 6] =
    ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"];

/// Everything a backup operation needs from its host: an open pool, an unlocked
/// master key, and a directory to keep logs and default output paths under.
///
/// The caller is responsible for having unlocked the vault; holding an
/// `Arc<SecretKey>` is the proof, which is why there is no `ensure_unlocked`
/// here.
pub struct BackupCtx {
    pub pool: SqlitePool,
    pub master_key: Arc<SecretKey>,
    pub root: PathBuf,
}

impl BackupCtx {
    pub fn new(pool: SqlitePool, master_key: Arc<SecretKey>, root: PathBuf) -> Self {
        Self {
            pool,
            master_key,
            root,
        }
    }

    /// Where an export lands when the caller has no preference of its own.
    pub fn default_export_path(&self) -> PathBuf {
        default_backup_path(&self.root)
    }

    fn log(&self, message: &str) {
        let logs_dir = self.root.join("logs");
        let _ = std::fs::create_dir_all(&logs_dir);
        let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(logs_dir.join("backup.log"))
        else {
            return;
        };
        let _ = writeln!(file, "{} {}", Utc::now().to_rfc3339(), message);
    }
}

/// A failure carrying a stable `kind` for the UI to translate, per ADR 0001.
/// Clients must not parse `message`.
#[derive(thiserror::Error)]
#[error("{message}")]
pub struct BackupError {
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
    pub kind: String,
    pub message: String,
}

impl BackupError {
    pub fn source(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self {
            kind: "backup_failed".into(),
            message: "backup operation failed".into(),
            source: Some(error.into()),
        }
    }
    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            source: None,
            kind: kind.into(),
            message: message.into(),
        }
    }
}

impl From<&str> for BackupError {
    fn from(message: &str) -> Self {
        Self::new("backup_failed", message)
    }
}

impl From<String> for BackupError {
    fn from(message: String) -> Self {
        Self::new("backup_failed", message)
    }
}

impl From<anyhow::Error> for BackupError {
    fn from(err: anyhow::Error) -> Self {
        Self::source(err)
    }
}

// ---------------------------------------------------------------------------
// The on-disk backup format. Changing any of this changes what older builds can
// read, so it is versioned by `BACKUP_VERSION`.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct PlainBackupStorage {
    pub id: String,
    pub kind: i32,
    pub name: String,
    pub server_url: Option<String>,
    pub server_name: Option<String>,
    pub server_fingerprint: Option<String>,
    pub account_subject: Option<String>,
    pub personal_vaults_enabled: bool,
    pub auth_method: Option<i32>,
}

#[derive(Serialize, Deserialize)]
pub struct PlainBackupVault {
    pub id: String,
    pub storage_id: String,
    pub name: String,
    pub kind: i32,
    pub is_default: bool,
}

#[derive(Serialize, Deserialize)]
pub struct PlainBackupItem {
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub favorite: bool,
    pub id: Option<String>,
    pub storage_id: String,
    pub vault_id: String,
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload: EncryptedPayload,
    pub updated_at: String,
    pub version: i64,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportReport {
    pub path: String,
    pub storages_count: usize,
    pub vaults_count: usize,
    pub items_count: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportReport {
    pub imported_items: usize,
    pub skipped_existing: usize,
    pub skipped_missing_storage: usize,
    pub skipped_missing_vault: usize,
    pub skipped_deleted: usize,
}

pub fn insert_payload_field(
    payload: &mut EncryptedPayload,
    key: &str,
    kind: FieldKind,
    value: Option<&str>,
) {
    let Some(value) = value else {
        return;
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    payload.fields.insert(
        key.to_string(),
        FieldValue {
            kind,
            value: trimmed.to_string(),
            meta: None,
        },
    );
}

#[cfg(test)]
#[path = "../../tests/maintenance/backup.rs"]
mod tests;

mod totp;
pub use totp::*;

mod apple;
pub use apple::*;

mod export;
pub use export::*;

mod import;
pub use import::*;

mod stream;
pub use stream::*;

impl std::fmt::Debug for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
