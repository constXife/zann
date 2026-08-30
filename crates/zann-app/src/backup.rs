//! Backup: export, import, and Apple Passwords CSV import.
//!
//! Lifted out of the Tauri backend so that every client can reach it. The
//! desktop app used to be the only one able to export a vault, while
//! `zann-ffi` shipped `Unimplemented` stubs in place of these functions, which
//! left the COSMIC client with no way to get its own data out.
//!
//! Nothing here touches the OS: callers supply the paths and the unlocked key.
//! See docs/adr/0002-client-strategy.md.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::future::Future;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

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
use zann_core::vault_crypto as core_crypto;
use zann_core::{
    AuthMethod, EncryptedPayload, FieldKind, FieldValue, ItemsService, StorageKind, VaultKind,
    VaultsService,
};
use zann_db::local::{
    KeyWrapType, LocalItem, LocalItemRepo, LocalStorage, LocalStorageRepo, LocalVault,
    LocalVaultRepo,
};
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
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct BackupError {
    pub kind: String,
    pub message: String,
}

impl BackupError {
    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
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
        Self::new("backup_failed", err.to_string())
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

/// Importing into a remote storage still needs the HTTP and token machinery
/// that lives outside this crate, so the routing decision is made here and the
/// work is handed back to the caller.
pub enum ImportOutcome {
    Done(ImportReport),
    NeedsRemote(LocalStorage),
}

pub struct TotpMeta {
    pub secret: String,
    pub otp_type: Option<String>,
    pub issuer: Option<String>,
    pub label: Option<String>,
    pub algorithm: Option<String>,
    pub digits: Option<String>,
    pub period: Option<String>,
}

pub fn extract_totp_meta(value: &str) -> Option<TotpMeta> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let url = Url::parse(trimmed).ok()?;
    if url.scheme() != "otpauth" {
        return None;
    }
    let otp_type = url.host_str().map(|value| value.to_string());
    let mut secret = None;
    let mut issuer = None;
    let mut label = None;
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;
    let raw_path = url.path().trim_matches('/');
    if !raw_path.is_empty() {
        let decoded = percent_decode_str(raw_path).decode_utf8_lossy();
        if let Some((path_issuer, path_label)) = decoded.split_once(':') {
            let path_issuer = path_issuer.trim();
            let path_label = path_label.trim();
            if !path_issuer.is_empty() && issuer.is_none() {
                issuer = Some(path_issuer.to_string());
            }
            if !path_label.is_empty() {
                label = Some(path_label.to_string());
            }
        } else {
            let path_label = decoded.trim();
            if !path_label.is_empty() {
                label = Some(path_label.to_string());
            }
        }
    }
    for (key, val) in url.query_pairs() {
        if key.eq_ignore_ascii_case("secret") {
            let value = val.trim();
            if !value.is_empty() {
                secret = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("issuer") {
            let value = val.trim();
            if !value.is_empty() {
                issuer = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("algorithm") {
            let value = val.trim();
            if !value.is_empty() {
                algorithm = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("digits") {
            let value = val.trim();
            if !value.is_empty() {
                digits = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("period") {
            let value = val.trim();
            if !value.is_empty() {
                period = Some(value.to_string());
            }
        }
    }
    let secret = secret?;
    Some(TotpMeta {
        secret,
        otp_type,
        issuer,
        label,
        algorithm,
        digits,
        period,
    })
}

#[derive(serde::Deserialize)]
pub struct ApplePasswordsRow {
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    #[serde(rename = "Username")]
    pub username: Option<String>,
    #[serde(rename = "Password")]
    pub password: Option<String>,
    #[serde(rename = "Notes")]
    pub notes: Option<String>,
    #[serde(rename = "OTPAuth")]
    pub otp_auth: Option<String>,
}

/// A read-only summary used by clients before they ask for confirmation.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ApplePasswordsPreflight {
    pub total_rows: usize,
    pub importable_items: usize,
    pub duplicate_rows: usize,
    pub invalid_rows: usize,
}

/// What the Apple Passwords import changed.
///
/// Existing paths and repeated titles are never overwritten or dropped. A
/// numeric suffix is added instead and counted in `renamed_items`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ApplePasswordsImportReport {
    pub imported_items: usize,
    pub renamed_items: usize,
    pub skipped_invalid: usize,
}

fn apple_passwords_reader(path: &Path) -> Result<csv::Reader<std::fs::File>, BackupError> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        BackupError::new(
            "apple_csv_open_failed",
            format!("could not open CSV: {err}"),
        )
    })?;
    if metadata.len() > APPLE_PASSWORDS_MAX_FILE_BYTES {
        return Err(BackupError::new(
            "apple_csv_too_large",
            "Apple Passwords CSV exceeds the 50 MiB limit",
        ));
    }

    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .from_path(path)
        .map_err(|err| BackupError::new("apple_csv_open_failed", err.to_string()))?;
    let headers = reader
        .headers()
        .map_err(|err| BackupError::new("apple_csv_invalid", err.to_string()))?
        .clone();
    let missing = APPLE_PASSWORDS_REQUIRED_HEADERS
        .iter()
        .filter(|required| !headers.iter().any(|header| header == **required))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(BackupError::new(
            "apple_csv_headers_invalid",
            format!("missing Apple Passwords columns: {}", missing.join(", ")),
        ));
    }
    Ok(reader)
}

/// Validate an Apple Passwords export without retaining any secret fields.
pub fn apple_passwords_preflight(path: &Path) -> Result<ApplePasswordsPreflight, BackupError> {
    let mut reader = apple_passwords_reader(path)?;
    let mut report = ApplePasswordsPreflight::default();
    let mut seen_titles = HashSet::new();

    for result in reader.deserialize::<ApplePasswordsRow>() {
        if report.total_rows >= APPLE_PASSWORDS_MAX_ROWS {
            return Err(BackupError::new(
                "apple_csv_too_many_rows",
                "Apple Passwords CSV exceeds the 100000-row limit",
            ));
        }
        let row = result.map_err(|err| BackupError::new("apple_csv_invalid", err.to_string()))?;
        report.total_rows += 1;
        let title = row.title.trim();
        if title.is_empty() {
            report.invalid_rows += 1;
            continue;
        }
        report.importable_items += 1;
        if !seen_titles.insert(title.to_string()) {
            report.duplicate_rows += 1;
        }
    }
    Ok(report)
}

async fn apple_passwords_target(
    ctx: &BackupCtx,
    target_storage_id: Option<&str>,
) -> Result<(Uuid, Uuid), BackupError> {
    let services = LocalServices::new(&ctx.pool, ctx.master_key.as_ref());
    let Some(target_storage_id) = target_storage_id
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "local")
    else {
        let vault = services
            .ensure_default_local_personal()
            .await
            .map_err(|err| BackupError::new(err.kind, err.message))?;
        return Ok((Uuid::nil(), vault.id));
    };

    let storage_id = Uuid::parse_str(target_storage_id)
        .map_err(|_| BackupError::new("apple_import_target_invalid", "invalid storage id"))?;
    let storage_repo = LocalStorageRepo::new(&ctx.pool);
    let storage = storage_repo
        .get(storage_id)
        .await
        .map_err(|err| BackupError::new("storage_lookup_failed", err.to_string()))?
        .ok_or_else(|| BackupError::new("storage_not_found", "storage not found"))?;
    if storage.kind == StorageKind::LocalOnly {
        let vault = services
            .ensure_default_local_personal()
            .await
            .map_err(|err| BackupError::new(err.kind, err.message))?;
        return Ok((Uuid::nil(), vault.id));
    }
    if !storage.personal_vaults_enabled {
        return Err(BackupError::new(
            "personal_vaults_disabled",
            "personal vaults are disabled for this server",
        ));
    }

    let vault_repo = LocalVaultRepo::new(&ctx.pool);
    let vault = vault_repo
        .list_by_storage(storage.id)
        .await
        .map_err(|err| BackupError::new("vault_lookup_failed", err.to_string()))?
        .into_iter()
        .find(|vault| vault.kind == VaultKind::Personal)
        .ok_or_else(|| {
            BackupError::new(
                "personal_vault_missing",
                "sync this server before importing into its personal vault",
            )
        })?;
    Ok((storage.id, vault.id))
}

fn apple_passwords_payload(row: &ApplePasswordsRow) -> EncryptedPayload {
    let mut payload = EncryptedPayload::new("login");
    insert_payload_field(
        &mut payload,
        "username",
        FieldKind::Text,
        row.username.as_deref(),
    );
    insert_payload_field(
        &mut payload,
        "password",
        FieldKind::Password,
        row.password.as_deref(),
    );
    insert_payload_field(&mut payload, "url", FieldKind::Url, row.url.as_deref());
    insert_payload_field(&mut payload, "notes", FieldKind::Note, row.notes.as_deref());
    if let Some(meta) = row.otp_auth.as_deref().and_then(extract_totp_meta) {
        insert_payload_field(
            &mut payload,
            "totp_secret",
            FieldKind::Otp,
            Some(meta.secret.as_str()),
        );
        let mut extra = payload.extra.take().unwrap_or_default();
        for (key, value) in [
            ("otp_type", meta.otp_type),
            ("otp_issuer", meta.issuer),
            ("otp_algorithm", meta.algorithm),
            ("otp_label", meta.label),
            ("otp_digits", meta.digits),
            ("otp_period", meta.period),
        ] {
            if let Some(value) = value {
                extra.insert(key.to_string(), value);
            }
        }
        if !extra.is_empty() {
            payload.extra = Some(extra);
        }
    }
    payload
}

fn suffixed_import_path(base: &str, attempt: usize) -> String {
    let suffix = format!(" ({attempt})");
    let (folder, name) = base
        .rsplit_once('/')
        .map_or((None, base), |(folder, name)| (Some(folder), name));
    let available = MAX_ITEM_NAME_LEN.saturating_sub(suffix.len());
    let mut shortened = String::new();
    for character in name.chars() {
        if shortened.len() + character.len_utf8() > available {
            break;
        }
        shortened.push(character);
    }
    match folder {
        Some(folder) => format!("{folder}/{shortened}{suffix}"),
        None => format!("{shortened}{suffix}"),
    }
}

/// Import an Apple Passwords CSV into the selected personal vault.
///
/// The file is streamed. Duplicate titles and paths already present in the
/// vault receive ` (2)`, ` (3)`, ... suffixes so distinct credentials are not
/// silently discarded.
pub async fn apple_passwords_import(
    ctx: &BackupCtx,
    path: PathBuf,
    target_storage_id: Option<String>,
) -> Result<ApplePasswordsImportReport, BackupError> {
    // Parse the entire source before the first write. A malformed row near the
    // end therefore cannot produce a surprising partial import.
    let _ = apple_passwords_preflight(&path)?;
    let mut reader = apple_passwords_reader(&path)?;
    let (storage_id, vault_id) = apple_passwords_target(ctx, target_storage_id.as_deref()).await?;
    let services = LocalServices::new(&ctx.pool, ctx.master_key.as_ref());
    let mut report = ApplePasswordsImportReport::default();
    ctx.log(&format!("apple_import_start path={}", path.display()));

    for (index, result) in reader.deserialize::<ApplePasswordsRow>().enumerate() {
        if index >= APPLE_PASSWORDS_MAX_ROWS {
            return Err(BackupError::new(
                "apple_csv_too_many_rows",
                "Apple Passwords CSV exceeds the 100000-row limit",
            ));
        }
        let row = result.map_err(|err| BackupError::new("apple_csv_invalid", err.to_string()))?;
        let title = row.title.trim();
        if title.is_empty() {
            report.skipped_invalid += 1;
            continue;
        }

        let payload = apple_passwords_payload(&row);
        let mut attempt = 1usize;
        loop {
            let candidate = if attempt == 1 {
                title.to_string()
            } else {
                suffixed_import_path(title, attempt)
            };
            match services
                .put_item(
                    storage_id,
                    vault_id,
                    candidate,
                    "login".to_string(),
                    payload.clone(),
                )
                .await
            {
                Ok(_) => {
                    report.imported_items += 1;
                    if attempt > 1 {
                        report.renamed_items += 1;
                    }
                    break;
                }
                Err(err) if err.kind == "item_exists" && attempt < 10_000 => {
                    attempt += 1;
                }
                Err(err)
                    if matches!(
                        err.kind.as_str(),
                        "path_required"
                            | "path_invalid"
                            | "path_segment_invalid"
                            | "name_too_long"
                            | "path_too_long"
                            | "path_segments_limit"
                            | "payload_too_large"
                    ) =>
                {
                    report.skipped_invalid += 1;
                    break;
                }
                Err(err) => return Err(BackupError::new(err.kind, err.message)),
            }
        }
    }

    ctx.log(&format!(
        "apple_import_ok path={} imported={} renamed={} skipped_invalid={}",
        path.display(),
        report.imported_items,
        report.renamed_items,
        report.skipped_invalid
    ));
    Ok(report)
}

pub fn slugify(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in value.chars() {
        let next = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if next == '-' {
            if last_dash || out.is_empty() {
                continue;
            }
            last_dash = true;
            out.push('-');
        } else {
            last_dash = false;
            out.push(next);
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "imported-vault".to_string()
    } else {
        trimmed
    }
}

pub async fn plain_export(ctx: &BackupCtx, path: PathBuf) -> Result<ExportReport, BackupError> {
    let master_key = ctx.master_key.clone();
    let services = LocalServices::new(&ctx.pool, master_key.as_ref());
    let storage_repo = LocalStorageRepo::new(&ctx.pool);
    let vault_repo = LocalVaultRepo::new(&ctx.pool);
    let item_repo = LocalItemRepo::new(&ctx.pool);

    let storages = storage_repo.list().await.map_err(|err| err.to_string())?;

    let mut backup_storages = Vec::with_capacity(storages.len());
    let mut backup_vaults = Vec::new();
    let mut vault_queue = VecDeque::new();

    for storage in storages {
        let storage_id = storage.id;
        backup_storages.push(PlainBackupStorage {
            id: storage_id.to_string(),
            kind: storage.kind.as_i32(),
            name: storage.name.clone(),
            server_url: storage.server_url.clone(),
            server_name: storage.server_name.clone(),
            server_fingerprint: storage.server_fingerprint.clone(),
            account_subject: storage.account_subject.clone(),
            personal_vaults_enabled: storage.personal_vaults_enabled,
            auth_method: storage.auth_method.map(|method| method.as_i32()),
        });

        let vaults = vault_repo
            .list_by_storage(storage_id)
            .await
            .map_err(|err| err.to_string())?;
        for vault in vaults {
            backup_vaults.push(PlainBackupVault {
                id: vault.id.to_string(),
                storage_id: storage_id.to_string(),
                name: vault.name.clone(),
                kind: vault.kind.as_i32(),
                is_default: vault.is_default,
            });
            vault_queue.push_back((storage_id, vault.id));
        }
    }

    let output_path = path;
    ctx.log(&format!("export_start path={}", output_path.display()));
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let file =
        crate::secure_file::create_private_file(&output_path).map_err(|err| err.to_string())?;
    let mut writer = BufWriter::new(file);
    let exported_at = Utc::now().to_rfc3339();
    let mut streamer = ExportItemStreamer::new(services, item_repo, vault_queue);
    let items_count = match write_backup_streaming(
        &mut writer,
        BACKUP_VERSION,
        &exported_at,
        &backup_storages,
        &backup_vaults,
        &mut streamer,
    )
    .await
    {
        Ok(count) => count,
        Err(err) => {
            ctx.log(&format!(
                "export_failed path={} error={}",
                output_path.display(),
                err
            ));
            return Err(err.to_string().into());
        }
    };
    if let Err(err) = writer.flush() {
        ctx.log(&format!(
            "export_failed path={} error={}",
            output_path.display(),
            err
        ));
        return Err(err.to_string().into());
    }
    ctx.log(&format!(
        "export_ok path={} storages={} vaults={} items={}",
        output_path.display(),
        backup_storages.len(),
        backup_vaults.len(),
        items_count
    ));

    Ok(ExportReport {
        path: output_path.display().to_string(),
        storages_count: backup_storages.len(),
        vaults_count: backup_vaults.len(),
        items_count,
    })
}

pub async fn plain_import(
    ctx: &BackupCtx,
    path: PathBuf,
    target_storage_id: Option<String>,
) -> Result<ImportOutcome, BackupError> {
    ctx.log(&format!(
        "import_mode_raw target_storage_id={}",
        target_storage_id.as_deref().unwrap_or("<none>")
    ));
    let target_storage_id = match target_storage_id.as_deref() {
        Some("local") | Some("") => None,
        other => other.map(str::to_string),
    };
    ctx.log(&format!(
        "import_mode_select target_storage_id={}",
        target_storage_id.as_deref().unwrap_or("<none>")
    ));
    let master_key = ctx.master_key.clone();
    let services = LocalServices::new(&ctx.pool, master_key.as_ref());
    let storage_repo = LocalStorageRepo::new(&ctx.pool);
    let vault_repo = LocalVaultRepo::new(&ctx.pool);
    let item_repo = LocalItemRepo::new(&ctx.pool);

    let mut target_storage_id = target_storage_id;
    if target_storage_id.is_none() {
        if let Ok(storages) = storage_repo.list().await {
            let remote = storages
                .into_iter()
                .filter(|storage| storage.kind == StorageKind::Remote)
                .collect::<Vec<_>>();
            if remote.len() == 1 {
                target_storage_id = Some(remote[0].id.to_string());
                ctx.log(&format!("import_mode_fallback storage_id={}", remote[0].id));
            }
        }
    }

    if let Some(target_storage_id) = target_storage_id.as_deref() {
        let target_id =
            Uuid::parse_str(target_storage_id).map_err(|_| "invalid storage id".to_string())?;
        match storage_repo.get(target_id).await {
            Ok(Some(storage)) => {
                ctx.log(&format!(
                    "import_mode_candidate storage_id={} kind={}",
                    storage.id,
                    storage.kind.as_i32()
                ));
                if storage.kind == StorageKind::Remote {
                    ctx.log(&format!("import_mode_remote storage_id={}", storage.id));
                    return Ok(ImportOutcome::NeedsRemote(storage));
                }
                ctx.log("import_mode_fallback reason=storage_not_remote");
            }
            Ok(None) => {
                ctx.log("import_mode_fallback reason=storage_not_found");
            }
            Err(err) => {
                ctx.log(&format!(
                    "import_mode_fallback reason=storage_lookup_failed error={}",
                    err
                ));
            }
        }
    }

    let input_path = path;
    ctx.log(&format!("import_start path={}", input_path.display()));
    ctx.log(&format!("import_read_start path={}", input_path.display()));
    let backup_meta = match read_backup_metadata(&input_path) {
        Ok(meta) => meta,
        Err(err) => {
            ctx.log(&format!(
                "import_failed path={} error={}",
                input_path.display(),
                err
            ));
            return Err(err.to_string().into());
        }
    };
    ctx.log(&format!(
        "import_read_ok path={} storages={} vaults={} items=streaming",
        input_path.display(),
        backup_meta.storages.len(),
        backup_meta.vaults.len()
    ));
    if backup_meta.version != BACKUP_VERSION {
        ctx.log(&format!(
            "import_failed path={} error=unsupported_version version={}",
            input_path.display(),
            backup_meta.version
        ));
        return Err(BackupError::new(
            "backup_version_unsupported",
            "unsupported backup version",
        ));
    }

    let mut storage_map: HashMap<Uuid, Uuid> = HashMap::new();
    let local_storage_id = Uuid::nil();
    let log_error = |message: &str| {
        ctx.log(&format!(
            "import_failed path={} error={}",
            input_path.display(),
            message
        ));
        message.to_string()
    };
    let mut created_storages = 0usize;
    let mut mapped_to_local = 0usize;
    for storage in backup_meta.storages {
        let storage_id =
            Uuid::parse_str(&storage.id).map_err(|_| log_error("invalid storage id"))?;
        let kind =
            StorageKind::try_from(storage.kind).map_err(|_| log_error("invalid storage kind"))?;
        let existing = storage_repo
            .get(storage_id)
            .await
            .map_err(|err| log_error(&err.to_string()))?;
        if let Some(existing) = existing {
            storage_map.insert(storage_id, existing.id);
            continue;
        }
        if kind == StorageKind::LocalOnly {
            let local_storage = LocalStorage {
                id: storage_id,
                kind,
                name: storage.name,
                server_url: storage.server_url,
                server_name: storage.server_name,
                server_fingerprint: storage.server_fingerprint,
                account_subject: storage.account_subject,
                personal_vaults_enabled: storage.personal_vaults_enabled,
                auth_method: storage
                    .auth_method
                    .map(AuthMethod::try_from)
                    .transpose()
                    .map_err(|_| "invalid auth method")?,
            };
            storage_repo
                .upsert(&local_storage)
                .await
                .map_err(|err| log_error(&err.to_string()))?;
            storage_map.insert(storage_id, storage_id);
            created_storages += 1;
        } else {
            storage_map.insert(storage_id, local_storage_id);
            mapped_to_local += 1;
            ctx.log(&format!(
                "import_storage_mapped path={} storage_id={} mapped_to={}",
                input_path.display(),
                storage_id,
                local_storage_id
            ));
        }
    }
    ctx.log(&format!(
        "import_storages_done path={} total={} created={} mapped_to_local={}",
        input_path.display(),
        storage_map.len(),
        created_storages,
        mapped_to_local
    ));

    let mut vault_map: HashMap<(Uuid, Uuid), (Uuid, Uuid)> = HashMap::new();
    let mut created_vaults = 0usize;
    let mut reused_vaults = 0usize;
    for vault in &backup_meta.vaults {
        let backup_storage_id =
            Uuid::parse_str(&vault.storage_id).map_err(|_| log_error("invalid storage id"))?;
        let backup_vault_id =
            Uuid::parse_str(&vault.id).map_err(|_| log_error("invalid vault id"))?;
        let Some(&target_storage_id) = storage_map.get(&backup_storage_id) else {
            ctx.log(&format!(
                "import_vault_skip path={} storage_id={} vault_id={} reason=missing_storage",
                input_path.display(),
                backup_storage_id,
                backup_vault_id
            ));
            continue;
        };
        if let Some(existing) = vault_repo
            .get_by_name(target_storage_id, &vault.name)
            .await
            .map_err(|err| log_error(&err.to_string()))?
        {
            vault_map.insert(
                (backup_storage_id, backup_vault_id),
                (target_storage_id, existing.id),
            );
            reused_vaults += 1;
            ctx.log(&format!(
                "import_vault_reuse path={} storage_id={} vault_id={} existing_vault_id={} name={}",
                input_path.display(),
                backup_storage_id,
                backup_vault_id,
                existing.id,
                vault.name
            ));
            continue;
        }
        if let Some(existing) = vault_repo
            .get_by_id(target_storage_id, backup_vault_id)
            .await
            .map_err(|err| log_error(&err.to_string()))?
        {
            vault_map.insert(
                (backup_storage_id, backup_vault_id),
                (target_storage_id, existing.id),
            );
            reused_vaults += 1;
            ctx.log(&format!(
                "import_vault_reuse path={} storage_id={} vault_id={} existing_vault_id={} reason=id_match",
                input_path.display(),
                backup_storage_id,
                backup_vault_id,
                existing.id
            ));
            continue;
        }

        let vault_kind =
            VaultKind::try_from(vault.kind).map_err(|_| log_error("invalid vault kind"))?;
        let vault_id_to_use = if target_storage_id == backup_storage_id {
            backup_vault_id
        } else {
            Uuid::now_v7()
        };
        let vault_key = SecretKey::generate();
        let vault_key_enc =
            core_crypto::encrypt_vault_key(master_key.as_ref(), vault_id_to_use, &vault_key)
                .map_err(|err| log_error(&err.to_string()))?;
        let base_name = vault.name.clone();
        let mut created = false;
        for attempt in 0..6 {
            let name = if attempt == 0 {
                base_name.clone()
            } else {
                format!("{base_name} (import {attempt})")
            };
            let local_vault = LocalVault {
                id: vault_id_to_use,
                storage_id: target_storage_id,
                slug: LocalVault::local_slug(vault_id_to_use),
                name: name.clone(),
                kind: vault_kind,
                is_default: vault.is_default,
                vault_key_enc: vault_key_enc.clone(),
                key_wrap_type: KeyWrapType::Master,
                cache_key_fp: None,
                last_synced_at: None,
            };
            match vault_repo.create(&local_vault).await {
                Ok(()) => {
                    if attempt > 0 {
                        ctx.log(&format!(
                            "import_vault_renamed path={} storage_id={} vault_id={} name_from={} name_to={}",
                            input_path.display(),
                            target_storage_id,
                            vault_id_to_use,
                            base_name,
                            name
                        ));
                    }
                    vault_map.insert(
                        (backup_storage_id, backup_vault_id),
                        (target_storage_id, vault_id_to_use),
                    );
                    created_vaults += 1;
                    created = true;
                    break;
                }
                Err(err) => {
                    let message = err.to_string();
                    if message.contains(
                        "UNIQUE constraint failed: local_vaults.storage_id, local_vaults.name",
                    ) {
                        continue;
                    }
                    return Err(log_error(&message).into());
                }
            }
        }
        if !created {
            return Err(log_error("vault_name_conflict").into());
        }
    }
    ctx.log(&format!(
        "import_vaults_done path={} total={} created={} reused={}",
        input_path.display(),
        vault_map.len(),
        created_vaults,
        reused_vaults
    ));

    ctx.log(&format!(
        "import_items_start path={} total=streaming",
        input_path.display()
    ));
    #[derive(Default)]
    struct ImportCounters {
        imported_items: usize,
        skipped_existing: usize,
        skipped_missing_storage: usize,
        skipped_missing_vault: usize,
        skipped_deleted: usize,
    }

    let counters = Arc::new(Mutex::new(ImportCounters::default()));
    let api_error = Arc::new(Mutex::new(None));
    let path_display = input_path.display().to_string();
    let storage_map_ref = &storage_map;
    let vault_map_ref = &vault_map;
    let services_ref = &services;
    let item_repo_ref = &item_repo;

    let stream_result = stream_backup_items_async(&input_path, |item, index| {
        let counters = Arc::clone(&counters);
        let api_error = Arc::clone(&api_error);
        let path_display = path_display.clone();
        async move {
            ctx.log(&format!(
                "import_item_start path={} index={} item_id={}",
                path_display,
                index,
                item.id.as_deref().unwrap_or("new")
            ));
            if item.deleted_at.is_some() {
                let mut guard = counters
                    .lock()
                    .map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_deleted += 1;
                ctx.log(&format!(
                    "import_item_skip path={} index={} reason=deleted",
                    path_display, index
                ));
                return Ok(());
            }
            let backup_storage_id =
                Uuid::parse_str(&item.storage_id).map_err(|_| "invalid storage id".to_string())?;
            let backup_vault_id =
                Uuid::parse_str(&item.vault_id).map_err(|_| "invalid vault id".to_string())?;
            if !storage_map_ref.contains_key(&backup_storage_id) {
                let mut guard = counters
                    .lock()
                    .map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_missing_storage += 1;
                ctx.log(&format!(
                    "import_item_skip path={} index={} reason=missing_storage",
                    path_display, index
                ));
                return Ok(());
            }
            let Some(&(target_storage_id, target_vault_id)) =
                vault_map_ref.get(&(backup_storage_id, backup_vault_id))
            else {
                let mut guard = counters
                    .lock()
                    .map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_missing_vault += 1;
                ctx.log(&format!(
                    "import_item_skip path={} index={} reason=missing_vault",
                    path_display, index
                ));
                return Ok(());
            };
            let existing = item_repo_ref
                .get_active_by_vault_path(target_storage_id, target_vault_id, &item.path)
                .await
                .map_err(|err| err.to_string())?;
            if existing.is_some() {
                let mut guard = counters
                    .lock()
                    .map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_existing += 1;
                ctx.log(&format!(
                    "import_item_skip path={} index={} reason=existing_path",
                    path_display, index
                ));
                return Ok(());
            }
            match services_ref
                .put_item(
                    target_storage_id,
                    target_vault_id,
                    item.path.clone(),
                    item.type_id.clone(),
                    item.payload.clone(),
                )
                .await
            {
                Ok(_) => {
                    let mut guard = counters
                        .lock()
                        .map_err(|_| "counter_lock_failed".to_string())?;
                    guard.imported_items += 1;
                    ctx.log(&format!(
                        "import_item_ok path={} index={}",
                        path_display, index
                    ));
                }
                Err(err) if err.kind == "item_exists" => {
                    let mut guard = counters
                        .lock()
                        .map_err(|_| "counter_lock_failed".to_string())?;
                    guard.skipped_existing += 1;
                    ctx.log(&format!(
                        "import_item_skip path={} index={} reason=item_exists",
                        path_display, index
                    ));
                }
                Err(err) => {
                    ctx.log(&format!(
                        "import_failed path={} error={}",
                        path_display, err.message
                    ));
                    if let Ok(mut guard) = api_error.lock() {
                        *guard = Some((err.kind, err.message));
                    }
                    return Err("import_failed".to_string());
                }
            }
            Ok(())
        }
    })
    .await;
    if let Ok(guard) = api_error.lock() {
        if let Some((kind, message)) = guard.as_ref() {
            return Err(BackupError::new(kind.clone(), message.clone()));
        }
    }
    if let Err(err) = stream_result {
        ctx.log(&format!(
            "import_failed path={} error={}",
            input_path.display(),
            err
        ));
        return Err(err.into());
    }

    let counters = counters
        .lock()
        .map_err(|_| "counter_lock_failed".to_string())?;
    let imported_items = counters.imported_items;
    let skipped_existing = counters.skipped_existing;
    let skipped_missing_storage = counters.skipped_missing_storage;
    let skipped_missing_vault = counters.skipped_missing_vault;
    let skipped_deleted = counters.skipped_deleted;

    ctx.log(&format!(
        "import_ok path={} imported={} skipped_existing={} skipped_missing_storage={} skipped_missing_vault={} skipped_deleted={}",
        input_path.display(),
        imported_items,
        skipped_existing,
        skipped_missing_storage,
        skipped_missing_vault,
        skipped_deleted
    ));
    Ok(ImportOutcome::Done(ImportReport {
        imported_items,
        skipped_existing,
        skipped_missing_storage,
        skipped_missing_vault,
        skipped_deleted,
    }))
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

fn default_backup_path(root: &Path) -> PathBuf {
    let filename = format!(
        "zann-plain-backup-{}.json",
        Utc::now().format("%Y%m%d-%H%M%S")
    );
    root.join("backups").join(filename)
}

struct ExportItemStreamer<'a> {
    services: LocalServices<'a>,
    item_repo: LocalItemRepo<'a>,
    vaults: VecDeque<(Uuid, Uuid)>,
    current_vault: Option<(Uuid, Uuid)>,
    cursor: Option<(chrono::DateTime<Utc>, Uuid)>,
    buffer: VecDeque<LocalItem>,
}

trait BackupItemSource: Send {
    fn next_item<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<PlainBackupItem>, anyhow::Error>> + Send + 'a>>;
}

impl<'a> BackupItemSource for ExportItemStreamer<'a> {
    fn next_item<'b>(
        &'b mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<PlainBackupItem>, anyhow::Error>> + Send + 'b>>
    {
        Box::pin(ExportItemStreamer::next_item(self))
    }
}

impl<'a> ExportItemStreamer<'a> {
    fn new(
        services: LocalServices<'a>,
        item_repo: LocalItemRepo<'a>,
        vaults: VecDeque<(Uuid, Uuid)>,
    ) -> Self {
        Self {
            services,
            item_repo,
            vaults,
            current_vault: None,
            cursor: None,
            buffer: VecDeque::new(),
        }
    }

    async fn next_item(&mut self) -> Result<Option<PlainBackupItem>, anyhow::Error> {
        loop {
            if let Some(item) = self.buffer.pop_front() {
                let payload = self
                    .services
                    .decrypt_payload_for_item(
                        item.storage_id,
                        item.vault_id,
                        item.id,
                        &item.payload_enc,
                    )
                    .await
                    .map_err(|err| anyhow::anyhow!(err.message))?;
                let backup_item = PlainBackupItem {
                    id: Some(item.id.to_string()),
                    storage_id: item.storage_id.to_string(),
                    vault_id: item.vault_id.to_string(),
                    path: item.path.clone(),
                    name: item.name.clone(),
                    type_id: item.type_id.clone(),
                    payload,
                    updated_at: item.updated_at.to_rfc3339(),
                    version: item.version,
                    deleted_at: item.deleted_at.map(|dt| dt.to_rfc3339()),
                };
                return Ok(Some(backup_item));
            }

            if self.current_vault.is_none() {
                self.current_vault = self.vaults.pop_front();
                self.cursor = None;
            }

            let Some((storage_id, vault_id)) = self.current_vault else {
                return Ok(None);
            };

            let items = self
                .item_repo
                .list_by_vault_paged(storage_id, vault_id, true, EXPORT_PAGE_LIMIT, self.cursor)
                .await?;
            if items.is_empty() {
                self.current_vault = None;
                self.cursor = None;
                continue;
            }
            if let Some(last) = items.last() {
                self.cursor = Some((last.updated_at, last.id));
            }
            self.buffer = VecDeque::from(items);
        }
    }
}

async fn write_backup_streaming<W>(
    writer: &mut W,
    version: u32,
    exported_at: &str,
    storages: &[PlainBackupStorage],
    vaults: &[PlainBackupVault],
    source: &mut dyn BackupItemSource,
) -> Result<usize, anyhow::Error>
where
    W: std::io::Write,
{
    write!(writer, "{{\"version\":")?;
    serde_json::to_writer(&mut *writer, &version)?;
    write!(writer, ",\"exported_at\":")?;
    serde_json::to_writer(&mut *writer, &exported_at)?;
    write!(writer, ",\"storages\":[")?;
    for (idx, storage) in storages.iter().enumerate() {
        if idx > 0 {
            write!(writer, ",")?;
        }
        serde_json::to_writer(&mut *writer, storage)?;
    }
    write!(writer, "],\"vaults\":[")?;
    for (idx, vault) in vaults.iter().enumerate() {
        if idx > 0 {
            write!(writer, ",")?;
        }
        serde_json::to_writer(&mut *writer, vault)?;
    }
    write!(writer, "],\"items\":[")?;
    let mut items_count = 0usize;
    let mut item_index = 0usize;
    loop {
        let item = source.next_item().await?;
        let Some(item) = item else {
            break;
        };
        if item_index > 0 {
            write!(writer, ",")?;
        }
        serde_json::to_writer(&mut *writer, &item)?;
        item_index += 1;
        items_count += 1;
    }
    write!(writer, "]}}")?;
    Ok(items_count)
}

pub struct PlainBackupMeta {
    pub version: u32,
    pub _exported_at: String,
    pub storages: Vec<PlainBackupStorage>,
    pub vaults: Vec<PlainBackupVault>,
}

impl<'de> Deserialize<'de> for PlainBackupMeta {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct MetaVisitor;

        impl<'de> Visitor<'de> for MetaVisitor {
            type Value = PlainBackupMeta;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("plain backup metadata")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut version: Option<u32> = None;
                let mut exported_at: Option<String> = None;
                let mut storages: Option<Vec<PlainBackupStorage>> = None;
                let mut vaults: Option<Vec<PlainBackupVault>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" => {
                            version = Some(map.next_value()?);
                        }
                        "exported_at" => {
                            exported_at = Some(map.next_value()?);
                        }
                        "storages" => {
                            storages = Some(map.next_value()?);
                        }
                        "vaults" => {
                            vaults = Some(map.next_value()?);
                        }
                        "items" => {
                            let _: IgnoredAny = map.next_value()?;
                        }
                        _ => {
                            let _: IgnoredAny = map.next_value()?;
                        }
                    }
                }

                Ok(PlainBackupMeta {
                    version: version.ok_or_else(|| de::Error::missing_field("version"))?,
                    _exported_at: exported_at
                        .ok_or_else(|| de::Error::missing_field("exported_at"))?,
                    storages: storages.ok_or_else(|| de::Error::missing_field("storages"))?,
                    vaults: vaults.ok_or_else(|| de::Error::missing_field("vaults"))?,
                })
            }
        }

        deserializer.deserialize_map(MetaVisitor)
    }
}

struct ItemsSeed<'a, F> {
    handler: &'a mut F,
    index: &'a mut usize,
}

impl<'de, 'a, F> DeserializeSeed<'de> for ItemsSeed<'a, F>
where
    F: FnMut(PlainBackupItem, usize) -> Result<(), String>,
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ItemsVisitor<'a, F> {
            handler: &'a mut F,
            index: &'a mut usize,
        }

        impl<'de, 'a, F> Visitor<'de> for ItemsVisitor<'a, F>
        where
            F: FnMut(PlainBackupItem, usize) -> Result<(), String>,
        {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("plain backup items list")
            }

            fn visit_seq<M>(self, mut seq: M) -> Result<Self::Value, M::Error>
            where
                M: SeqAccess<'de>,
            {
                while let Some(item) = seq.next_element::<PlainBackupItem>()? {
                    let index = *self.index;
                    *self.index += 1;
                    (self.handler)(item, index).map_err(de::Error::custom)?;
                }
                Ok(())
            }
        }

        deserializer.deserialize_seq(ItemsVisitor {
            handler: self.handler,
            index: self.index,
        })
    }
}

pub fn read_backup_metadata(path: &Path) -> Result<PlainBackupMeta, anyhow::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let meta = PlainBackupMeta::deserialize(&mut deserializer)?;
    Ok(meta)
}

fn stream_backup_items<F>(path: &Path, mut handler: F) -> Result<(), anyhow::Error>
where
    F: FnMut(PlainBackupItem, usize) -> Result<(), String>,
{
    struct StreamVisitor<'a, F> {
        handler: &'a mut F,
        index: usize,
    }

    impl<'de, 'a, F> Visitor<'de> for StreamVisitor<'a, F>
    where
        F: FnMut(PlainBackupItem, usize) -> Result<(), String>,
    {
        type Value = ();

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("plain backup stream")
        }

        fn visit_map<M>(mut self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            while let Some(key) = map.next_key::<String>()? {
                match key.as_str() {
                    "items" => {
                        let mut index = self.index;
                        map.next_value_seed(ItemsSeed {
                            handler: self.handler,
                            index: &mut index,
                        })?;
                        self.index = index;
                    }
                    _ => {
                        let _: IgnoredAny = map.next_value()?;
                    }
                }
            }
            Ok(())
        }
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    deserializer.deserialize_map(StreamVisitor {
        handler: &mut handler,
        index: 0,
    })?;
    Ok(())
}

pub async fn stream_backup_items_async<F, Fut>(path: &Path, mut handler: F) -> Result<(), String>
where
    F: FnMut(PlainBackupItem, usize) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let (tx, mut rx) = mpsc::channel(32);
    let path = path.to_path_buf();
    let handle = tokio::task::spawn_blocking(move || {
        let parse_result = stream_backup_items(&path, |item, index| {
            tx.blocking_send(Ok((item, index)))
                .map_err(|_| "channel_closed".to_string())
        });
        if let Err(err) = parse_result {
            let _ = tx.blocking_send(Err(err.to_string()));
        }
    });

    while let Some(message) = rx.recv().await {
        match message {
            Ok((item, index)) => {
                if let Err(err) = handler(item, index).await {
                    handle.abort();
                    return Err(err);
                }
            }
            Err(err) => return Err(err),
        }
    }

    handle.await.map_err(|err| err.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs::File;
    use std::io::BufWriter;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    #[derive(Serialize, Deserialize)]
    struct PlainBackup {
        version: u32,
        exported_at: String,
        storages: Vec<PlainBackupStorage>,
        vaults: Vec<PlainBackupVault>,
        items: Vec<PlainBackupItem>,
    }

    struct VecItemSource {
        items: VecDeque<PlainBackupItem>,
    }

    impl BackupItemSource for VecItemSource {
        fn next_item<'a>(
            &'a mut self,
        ) -> Pin<Box<dyn Future<Output = Result<Option<PlainBackupItem>, anyhow::Error>> + Send + 'a>>
        {
            Box::pin(async move { Ok(self.items.pop_front()) })
        }
    }

    fn sample_payload() -> EncryptedPayload {
        let mut payload = EncryptedPayload::new("login");
        payload.fields.insert(
            "username".to_string(),
            FieldValue {
                kind: FieldKind::Text,
                value: "user@example.com".to_string(),
                meta: None,
            },
        );
        payload
    }

    fn temp_path(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("zann-{label}-{}.json", Uuid::now_v7()));
        path
    }

    fn temp_csv_path(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("zann-{label}-{}.csv", Uuid::now_v7()));
        path
    }

    #[test]
    fn preflights_apple_passwords_without_counting_embedded_newlines_as_rows() {
        let path = temp_csv_path("apple-preflight");
        std::fs::write(
            &path,
            concat!(
                "Title,URL,Username,Password,Notes,OTPAuth\n",
                "Mail,https://example.com,first,pw,\"line one\nline two\",\n",
                "Mail,https://example.org,second,pw2,,\n",
                ",https://invalid.example,user,pw,,\n",
            ),
        )
        .expect("write CSV");

        let report = apple_passwords_preflight(&path).expect("preflight");
        assert_eq!(report.total_rows, 3);
        assert_eq!(report.importable_items, 2);
        assert_eq!(report.duplicate_rows, 1);
        assert_eq!(report.invalid_rows, 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn preflight_rejects_non_apple_csv_headers() {
        let path = temp_csv_path("apple-headers");
        std::fs::write(&path, "name,login,secret\nExample,user,pw\n").expect("write CSV");

        let err = apple_passwords_preflight(&path).expect_err("invalid headers");
        assert_eq!(err.kind, "apple_csv_headers_invalid");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn duplicate_suffix_keeps_the_item_name_within_the_path_limit() {
        let base = "x".repeat(MAX_ITEM_NAME_LEN);
        let candidate = suffixed_import_path(&base, 2);

        assert_eq!(candidate.len(), MAX_ITEM_NAME_LEN);
        assert!(candidate.ends_with(" (2)"));
    }

    #[test]
    fn reads_metadata_and_streams_items() {
        let path = temp_path("backup-meta");
        let backup = PlainBackup {
            version: BACKUP_VERSION,
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            storages: vec![PlainBackupStorage {
                id: Uuid::nil().to_string(),
                kind: StorageKind::LocalOnly.as_i32(),
                name: "Local".to_string(),
                server_url: None,
                server_name: None,
                server_fingerprint: None,
                account_subject: None,
                personal_vaults_enabled: false,
                auth_method: None,
            }],
            vaults: vec![PlainBackupVault {
                id: Uuid::now_v7().to_string(),
                storage_id: Uuid::nil().to_string(),
                name: "Default".to_string(),
                kind: VaultKind::Personal.as_i32(),
                is_default: true,
            }],
            items: vec![
                PlainBackupItem {
                    id: Some(Uuid::now_v7().to_string()),
                    storage_id: Uuid::nil().to_string(),
                    vault_id: Uuid::now_v7().to_string(),
                    path: "example".to_string(),
                    name: "Example".to_string(),
                    type_id: "login".to_string(),
                    payload: sample_payload(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                    version: 1,
                    deleted_at: None,
                },
                PlainBackupItem {
                    id: Some(Uuid::now_v7().to_string()),
                    storage_id: Uuid::nil().to_string(),
                    vault_id: Uuid::now_v7().to_string(),
                    path: "example2".to_string(),
                    name: "Example 2".to_string(),
                    type_id: "login".to_string(),
                    payload: sample_payload(),
                    updated_at: "2024-01-02T00:00:00Z".to_string(),
                    version: 1,
                    deleted_at: None,
                },
            ],
        };

        let file = File::create(&path).expect("create temp backup");
        serde_json::to_writer(file, &backup).expect("write backup");

        let meta = read_backup_metadata(&path).expect("read metadata");
        assert_eq!(meta.version, BACKUP_VERSION);
        assert_eq!(meta.storages.len(), 1);
        assert_eq!(meta.vaults.len(), 1);

        let mut streamed = Vec::new();
        stream_backup_items(&path, |item, _index| {
            streamed.push(item);
            Ok(())
        })
        .expect("stream items");
        assert_eq!(streamed.len(), 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn streams_items_async() {
        let path = temp_path("backup-stream-async");
        let backup = PlainBackup {
            version: BACKUP_VERSION,
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            storages: vec![],
            vaults: vec![],
            items: vec![
                PlainBackupItem {
                    id: Some(Uuid::now_v7().to_string()),
                    storage_id: Uuid::nil().to_string(),
                    vault_id: Uuid::now_v7().to_string(),
                    path: "one".to_string(),
                    name: "One".to_string(),
                    type_id: "login".to_string(),
                    payload: sample_payload(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                    version: 1,
                    deleted_at: None,
                },
                PlainBackupItem {
                    id: Some(Uuid::now_v7().to_string()),
                    storage_id: Uuid::nil().to_string(),
                    vault_id: Uuid::now_v7().to_string(),
                    path: "two".to_string(),
                    name: "Two".to_string(),
                    type_id: "login".to_string(),
                    payload: sample_payload(),
                    updated_at: "2024-01-02T00:00:00Z".to_string(),
                    version: 1,
                    deleted_at: None,
                },
            ],
        };

        let file = File::create(&path).expect("create temp backup");
        serde_json::to_writer(file, &backup).expect("write backup");

        let items = Arc::new(Mutex::new(Vec::new()));
        let items_clone = Arc::clone(&items);
        tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(async {
                stream_backup_items_async(&path, |item, _index| {
                    let items_clone = Arc::clone(&items_clone);
                    async move {
                        let mut guard = items_clone.lock().expect("lock items");
                        guard.push(item);
                        Ok(())
                    }
                })
                .await
                .expect("stream async");
            });

        let guard = items.lock().expect("lock items");
        assert_eq!(guard.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn writes_backup_streaming() {
        let path = temp_path("backup-write");
        let storages = vec![PlainBackupStorage {
            id: Uuid::nil().to_string(),
            kind: StorageKind::LocalOnly.as_i32(),
            name: "Local".to_string(),
            server_url: None,
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: false,
            auth_method: None,
        }];
        let vaults = vec![PlainBackupVault {
            id: Uuid::now_v7().to_string(),
            storage_id: Uuid::nil().to_string(),
            name: "Default".to_string(),
            kind: VaultKind::Personal.as_i32(),
            is_default: true,
        }];
        let items = VecDeque::from(vec![
            PlainBackupItem {
                id: Some(Uuid::now_v7().to_string()),
                storage_id: Uuid::nil().to_string(),
                vault_id: Uuid::now_v7().to_string(),
                path: "alpha".to_string(),
                name: "Alpha".to_string(),
                type_id: "login".to_string(),
                payload: sample_payload(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
                version: 1,
                deleted_at: None,
            },
            PlainBackupItem {
                id: Some(Uuid::now_v7().to_string()),
                storage_id: Uuid::nil().to_string(),
                vault_id: Uuid::now_v7().to_string(),
                path: "beta".to_string(),
                name: "Beta".to_string(),
                type_id: "login".to_string(),
                payload: sample_payload(),
                updated_at: "2024-01-02T00:00:00Z".to_string(),
                version: 1,
                deleted_at: None,
            },
        ]);
        let mut source = VecItemSource { items };

        let file = File::create(&path).expect("create temp backup");
        let mut writer = BufWriter::new(file);
        let items_count = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(async {
                write_backup_streaming(
                    &mut writer,
                    BACKUP_VERSION,
                    "2024-01-01T00:00:00Z",
                    &storages,
                    &vaults,
                    &mut source,
                )
                .await
                .expect("write backup")
            });
        writer.flush().expect("flush");
        assert_eq!(items_count, 2);

        let meta = read_backup_metadata(&path).expect("read metadata");
        assert_eq!(meta.version, BACKUP_VERSION);
        assert_eq!(meta.storages.len(), 1);
        assert_eq!(meta.vaults.len(), 1);

        let mut streamed = Vec::new();
        stream_backup_items(&path, |item, _index| {
            streamed.push(item);
            Ok(())
        })
        .expect("stream items");
        assert_eq!(streamed.len(), 2);
        let _ = std::fs::remove_file(&path);
    }
}
