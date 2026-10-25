//! Point-in-time copies of the vault database.
//!
//! A snapshot is **not** an export. The export in [`crate::maintenance::backup`] writes
//! plaintext JSON so the data can leave Zann; a snapshot is a byte-for-byte
//! copy of the encrypted database, so it is only useful for going back to a
//! moment before something went wrong. That difference matters for where the
//! files may safely be left lying around, and the two must never be confused
//! in the UI.
//!
//! Consistency comes from SQLite's `VACUUM INTO`, which reads inside a
//! transaction and writes a defragmented copy. It is safe against a live,
//! WAL-mode database, which is why nothing here stops the world first.
//!
//! ## The database alone is not enough
//!
//! The master key is derived from the password and the KDF salt, and that salt
//! lives in `config.json`, not in the database. A copy of `local.sqlite` whose
//! salt has been lost cannot be opened by any password. So each snapshot is
//! paired with an `.identity.json` holding just the `identity` block of
//! `config.json`.
//!
//! Only that block: `config.json` also carries refresh tokens in the clear, and
//! duplicating those into a directory of long-lived copies would trade one
//! recovery problem for a worse disclosure one. The salt is not a secret — it
//! is useless without the password — while the tokens are, and they can always
//! be obtained again by logging in.
//!
//! See docs/adr/0002-client-strategy.md on why being able to recover ranks
//! above features.

use std::path::{Path, PathBuf};
use std::time::Duration;

use zann_db::SqlitePool;

/// Snapshot filenames are `local-YYYYMMDD-HHMMSS.sqlite`. The timestamp is part
/// of the name rather than read from the filesystem, so a copied or restored
/// directory still sorts correctly.
const PREFIX: &str = "local-";
const SUFFIX: &str = ".sqlite";
const IDENTITY_SUFFIX: &str = ".identity.json";
const STAMP: &str = "%Y%m%d-%H%M%S";

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct SnapshotError {
    pub kind: String,
    pub message: String,
}

impl SnapshotError {
    fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.into(),
        }
    }
}

/// How many snapshots to keep. Both limits apply: a snapshot has to survive
/// each one to be kept.
///
/// The defaults mirror the `backup_retention_days` / `backup_max_count` fields
/// that have sat unread in the desktop config since before this module existed.
#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicy {
    pub max_count: Option<usize>,
    pub max_age_days: Option<i64>,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_count: Some(10),
            max_age_days: Some(30),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub path: PathBuf,
    /// The KDF salt this copy needs to be opened. `None` only when the vault
    /// had no `identity` in its config yet, which means it has never been
    /// unlocked and there is nothing to recover.
    pub identity_path: Option<PathBuf>,
    /// From the filename, as RFC 3339.
    pub created_at: String,
    pub size_bytes: u64,
}

/// Where snapshots live, next to the database they came from.
pub fn snapshots_dir(root: &Path) -> PathBuf {
    root.join("snapshots")
}

fn parse_stamp(name: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let stem = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
    let naive = chrono::NaiveDateTime::parse_from_str(stem, STAMP).ok()?;
    Some(naive.and_utc())
}

/// Newest first.
pub fn list(root: &Path) -> Result<Vec<Snapshot>, SnapshotError> {
    let dir = snapshots_dir(root);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        // Nothing taken yet is not a failure.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(SnapshotError::new("snapshot_list_failed", err.to_string())),
    };

    let mut found = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(created) = parse_stamp(name) else {
            continue;
        };
        let size_bytes = entry.metadata().map(|meta| meta.len()).unwrap_or(0);
        let identity_path = dir.join(format!(
            "{PREFIX}{}{IDENTITY_SUFFIX}",
            created.format(STAMP)
        ));
        found.push((
            created,
            Snapshot {
                path: entry.path(),
                identity_path: identity_path.exists().then_some(identity_path),
                created_at: created.to_rfc3339(),
                size_bytes,
            },
        ));
    }
    found.sort_by_key(|(created, _)| std::cmp::Reverse(*created));
    Ok(found.into_iter().map(|(_, snapshot)| snapshot).collect())
}

/// Drop whatever the policy no longer covers. Returns what was removed.
///
/// Removal failures are not fatal: a snapshot that could not be deleted is a
/// tidiness problem, and reporting it as an error would make the caller think
/// the snapshot it just took had failed.
pub fn prune(root: &Path, policy: &RetentionPolicy) -> Result<Vec<PathBuf>, SnapshotError> {
    let snapshots = list(root)?;
    let cutoff = policy
        .max_age_days
        .map(|days| chrono::Utc::now() - chrono::Duration::days(days));

    let mut removed = Vec::new();
    for (index, snapshot) in snapshots.iter().enumerate() {
        let too_many = policy.max_count.is_some_and(|max| index >= max);
        let too_old = cutoff.is_some_and(|cutoff| {
            chrono::DateTime::parse_from_rfc3339(&snapshot.created_at)
                .map(|created| created.with_timezone(&chrono::Utc) < cutoff)
                .unwrap_or(false)
        });
        if (too_many || too_old) && std::fs::remove_file(&snapshot.path).is_ok() {
            if let Some(identity) = snapshot.identity_path.as_ref() {
                let _ = std::fs::remove_file(identity);
            }
            removed.push(snapshot.path.clone());
        }
    }
    Ok(removed)
}

/// Take a snapshot, then apply the retention policy.
///
/// The filename has a second's resolution, and `VACUUM INTO` refuses to write
/// over an existing file, so two snapshots inside the same second would collide.
/// Rather than fail — which [`restore`] would hit every time it saved the
/// database it was about to replace — the stamp moves forward to the first free
/// slot. No existing snapshot is ever overwritten.
pub async fn create(
    pool: &SqlitePool,
    root: &Path,
    policy: &RetentionPolicy,
) -> Result<Snapshot, SnapshotError> {
    let dir = snapshots_dir(root);
    std::fs::create_dir_all(&dir)
        .map_err(|err| SnapshotError::new("snapshot_dir_failed", err.to_string()))?;

    let mut created = chrono::Utc::now();
    let mut path = dir.join(format!("{PREFIX}{}{SUFFIX}", created.format(STAMP)));
    // Bounded: a directory this contested is a bug somewhere else, and looping
    // forever would be a worse way to find out.
    for _ in 0..60 {
        if !path.exists() {
            break;
        }
        created += chrono::Duration::seconds(1);
        path = dir.join(format!("{PREFIX}{}{SUFFIX}", created.format(STAMP)));
    }
    if path.exists() {
        return Err(SnapshotError::new(
            "snapshot_exists",
            format!("no free snapshot name near {}", path.display()),
        ));
    }

    // Save the salt first: a database copy without it cannot be opened, so
    // failing here has to stop the snapshot rather than produce a useless one.
    let identity_path = save_identity(root, &dir, &created.format(STAMP).to_string())?;

    // `VACUUM INTO` takes an expression, so the destination binds as a normal
    // parameter — no quoting of a user-supplied path into SQL.
    zann_db::local::maintenance::snapshot_into(pool, &path)
        .await
        .map_err(|err| SnapshotError::new("snapshot_failed", err.to_string()))?;

    let size_bytes = std::fs::metadata(&path)
        .map_err(|err| SnapshotError::new("snapshot_failed", err.to_string()))?
        .len();

    let _ = prune(root, policy);

    Ok(Snapshot {
        path,
        identity_path,
        created_at: created.to_rfc3339(),
        size_bytes,
    })
}

/// Copy the `identity` block of `config.json` next to a snapshot.
///
/// Deliberately not the whole file — see the module docs on why the tokens in
/// it must not be duplicated.
fn save_identity(root: &Path, dir: &Path, stamp: &str) -> Result<Option<PathBuf>, SnapshotError> {
    let config_path = root.join("config.json");
    let contents = match std::fs::read_to_string(&config_path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(SnapshotError::new(
                "snapshot_identity_failed",
                err.to_string(),
            ));
        }
    };
    let config: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|err| SnapshotError::new("snapshot_identity_failed", err.to_string()))?;
    let Some(identity) = config.get("identity").filter(|value| !value.is_null()) else {
        return Ok(None);
    };

    let path = dir.join(format!("{PREFIX}{stamp}{IDENTITY_SUFFIX}"));
    let body = serde_json::to_string_pretty(identity)
        .map_err(|err| SnapshotError::new("snapshot_identity_failed", err.to_string()))?;
    std::fs::write(&path, body)
        .map_err(|err| SnapshotError::new("snapshot_identity_failed", err.to_string()))?;
    Ok(Some(path))
}

/// Whether the newest snapshot is older than `max_age`, i.e. whether one is due.
/// A vault with no snapshots at all is always due.
pub fn is_due(root: &Path, max_age: Duration) -> bool {
    let Ok(snapshots) = list(root) else {
        return false;
    };
    let Some(newest) = snapshots.first() else {
        return true;
    };
    let Ok(created) = chrono::DateTime::parse_from_rfc3339(&newest.created_at) else {
        return true;
    };
    let age = chrono::Utc::now().signed_duration_since(created.with_timezone(&chrono::Utc));
    age.to_std().map(|age| age >= max_age).unwrap_or(false)
}

/// Take a snapshot only if the newest one has aged out. Returns `None` when one
/// was taken recently enough.
///
/// This is deliberately a separate call rather than something `unlock` does on
/// its own: hiding disk work inside unlock would make an unrelated operation
/// occasionally slow, and there would be no way for a client to opt out.
pub async fn create_if_due(
    pool: &SqlitePool,
    root: &Path,
    max_age: Duration,
    policy: &RetentionPolicy,
) -> Result<Option<Snapshot>, SnapshotError> {
    if !is_due(root, max_age) {
        return Ok(None);
    }
    create(pool, root, policy).await.map(Some)
}

/// Where a snapshot has to be copied to put it back.
///
/// Still public for clients that only want to show the destination — restoring
/// by hand with everything closed remains a valid procedure, and the one to
/// fall back on if [`restore`] cannot run.
pub fn restore_target(root: &Path) -> PathBuf {
    root.join("local.sqlite")
}

/// What a restore did, so a client can report it and the user can undo it.
#[derive(Debug, Clone)]
pub struct RestoreOutcome {
    pub restored_from: PathBuf,
    /// The database that was in place beforehand, kept as a snapshot of its
    /// own. A restore is reversible by restoring this.
    pub replaced_saved_to: PathBuf,
    /// Whether the KDF salt came back with the snapshot. When it did, the
    /// password that opens the restored database is the one that was in use
    /// when the snapshot was taken, and anything derived from the old salt —
    /// a remembered unlock, above all — is now wrong.
    pub identity_replaced: bool,
}

/// Put a snapshot back in place of the live database.
///
/// **The caller must not use `pool` afterwards.** This closes it, because the
/// one thing that reliably turns a working vault into a corrupt one is swapping
/// the file under an open connection. A client calls this, then reconnects.
///
/// The order is chosen so that no step can lose data on its own:
///
/// 1. the snapshot is opened and checked before anything is touched, so a
///    damaged file is refused rather than half-installed;
/// 2. the current database is snapshotted first — with retention disabled,
///    because pruning could otherwise delete the very file being restored —
///    so the state being replaced survives;
/// 3. the pool is closed, and only then does the file move, through a temporary
///    in the same directory and a rename, so an interrupted copy cannot leave a
///    truncated database at the live path.
pub async fn restore(
    pool: SqlitePool,
    root: &Path,
    snapshot_path: &Path,
) -> Result<RestoreOutcome, SnapshotError> {
    if !snapshot_path.is_file() {
        return Err(SnapshotError::new(
            "snapshot_not_found",
            format!("no snapshot at {}", snapshot_path.display()),
        ));
    }
    let target = restore_target(root);
    if snapshot_path == target {
        return Err(SnapshotError::new(
            "snapshot_is_live_database",
            "that path is the live database, not a snapshot",
        ));
    }
    check_readable(snapshot_path).await?;
    // Read and parse the salt now, while a failure still costs nothing. Only
    // the write of it happens after the database has moved.
    let identity = read_identity(snapshot_path)?;

    // Keep what is about to be replaced. Retention is off for this one: the
    // pruning that follows a normal snapshot could delete the file we are in
    // the middle of restoring from.
    let replaced = create(
        &pool,
        root,
        &RetentionPolicy {
            max_count: None,
            max_age_days: None,
        },
    )
    .await?;

    pool.close().await;

    let staged = target.with_extension("sqlite.restoring");
    let _ = std::fs::remove_file(&staged);
    std::fs::copy(snapshot_path, &staged)
        .map_err(|err| SnapshotError::new("snapshot_restore_failed", err.to_string()))?;
    std::fs::rename(&staged, &target).map_err(|err| {
        let _ = std::fs::remove_file(&staged);
        SnapshotError::new("snapshot_restore_failed", err.to_string())
    })?;

    // A write-ahead log left from the database that was just replaced would be
    // replayed into the restored one on the next open, undoing the restore.
    for sidecar in ["sqlite-wal", "sqlite-shm"] {
        let _ = std::fs::remove_file(target.with_extension(sidecar));
    }

    let identity_replaced = match identity {
        Some(identity) => write_identity(root, identity)?,
        None => false,
    };

    Ok(RestoreOutcome {
        restored_from: snapshot_path.to_path_buf(),
        replaced_saved_to: replaced.path,
        identity_replaced,
    })
}

/// Refuse a file that is not an intact vault database, before anything is
/// replaced. `integrity_check` alone would accept any healthy SQLite file, so
/// the schema is checked too — restoring some other application's database over
/// the vault would be a spectacular way to lose everything.
async fn check_readable(path: &Path) -> Result<(), SnapshotError> {
    let url = format!("sqlite://{}", path.display());
    let pool = zann_db::connect_sqlite_with_max(&url, 1)
        .await
        .map_err(|err| SnapshotError::new("snapshot_unreadable", err.to_string()))?;

    let result = async {
        let (verdict, tables) = zann_db::local::maintenance::inspect_snapshot(&pool)
            .await
            .map_err(|err| SnapshotError::new("snapshot_unreadable", err.to_string()))?;
        if verdict != "ok" {
            return Err(SnapshotError::new(
                "snapshot_corrupt",
                format!("the snapshot failed its integrity check: {verdict}"),
            ));
        }
        if tables < 3 {
            return Err(SnapshotError::new(
                "snapshot_not_a_vault",
                "that database is not a Zann vault",
            ));
        }
        Ok(())
    }
    .await;

    pool.close().await;
    // Opening in WAL mode leaves sidecars beside the snapshot; they describe a
    // read that is now over, and leaving them would make the directory listing
    // confusing.
    for sidecar in ["sqlite-wal", "sqlite-shm"] {
        let _ = std::fs::remove_file(path.with_extension(sidecar));
    }
    result
}

/// The `identity` block saved beside a snapshot, if there is one.
///
/// A snapshot with no identity beside it is not an error: the salt in place may
/// well be the one it was taken under, and refusing the restore would help
/// nobody. A file that is there but unreadable *is* an error, and this runs
/// before anything has been replaced so it can still be reported as one.
fn read_identity(snapshot_path: &Path) -> Result<Option<serde_json::Value>, SnapshotError> {
    let identity_path = snapshot_path.with_extension("identity.json");
    let Ok(contents) = std::fs::read_to_string(&identity_path) else {
        return Ok(None);
    };
    serde_json::from_str(&contents)
        .map(Some)
        .map_err(|err| SnapshotError::new("snapshot_identity_failed", err.to_string()))
}

/// Put the snapshot's `identity` block into `config.json`, leaving the rest of
/// the file — the tokens above all — alone. Returns whether anything changed.
fn write_identity(root: &Path, identity: serde_json::Value) -> Result<bool, SnapshotError> {
    let config_path = root.join("config.json");
    let mut config = match std::fs::read_to_string(&config_path) {
        Ok(contents) => serde_json::from_str::<serde_json::Value>(&contents)
            .map_err(|err| SnapshotError::new("snapshot_identity_failed", err.to_string()))?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            serde_json::Value::Object(serde_json::Map::new())
        }
        Err(err) => {
            return Err(SnapshotError::new(
                "snapshot_identity_failed",
                err.to_string(),
            ))
        }
    };
    if config.get("identity") == Some(&identity) {
        return Ok(false);
    }
    match config.as_object_mut() {
        Some(map) => {
            map.insert("identity".to_string(), identity);
        }
        None => config = serde_json::json!({ "identity": identity }),
    }
    let body = serde_json::to_string_pretty(&config)
        .map_err(|err| SnapshotError::new("snapshot_identity_failed", err.to_string()))?;
    crate::maintenance::secure_file::write_private(&config_path, body.as_bytes())
        .map_err(|err| SnapshotError::new("snapshot_identity_failed", err.to_string()))?;
    Ok(true)
}

#[cfg(test)]
#[path = "../../tests/maintenance/snapshot.rs"]
mod tests;
