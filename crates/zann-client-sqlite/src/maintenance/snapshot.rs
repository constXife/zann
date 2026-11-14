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
//! The encrypted device keyring lives in the same SQLite database as the cache.
//! VACUUM INTO captures keys and ciphertext in one consistent read transaction.
//! Restoring the file restores its unlock password and account keys together.

use std::path::{Path, PathBuf};
use std::time::Duration;

use zann_client::app::unlock::DeviceUnlock;
use zann_db::SqlitePool;

/// Snapshot filenames are `local-YYYYMMDD-HHMMSS.sqlite`. The timestamp is part
/// of the name rather than read from the filesystem, so a copied or restored
/// directory still sorts correctly.
const PREFIX: &str = "local-";
const SUFFIX: &str = ".sqlite";
const STAMP: &str = "%Y%m%d-%H%M%S";

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SnapshotError {
    pub kind: String,
    pub message: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl SnapshotError {
    fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.into(),
            source: None,
        }
    }
    fn source(kind: &str, error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            kind: kind.into(),
            message: kind.into(),
            source: Some(Box::new(error)),
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
        Err(err) => return Err(SnapshotError::source("snapshot_list_failed", err)),
    };

    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| SnapshotError::source("snapshot_list_failed", err))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(created) = parse_stamp(name) else {
            continue;
        };
        let metadata = entry
            .metadata()
            .map_err(|err| SnapshotError::source("snapshot_list_failed", err))?;
        let size_bytes = metadata.len();
        if !metadata.is_file() || size_bytes == 0 {
            continue;
        }
        found.push((
            created,
            Snapshot {
                path: entry.path(),
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
            removed.push(snapshot.path.clone());
        }
    }
    Ok(removed)
}

struct SnapshotCandidate {
    path: PathBuf,
    complete: bool,
}
impl Drop for SnapshotCandidate {
    fn drop(&mut self) {
        if !self.complete {
            let _ = std::fs::remove_file(&self.path);
        }
    }
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
    crate::maintenance::secure_file::ensure_private_dir(&dir)
        .map_err(|err| SnapshotError::source("snapshot_dir_failed", err))?;

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

    let output = crate::maintenance::secure_file::create_new_private_file(&path)
        .map_err(|err| SnapshotError::source("snapshot_failed", err))?;
    drop(output);
    let mut candidate = SnapshotCandidate {
        path: path.clone(),
        complete: false,
    };
    // `VACUUM INTO` takes an expression, so the destination binds as a normal
    // parameter — no quoting of a user-supplied path into SQL.
    zann_db::local::maintenance::snapshot_into(pool, &path)
        .await
        .map_err(|err| SnapshotError::source("snapshot_failed", err))?;

    std::fs::File::open(&path)
        .and_then(|file| file.sync_all())
        .map_err(|err| SnapshotError::source("snapshot_failed", err))?;
    std::fs::File::open(&dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| SnapshotError::source("snapshot_failed", err))?;

    let size_bytes = std::fs::metadata(&path)
        .map_err(|err| SnapshotError::source("snapshot_failed", err))?
        .len();

    let _ = prune(root, policy);

    candidate.complete = true;
    Ok(Snapshot {
        path,
        created_at: created.to_rfc3339(),
        size_bytes,
    })
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
        .map_err(|err| SnapshotError::source("snapshot_restore_failed", err))?;
    std::fs::rename(&staged, &target).map_err(|err| {
        let _ = std::fs::remove_file(&staged);
        SnapshotError::source("snapshot_restore_failed", err)
    })?;

    // A write-ahead log left from the database that was just replaced would be
    // replayed into the restored one on the next open, undoing the restore.
    for sidecar in ["sqlite-wal", "sqlite-shm"] {
        let _ = std::fs::remove_file(target.with_extension(sidecar));
    }

    Ok(RestoreOutcome {
        restored_from: snapshot_path.to_path_buf(),
        replaced_saved_to: replaced.path,
    })
}

/// Refuse a file that is not an intact vault database, before anything is
/// replaced. `integrity_check` alone would accept any healthy SQLite file, so
/// the schema is checked too — restoring some other application's database over
/// the vault would be a spectacular way to lose everything.
async fn check_readable(path: &Path) -> Result<(), SnapshotError> {
    let location = zann_db::SqliteFileLocation::from_path(path)
        .map_err(|err| SnapshotError::source("snapshot_unreadable", err))?;
    let pool = zann_db::connect_sqlite_file_with_max(&location, 1)
        .await
        .map_err(|err| SnapshotError::source("snapshot_unreadable", err))?;

    let result = async {
        let (verdict, tables) = zann_db::local::maintenance::inspect_snapshot(&pool)
            .await
            .map_err(|err| SnapshotError::source("snapshot_unreadable", err))?;
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
        let raw = zann_db::local::MetadataRepo::new(&pool)
            .get_value_bounded("device_keyring", 1024 * 1024)
            .await
            .map_err(|err| SnapshotError::source("snapshot_keyring_failed", err))?;
        let keyring = raw
            .as_deref()
            .map(DeviceUnlock::decode)
            .transpose()
            .map_err(|err| SnapshotError::source("snapshot_keyring_failed", err))?;
        let storages = zann_db::local::LocalStorageRepo::new(&pool)
            .list()
            .await
            .map_err(|err| SnapshotError::source("snapshot_keyring_failed", err))?;
        for storage in storages {
            let vaults = zann_db::local::LocalVaultRepo::new(&pool)
                .list_by_storage(storage.id)
                .await
                .map_err(|err| SnapshotError::source("snapshot_keyring_failed", err))?;
            if !vaults.is_empty()
                && !keyring
                    .as_ref()
                    .is_some_and(|bag| bag.accounts.contains_key(&storage.id.to_string()))
            {
                return Err(SnapshotError::new(
                    "snapshot_keyring_missing",
                    "the snapshot has encrypted data without its account keyring",
                ));
            }
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

#[cfg(test)]
#[path = "../../tests/maintenance/snapshot.rs"]
mod tests;
