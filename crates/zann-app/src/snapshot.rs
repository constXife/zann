//! Point-in-time copies of the vault database.
//!
//! A snapshot is **not** an export. The export in [`crate::backup`] writes
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

use sqlx_core::executor::Executor;
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
    found.sort_by(|a, b| b.0.cmp(&a.0));
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
/// `VACUUM INTO` refuses to write over an existing file, so a second snapshot
/// inside the same second fails rather than clobbering the first. That is the
/// safe direction, and the caller can simply try again.
pub async fn create(
    pool: &SqlitePool,
    root: &Path,
    policy: &RetentionPolicy,
) -> Result<Snapshot, SnapshotError> {
    let dir = snapshots_dir(root);
    std::fs::create_dir_all(&dir)
        .map_err(|err| SnapshotError::new("snapshot_dir_failed", err.to_string()))?;

    let created = chrono::Utc::now();
    let path = dir.join(format!("{PREFIX}{}{SUFFIX}", created.format(STAMP)));
    if path.exists() {
        return Err(SnapshotError::new(
            "snapshot_exists",
            format!("a snapshot already exists at {}", path.display()),
        ));
    }

    // Save the salt first: a database copy without it cannot be opened, so
    // failing here has to stop the snapshot rather than produce a useless one.
    let identity_path = save_identity(root, &dir, &created.format(STAMP).to_string())?;

    // `VACUUM INTO` takes an expression, so the destination binds as a normal
    // parameter — no quoting of a user-supplied path into SQL.
    let mut conn = pool
        .acquire()
        .await
        .map_err(|err| SnapshotError::new("snapshot_failed", err.to_string()))?;
    conn.execute(sqlx_core::query::query("VACUUM INTO ?").bind(path.to_string_lossy().to_string()))
        .await
        .map_err(|err| SnapshotError::new("snapshot_failed", err.to_string()))?;
    drop(conn);

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
/// Restoring is deliberately not done here. The database is open, and swapping
/// the file under a live pool is how a working vault becomes a corrupt one; the
/// safe procedure is to close every client first and copy the file back. Giving
/// clients the destination lets them show the two paths and say so.
pub fn restore_target(root: &Path) -> PathBuf {
    root.join("local.sqlite")
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn temp_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!("zann-snapshot-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("create temp root");
        root
    }

    async fn seeded_pool(root: &Path) -> SqlitePool {
        let url = format!("sqlite://{}", root.join("local.sqlite").display());
        let pool = zann_db::connect_sqlite_with_max(&url, 2)
            .await
            .expect("connect");
        zann_db::migrate_local(&pool).await.expect("migrate");
        pool
    }

    fn touch(root: &Path, name: &str) {
        let dir = snapshots_dir(root);
        std::fs::create_dir_all(&dir).expect("create dir");
        std::fs::write(dir.join(name), b"x").expect("write");
    }

    #[tokio::test]
    async fn creates_a_readable_copy_of_the_database() {
        let root = temp_root();
        let pool = seeded_pool(&root).await;

        let snapshot = create(&pool, &root, &RetentionPolicy::default())
            .await
            .expect("snapshot");

        assert!(snapshot.path.exists(), "no file at the reported path");
        assert!(snapshot.size_bytes > 0, "snapshot is empty");

        // The copy has to be a working database, not just bytes on disk.
        let url = format!("sqlite://{}", snapshot.path.display());
        let copy = zann_db::connect_sqlite_with_max(&url, 1)
            .await
            .expect("open the snapshot");
        copy.close().await;

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn listing_a_vault_with_no_snapshots_is_empty_not_an_error() {
        let root = temp_root();
        assert!(list(&root).expect("list").is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lists_newest_first_and_ignores_foreign_files() {
        let root = temp_root();
        touch(&root, "local-20260101-000000.sqlite");
        touch(&root, "local-20260601-120000.sqlite");
        touch(&root, "notes.txt");
        touch(&root, "local-nonsense.sqlite");

        let found = list(&root).expect("list");
        assert_eq!(found.len(), 2, "foreign files must not be listed");
        assert!(found[0].created_at.starts_with("2026-06-01"));
        assert!(found[1].created_at.starts_with("2026-01-01"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn retention_keeps_the_newest_and_drops_the_rest() {
        let root = temp_root();
        for day in 1..=5 {
            touch(&root, &format!("local-202606{day:02}-120000.sqlite"));
        }

        let removed = prune(
            &root,
            &RetentionPolicy {
                max_count: Some(2),
                max_age_days: None,
            },
        )
        .expect("prune");

        assert_eq!(removed.len(), 3);
        let left = list(&root).expect("list");
        assert_eq!(left.len(), 2);
        assert!(left[0].created_at.starts_with("2026-06-05"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn retention_drops_whatever_has_aged_out() {
        let root = temp_root();
        let old = chrono::Utc::now() - chrono::Duration::days(90);
        touch(&root, &format!("local-{}.sqlite", old.format(STAMP)));
        let fresh = chrono::Utc::now();
        touch(&root, &format!("local-{}.sqlite", fresh.format(STAMP)));

        let removed = prune(
            &root,
            &RetentionPolicy {
                max_count: None,
                max_age_days: Some(30),
            },
        )
        .expect("prune");

        assert_eq!(removed.len(), 1, "only the aged-out snapshot goes");
        assert_eq!(list(&root).expect("list").len(), 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_vault_with_no_snapshots_is_always_due() {
        let root = temp_root();
        assert!(is_due(&root, Duration::from_secs(3600)));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_recent_snapshot_means_nothing_is_due() {
        let root = temp_root();
        let pool = seeded_pool(&root).await;
        create(&pool, &root, &RetentionPolicy::default())
            .await
            .expect("snapshot");

        assert!(!is_due(&root, Duration::from_secs(3600)));
        assert!(
            create_if_due(
                &pool,
                &root,
                Duration::from_secs(3600),
                &RetentionPolicy::default()
            )
            .await
            .expect("create_if_due")
            .is_none(),
            "a second snapshot was taken while one was still fresh"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_stale_snapshot_makes_one_due_again() {
        let root = temp_root();
        let pool = seeded_pool(&root).await;
        let old = chrono::Utc::now() - chrono::Duration::days(2);
        touch(&root, &format!("local-{}.sqlite", old.format(STAMP)));

        let taken = create_if_due(
            &pool,
            &root,
            Duration::from_secs(24 * 3600),
            &RetentionPolicy::default(),
        )
        .await
        .expect("create_if_due");

        assert!(taken.is_some(), "a day-old snapshot should be due");
        let _ = std::fs::remove_dir_all(&root);
    }
}
