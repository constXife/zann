#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_raw_string_hashes)]
#![allow(clippy::uninlined_format_args)]

extern crate sqlx_core as sqlx;

#[cfg(feature = "sqlite")]
use same_file::Handle as FileIdentity;
use sqlx_core::pool::{Pool, PoolOptions};
#[cfg(feature = "sqlite")]
use sqlx_core::row::Row;
#[cfg(feature = "postgres")]
use sqlx_postgres::{PgConnectOptions, Postgres};
#[cfg(feature = "sqlite")]
use sqlx_sqlite::{Sqlite, SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
#[cfg(feature = "sqlite")]
use std::fs;
#[cfg(feature = "sqlite")]
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
#[cfg(feature = "sqlite")]
use std::time::Duration;

#[cfg(feature = "sqlite")]
pub mod local;
#[cfg(feature = "postgres")]
pub mod repo;
#[cfg(feature = "sqlite")]
pub mod services;

#[cfg(feature = "sqlite")]
pub type SqlitePool = Pool<Sqlite>;
#[cfg(feature = "postgres")]
pub type PgPool = Pool<Postgres>;

/// A durable SQLite file resolved to one stable absolute filesystem path.
///
/// The resolved path owns both database connection options and the adjacent
/// client-state root. This prevents composition roots from parsing a URI one
/// way for SQLite and another way for `config.json` or keystore state.
#[cfg(feature = "sqlite")]
#[derive(Clone, Debug)]
pub struct SqliteFileLocation {
    path: PathBuf,
    root: PathBuf,
    options: SqliteConnectOptions,
}

#[cfg(feature = "sqlite")]
impl SqliteFileLocation {
    /// Treats `path` as a literal native filesystem path, never as a SQLite URI.
    pub fn from_path(path: &Path) -> Result<Self, sqlx_core::Error> {
        let path = resolve_sqlite_file_path(path)?;
        let options = SqliteConnectOptions::new().filename(&path);
        Self::new(path, options)
    }

    /// Resolves a pre-existing durable database without permitting creation.
    ///
    /// The input must already be absolute and lexically normalized. Every
    /// parent component and the final file is checked with `symlink_metadata`;
    /// the final file must be regular and, on Unix, have exactly one hard
    /// link. The existing parent is then canonicalized and becomes the one
    /// adjacent state root owned by this location.
    pub fn from_existing_path(path: &Path) -> Result<Self, sqlx_core::Error> {
        let path = validate_existing_sqlite_path(path)?;
        let options = SqliteConnectOptions::new().filename(&path);
        Self::new(path, options)
    }

    /// Parses a legacy `sqlite:` URI with SQLx, then fixes its decoded filename
    /// to a stable absolute path. Memory, temporary, and nested `file:` URI
    /// semantics are rejected because this application requires durable state.
    pub fn from_uri(uri: &str) -> Result<Self, sqlx_core::Error> {
        if !uri.starts_with("sqlite:") {
            return Err(invalid_sqlite_location(
                "expected a sqlite: URI for the legacy SQLite connector",
            ));
        }

        let options = SqliteConnectOptions::from_str(uri)?;
        let uri_body = uri
            .strip_prefix("sqlite://")
            .or_else(|| uri.strip_prefix("sqlite:"))
            .unwrap_or_default();
        let (database, params) = uri_body
            .split_once('?')
            .map_or((uri_body, None), |(database, params)| {
                (database, Some(params))
            });

        if database == ":memory:" {
            return Err(invalid_sqlite_location(
                "in-memory SQLite URIs are not durable file locations",
            ));
        }
        if let Some(params) = params {
            for (key, value) in url::form_urlencoded::parse(params.as_bytes()) {
                if key == "mode" && value == "memory" {
                    return Err(invalid_sqlite_location(
                        "mode=memory SQLite URIs are not durable file locations",
                    ));
                }
                if key == "vfs" {
                    return Err(invalid_sqlite_location(
                        "custom SQLite VFS URIs cannot guarantee durable file semantics",
                    ));
                }
            }
        }

        let decoded = options.get_filename();
        if decoded.as_os_str().is_empty() {
            return Err(invalid_sqlite_location(
                "temporary SQLite URIs without a filename are not durable",
            ));
        }
        if decoded == Path::new(":memory:") {
            return Err(invalid_sqlite_location(
                ":memory: is not a durable SQLite filename",
            ));
        }
        if decoded
            .to_str()
            .is_some_and(|filename| filename.starts_with("file:"))
        {
            return Err(invalid_sqlite_location(
                "nested file: SQLite URI semantics are not accepted",
            ));
        }

        let path = resolve_sqlite_file_path(decoded)?;
        let options = options.filename(&path);
        Self::new(path, options)
    }

    fn new(path: PathBuf, options: SqliteConnectOptions) -> Result<Self, sqlx_core::Error> {
        let root = path.parent().ok_or_else(|| {
            invalid_sqlite_location("SQLite file location must have an adjacent state directory")
        })?;
        if path.file_name().is_none() {
            return Err(invalid_sqlite_location(
                "SQLite file location must name a file",
            ));
        }
        Ok(Self {
            root: root.to_path_buf(),
            path,
            options,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Opaque logical identity stored inside one migrated local database.
#[cfg(feature = "sqlite")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalDatabaseInstanceId([u8; 16]);

#[cfg(feature = "sqlite")]
impl std::fmt::Debug for LocalDatabaseInstanceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("LocalDatabaseInstanceId")
            .field(&"<redacted>")
            .finish()
    }
}

/// A pinned, non-creating, single-connection handle to an existing database.
///
/// Filesystem identity and the database's logical instance UUID are checked
/// before the handle is returned and can be rechecked through
/// [`Self::verify_identity`]. SQLx does not expose an atomic "open this inode"
/// primitive: a malicious same-UID process that swaps in an exact clone
/// (including the logical UUID) during the narrow path-open race cannot be
/// distinguished. Callers must still protect the containing directory with
/// normal per-user permissions.
#[cfg(feature = "sqlite")]
pub struct ExistingSqliteDatabase {
    location: SqliteFileLocation,
    pool: SqlitePool,
    file_identity: FileIdentity,
    instance_id: LocalDatabaseInstanceId,
}

#[cfg(feature = "sqlite")]
impl std::fmt::Debug for ExistingSqliteDatabase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExistingSqliteDatabase")
            .field("path", &self.location.path)
            .field("instance_id", &self.instance_id)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "sqlite")]
impl ExistingSqliteDatabase {
    pub fn location(&self) -> &SqliteFileLocation {
        &self.location
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub fn instance_id(&self) -> LocalDatabaseInstanceId {
        self.instance_id
    }

    /// Rechecks both the current pathname identity and the logical UUID read
    /// through the actual sole pooled connection.
    pub async fn verify_identity(&self) -> Result<(), sqlx_core::Error> {
        verify_file_identity(&self.location, &self.file_identity)?;
        let actual = read_database_instance_id(&self.pool).await?;
        if actual != self.instance_id {
            return Err(invalid_sqlite_location(
                "SQLite logical database identity changed",
            ));
        }
        verify_file_identity(&self.location, &self.file_identity)
    }
}

/// Lexically resolves a native SQLite file path without dereferencing symlinks.
#[cfg(feature = "sqlite")]
pub fn resolve_sqlite_file_path(path: &Path) -> Result<PathBuf, sqlx_core::Error> {
    if path.as_os_str().is_empty() {
        return Err(invalid_sqlite_location(
            "SQLite file path must not be empty",
        ));
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[cfg(feature = "sqlite")]
fn validate_existing_sqlite_path(path: &Path) -> Result<PathBuf, sqlx_core::Error> {
    if !path.is_absolute() {
        return Err(invalid_sqlite_location(
            "existing SQLite file path must be absolute",
        ));
    }
    if path.file_name().is_none() {
        return Err(invalid_sqlite_location(
            "existing SQLite file path must name a file",
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid_sqlite_location(
            "existing SQLite file path must be lexically normalized",
        ));
    }

    let parent = path.parent().ok_or_else(|| {
        invalid_sqlite_location("existing SQLite file must have an existing parent directory")
    })?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Normal(_)) {
            let metadata = fs::symlink_metadata(&current)?;
            if sqlite_metadata_is_indirect(&metadata) {
                return Err(invalid_sqlite_location(
                    "SQLite parent path must not contain symlinks",
                ));
            }
            if !metadata.is_dir() {
                return Err(invalid_sqlite_location(
                    "SQLite parent path component is not a directory",
                ));
            }
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let parent_metadata = fs::metadata(parent)?;
        if parent_metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid_sqlite_location(
                "SQLite state directory must not be accessible by group or other users",
            ));
        }
    }

    let mut metadata = fs::symlink_metadata(path)?;
    if sqlite_metadata_is_indirect(&metadata) {
        return Err(invalid_sqlite_location(
            "SQLite database path must not be a symlink",
        ));
    }
    if !metadata.is_file() {
        return Err(invalid_sqlite_location(
            "SQLite database path must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 {
            return Err(invalid_sqlite_location(
                "SQLite database path must not have hard links",
            ));
        }
        if metadata.permissions().mode() & 0o177 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            metadata = fs::symlink_metadata(path)?;
        }
        if metadata.permissions().mode() & 0o177 != 0 {
            return Err(invalid_sqlite_location(
                "SQLite database file permissions are not private",
            ));
        }
    }

    let canonical_parent = fs::canonicalize(parent)?;
    let filename = path
        .file_name()
        .ok_or_else(|| invalid_sqlite_location("existing SQLite file path must name a file"))?;
    let canonical_path = canonical_parent.join(filename);
    let final_metadata = fs::symlink_metadata(&canonical_path)?;
    if sqlite_metadata_is_indirect(&final_metadata) || !final_metadata.is_file() {
        return Err(invalid_sqlite_location(
            "SQLite database path changed during validation",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if final_metadata.nlink() != 1 {
            return Err(invalid_sqlite_location(
                "SQLite database path must not have hard links",
            ));
        }
    }
    validate_sqlite_sidecars(&canonical_path)?;
    Ok(canonical_path)
}

#[cfg(feature = "sqlite")]
fn validate_sqlite_sidecars(database_path: &Path) -> Result<(), sqlx_core::Error> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = database_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        let mut metadata = match fs::symlink_metadata(&sidecar) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if sqlite_metadata_is_indirect(&metadata) || !metadata.is_file() {
            return Err(invalid_sqlite_location(
                "SQLite sidecar path must be an ordinary regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.nlink() != 1 {
                return Err(invalid_sqlite_location(
                    "SQLite sidecar path must not have hard links",
                ));
            }
            if metadata.permissions().mode() & 0o177 != 0 {
                fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600))?;
                metadata = fs::symlink_metadata(&sidecar)?;
            }
            if metadata.permissions().mode() & 0o177 != 0 {
                return Err(invalid_sqlite_location(
                    "SQLite sidecar file permissions are not private",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(all(feature = "sqlite", windows))]
fn sqlite_metadata_is_indirect(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(all(feature = "sqlite", not(windows)))]
fn sqlite_metadata_is_indirect(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(feature = "sqlite")]
fn verify_file_identity(
    location: &SqliteFileLocation,
    expected: &FileIdentity,
) -> Result<(), sqlx_core::Error> {
    let current_path = validate_existing_sqlite_path(location.path())?;
    if current_path != location.path() {
        return Err(invalid_sqlite_location(
            "SQLite database canonical path changed",
        ));
    }
    let actual = FileIdentity::from_path(location.path())?;
    if &actual != expected {
        return Err(invalid_sqlite_location(
            "SQLite database filesystem identity changed",
        ));
    }
    Ok(())
}

#[cfg(feature = "sqlite")]
fn invalid_sqlite_location(message: &str) -> sqlx_core::Error {
    sqlx_core::Error::InvalidArgument(message.to_string())
}

#[cfg(feature = "postgres")]
pub async fn connect_postgres(path: &str) -> Result<PgPool, sqlx_core::Error> {
    connect_postgres_with_max(path, 10).await
}

#[cfg(feature = "postgres")]
pub async fn connect_postgres_with_max(
    path: &str,
    max_connections: u32,
) -> Result<PgPool, sqlx_core::Error> {
    let options = PgConnectOptions::from_str(path)?;
    PoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await
}

#[cfg(feature = "sqlite")]
pub async fn connect_sqlite(uri: &str) -> Result<SqlitePool, sqlx_core::Error> {
    connect_sqlite_with_max(uri, 10).await
}

#[cfg(feature = "sqlite")]
pub async fn connect_sqlite_path(path: &Path) -> Result<SqlitePool, sqlx_core::Error> {
    connect_sqlite_path_with_max(path, 10).await
}

/// Opens an already migrated SQLite database without ever creating a missing
/// file. The operational pool is deliberately capped at one eager connection
/// so identity verification and subsequent adapter transactions share the
/// same SQLite connection except after an explicit driver reconnect.
#[cfg(feature = "sqlite")]
pub async fn open_existing_sqlite(path: &Path) -> Result<ExistingSqliteDatabase, sqlx_core::Error> {
    let location = SqliteFileLocation::from_existing_path(path)?;
    let file_identity = FileIdentity::from_path(location.path())?;
    verify_file_identity(&location, &file_identity)?;

    // First read the logical identity without a persistent journal-mode
    // mutation. The pool is closed before the operational WAL connection is
    // opened and its identity is verified again.
    let probe = PoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .connect_with(sqlite_existing_probe_options(location.options.clone()))
        .await?;
    let instance_id = read_database_instance_id(&probe).await?;
    probe.close().await;
    verify_file_identity(&location, &file_identity)?;

    let pool = PoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .connect_with(sqlite_existing_connect_options(location.options.clone()))
        .await?;
    let actual = read_database_instance_id(&pool).await?;
    if actual != instance_id {
        pool.close().await;
        return Err(invalid_sqlite_location(
            "SQLite logical database identity changed while opening",
        ));
    }
    verify_file_identity(&location, &file_identity)?;
    Ok(ExistingSqliteDatabase {
        location,
        pool,
        file_identity,
        instance_id,
    })
}

#[cfg(feature = "sqlite")]
pub async fn connect_sqlite_path_with_max(
    path: &Path,
    max_connections: u32,
) -> Result<SqlitePool, sqlx_core::Error> {
    let location = SqliteFileLocation::from_path(path)?;
    connect_sqlite_file_with_max(&location, max_connections).await
}

/// Connects using the options and exact resolved path owned by `location`.
#[cfg(feature = "sqlite")]
pub async fn connect_sqlite_file_with_max(
    location: &SqliteFileLocation,
    max_connections: u32,
) -> Result<SqlitePool, sqlx_core::Error> {
    let options = sqlite_connect_options(location.options.clone());
    PoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await
}

#[cfg(feature = "sqlite")]
pub async fn connect_sqlite_with_max(
    uri: &str,
    max_connections: u32,
) -> Result<SqlitePool, sqlx_core::Error> {
    let location = SqliteFileLocation::from_uri(uri)?;
    connect_sqlite_file_with_max(&location, max_connections).await
}

#[cfg(feature = "sqlite")]
fn sqlite_connect_options(options: SqliteConnectOptions) -> SqliteConnectOptions {
    options
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true)
}

#[cfg(feature = "sqlite")]
fn sqlite_existing_probe_options(options: SqliteConnectOptions) -> SqliteConnectOptions {
    options
        .create_if_missing(false)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true)
}

#[cfg(feature = "sqlite")]
fn sqlite_existing_connect_options(options: SqliteConnectOptions) -> SqliteConnectOptions {
    sqlite_existing_probe_options(options)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
}

#[cfg(feature = "sqlite")]
async fn read_database_instance_id(
    pool: &SqlitePool,
) -> Result<LocalDatabaseInstanceId, sqlx_core::Error> {
    let rows = sqlx_core::query::query::<Sqlite>(
        r#"
        SELECT CASE
            WHEN typeof(singleton) != 'integer' THEN NULL
            WHEN singleton != 1 THEN NULL
            WHEN typeof(instance_uuid) != 'blob' THEN NULL
            WHEN octet_length(instance_uuid) != 16 THEN NULL
            ELSE hex(instance_uuid)
        END AS instance_hex
        FROM local_database_identity
        LIMIT 2
        "#,
    )
    .fetch_all(pool)
    .await?;
    let [row] = rows.as_slice() else {
        return Err(invalid_sqlite_location(
            "SQLite logical database identity is missing or duplicated",
        ));
    };
    let encoded = row
        .try_get::<Option<String>, _>("instance_hex")?
        .ok_or_else(|| invalid_sqlite_location("SQLite logical database identity is corrupt"))?;
    let decoded = decode_instance_hex(&encoded)?;
    Ok(LocalDatabaseInstanceId(decoded))
}

#[cfg(feature = "sqlite")]
fn decode_instance_hex(encoded: &str) -> Result<[u8; 16], sqlx_core::Error> {
    if encoded.len() != 32 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_sqlite_location(
            "SQLite logical database identity is corrupt",
        ));
    }
    let mut decoded = [0_u8; 16];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

#[cfg(feature = "sqlite")]
fn decode_hex_nibble(value: u8) -> Result<u8, sqlx_core::Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(invalid_sqlite_location(
            "SQLite logical database identity is corrupt",
        )),
    }
}

#[cfg(feature = "postgres")]
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx_core::migrate::MigrateError> {
    sqlx_macros::migrate!("../zann-server/migrations")
        .run(pool)
        .await
}

#[cfg(feature = "sqlite")]
pub async fn migrate_local(pool: &SqlitePool) -> Result<(), sqlx_core::migrate::MigrateError> {
    sqlx_macros::migrate!("../zann-db/migrations")
        .run(pool)
        .await
}
