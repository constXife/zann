//! Secure, process-wide file locks for client state transitions.
//!
//! Lock files are deliberately empty. Ownership is represented only by the
//! operating-system lock attached to the open file handle; no process id or
//! operation data is persisted. A lock path is selected exclusively from
//! [`LockKind`] and a client root so callers cannot accidentally create a
//! second lock namespace for the same operation.

use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use same_file::Handle;

use super::v2::ConfigError;

pub const CONFIG_LOCK_FILENAME: &str = "client-config.lock";
pub const CREDENTIAL_OPERATION_LOCK_FILENAME: &str = "client-config.credential.lock";
pub const SYNC_COMMIT_LOCK_FILENAME: &str = "client-sync.commit.lock";
pub(crate) const AUTH_OPERATION_LOCK_FILENAME: &str = "client-auth.lock";

const LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);

/// A distinct state transition serialized below the interface adapters.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum LockKind {
    AuthOperation,
    CredentialOperation,
    SyncCommit,
    Config,
}

impl LockKind {
    /// Resolves the one canonical lock path for this operation under `root`.
    ///
    /// Keeping this mapping here prevents callers from acquiring an ad-hoc
    /// filename which would look locked locally but not contend with another
    /// client process.
    pub(crate) fn path_in(self, root: &Path) -> PathBuf {
        root.join(self.filename())
    }

    pub(crate) fn pending_at(self, root: &Path) -> Result<PendingFileLock, ConfigError> {
        PendingFileLock::open(root, self)
    }

    const fn filename(self) -> &'static str {
        match self {
            Self::Config => CONFIG_LOCK_FILENAME,
            Self::CredentialOperation => CREDENTIAL_OPERATION_LOCK_FILENAME,
            Self::AuthOperation => AUTH_OPERATION_LOCK_FILENAME,
            Self::SyncCommit => SYNC_COMMIT_LOCK_FILENAME,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Config => "config lock",
            Self::CredentialOperation => "credential operation lock",
            Self::AuthOperation => "authentication operation lock",
            Self::SyncCommit => "sync commit lock",
        }
    }

    const fn inspect_path_operation(self) -> &'static str {
        match self {
            Self::Config => "inspect config lock path",
            Self::CredentialOperation => "inspect credential operation lock path",
            Self::AuthOperation => "inspect authentication operation lock path",
            Self::SyncCommit => "inspect sync commit lock path",
        }
    }

    const fn open_operation(self) -> &'static str {
        match self {
            Self::Config => "open config lock",
            Self::CredentialOperation => "open credential operation lock",
            Self::AuthOperation => "open authentication operation lock",
            Self::SyncCommit => "open sync commit lock",
        }
    }

    const fn inspect_file_operation(self) -> &'static str {
        match self {
            Self::Config => "inspect open config lock",
            Self::CredentialOperation => "inspect open credential operation lock",
            Self::AuthOperation => "inspect open authentication operation lock",
            Self::SyncCommit => "inspect open sync commit lock",
        }
    }

    const fn clone_handle_operation(self) -> &'static str {
        match self {
            Self::Config => "clone open config lock handle",
            Self::CredentialOperation => "clone open credential operation lock handle",
            Self::AuthOperation => "clone open authentication operation lock handle",
            Self::SyncCommit => "clone open sync commit lock handle",
        }
    }

    const fn identify_file_operation(self) -> &'static str {
        match self {
            Self::Config => "identify open config lock",
            Self::CredentialOperation => "identify open credential operation lock",
            Self::AuthOperation => "identify open authentication operation lock",
            Self::SyncCommit => "identify open sync commit lock",
        }
    }

    const fn identify_path_operation(self) -> &'static str {
        match self {
            Self::Config => "identify config lock path",
            Self::CredentialOperation => "identify credential operation lock path",
            Self::AuthOperation => "identify authentication operation lock path",
            Self::SyncCommit => "identify sync commit lock path",
        }
    }

    #[cfg(unix)]
    const fn secure_permissions_operation(self) -> &'static str {
        match self {
            Self::Config => "secure config lock permissions",
            Self::CredentialOperation => "secure credential operation lock permissions",
            Self::AuthOperation => "secure authentication operation lock permissions",
            Self::SyncCommit => "secure sync commit lock permissions",
        }
    }

    const fn acquire_operation(self) -> &'static str {
        match self {
            Self::Config => "lock config",
            Self::CredentialOperation => "lock credential operation",
            Self::AuthOperation => "lock authentication operation",
            Self::SyncCommit => "lock sync commit",
        }
    }

    fn unsafe_path(self, path: &Path, condition: &'static str) -> ConfigError {
        ConfigError::UnsafePath {
            path: path.to_path_buf(),
            reason: format!("{} {condition}", self.label()),
        }
    }
}

/// The only supported nested acquisition order for client state locks.
///
/// Keep this definition beside [`LockKind`] so every caller shares one order:
/// authentication -> credential operation -> sync commit -> config.
pub(crate) const LOCK_ORDER: [LockKind; 4] = [
    LockKind::AuthOperation,
    LockKind::CredentialOperation,
    LockKind::SyncCommit,
    LockKind::Config,
];

pub(crate) fn lock_order_allows(outer: LockKind, inner: LockKind) -> bool {
    let outer = LOCK_ORDER
        .iter()
        .position(|kind| *kind == outer)
        .expect("every lock kind is present in the canonical order");
    let inner = LOCK_ORDER
        .iter()
        .position(|kind| *kind == inner)
        .expect("every lock kind is present in the canonical order");
    outer < inner
}

/// Holds the shared sync gate and the config lock in the canonical order.
///
/// Fields intentionally drop in declaration order, releasing config before
/// the outer sync gate.
pub(crate) struct ConfigFileLockGuard {
    _config: FileLockGuard,
    _sync_commit: FileLockGuard,
}

impl ConfigFileLockGuard {
    pub(crate) fn acquire(root: &Path, timeout: Duration) -> Result<Self, ConfigError> {
        debug_assert!(lock_order_allows(LockKind::SyncCommit, LockKind::Config));
        let sync_commit = LockKind::SyncCommit
            .pending_at(root)?
            .acquire_blocking(timeout)?;
        let config = match LockKind::Config.pending_at(root)?.acquire_blocking(timeout) {
            Ok(config) => config,
            Err(error) => {
                drop(sync_commit);
                return Err(error);
            }
        };
        Ok(Self {
            _config: config,
            _sync_commit: sync_commit,
        })
    }
}

/// An opened and validated lock file which has not necessarily been acquired.
///
/// A contended non-blocking attempt returns this value so the caller may retry
/// the same file handle without reopening a potentially replaced path.
pub(crate) struct PendingFileLock {
    kind: LockKind,
    path: PathBuf,
    file: File,
    identity: Handle,
}

impl fmt::Debug for PendingFileLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingFileLock")
            .field("kind", &self.kind)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl PendingFileLock {
    pub(crate) fn open(root: &Path, kind: LockKind) -> Result<Self, ConfigError> {
        Self::open_with(root, kind, |_| {})
    }

    /// Attempts to acquire the lock once without sleeping.
    pub(crate) fn try_acquire(self) -> Result<LockAttempt, ConfigError> {
        match self.file.try_lock() {
            Ok(()) => {
                self.validate_identity()?;
                Ok(LockAttempt::Acquired(self.into_guard()))
            }
            Err(TryLockError::WouldBlock) => Ok(LockAttempt::WouldBlock(self)),
            Err(TryLockError::Error(source)) => {
                Err(self.io_error(self.kind.acquire_operation(), source))
            }
        }
    }

    /// Waits up to `timeout` for the lock, retrying at a bounded cadence.
    pub(crate) fn acquire_blocking(self, timeout: Duration) -> Result<FileLockGuard, ConfigError> {
        let started = Instant::now();
        let mut pending = self;

        loop {
            match pending.try_acquire()? {
                LockAttempt::Acquired(guard) => return Ok(guard),
                LockAttempt::WouldBlock(next) if started.elapsed() < timeout => {
                    pending = next;
                    let remaining = timeout.saturating_sub(started.elapsed());
                    thread::sleep(LOCK_RETRY_DELAY.min(remaining));
                }
                LockAttempt::WouldBlock(next) => {
                    return Err(ConfigError::Busy {
                        path: next.path,
                        timeout_ms: duration_millis_saturating(timeout),
                    });
                }
            }
        }
    }

    /// Waits asynchronously for the same already-opened lock handle.
    ///
    /// Each contended attempt yields to Tokio instead of sleeping the executor
    /// thread. Dropping this future drops the pending file immediately; if an
    /// outer lock guard is held by the caller, ordinary future cancellation
    /// drops that guard as well.
    #[cfg(feature = "session")]
    pub(crate) async fn acquire_async(
        self,
        timeout: Duration,
    ) -> Result<FileLockGuard, ConfigError> {
        let started = Instant::now();
        let mut pending = self;

        loop {
            match pending.try_acquire()? {
                LockAttempt::Acquired(guard) => return Ok(guard),
                LockAttempt::WouldBlock(next) if started.elapsed() < timeout => {
                    pending = next;
                    let remaining = timeout.saturating_sub(started.elapsed());
                    tokio::time::sleep(LOCK_RETRY_DELAY.min(remaining)).await;
                }
                LockAttempt::WouldBlock(next) => {
                    return Err(ConfigError::Busy {
                        path: next.path,
                        timeout_ms: duration_millis_saturating(timeout),
                    });
                }
            }
        }
    }

    fn open_with(
        root: &Path,
        kind: LockKind,
        after_open: impl FnOnce(&Path),
    ) -> Result<Self, ConfigError> {
        ensure_config_root(root)?;
        let path = kind.path_in(root);
        validate_lock_path_before_open(kind, &path)?;

        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        configure_lock_creation(&mut options);

        let file = options.open(&path).map_err(|source| ConfigError::Io {
            operation: kind.open_operation(),
            path: path.clone(),
            source,
        })?;
        let identity_file = file.try_clone().map_err(|source| ConfigError::Io {
            operation: kind.clone_handle_operation(),
            path: path.clone(),
            source,
        })?;
        let identity = Handle::from_file(identity_file).map_err(|source| ConfigError::Io {
            operation: kind.identify_file_operation(),
            path: path.clone(),
            source,
        })?;

        // This private seam makes replacement races deterministic in tests;
        // production always supplies a no-op callback and cannot choose a path.
        after_open(&path);

        let pending = Self {
            kind,
            path,
            file,
            identity,
        };
        pending.validate_identity()?;
        secure_lock_permissions(kind, &pending.path, &pending.file)?;
        pending.validate_identity()?;
        Ok(pending)
    }

    fn validate_identity(&self) -> Result<(), ConfigError> {
        validate_open_lock(self.kind, &self.path, &self.file)?;
        validate_required_lock_path(self.kind, &self.path)?;

        let path_handle = Handle::from_path(&self.path)
            .map_err(|source| self.io_error(self.kind.identify_path_operation(), source))?;
        if self.identity != path_handle {
            return Err(self
                .kind
                .unsafe_path(&self.path, "path does not identify the opened lock file"));
        }

        // Check again after opening the path handle so a symlink or hard-link
        // substitution during identity validation is rejected as well.
        validate_required_lock_path(self.kind, &self.path)?;
        validate_open_lock(self.kind, &self.path, &self.file)
    }

    fn into_guard(self) -> FileLockGuard {
        FileLockGuard {
            kind: self.kind,
            path: self.path,
            file: self.file,
            _identity: self.identity,
        }
    }

    fn io_error(&self, operation: &'static str, source: io::Error) -> ConfigError {
        ConfigError::Io {
            operation,
            path: self.path.clone(),
            source,
        }
    }
}

/// Result of one non-blocking lock attempt.
pub(crate) enum LockAttempt {
    Acquired(FileLockGuard),
    WouldBlock(PendingFileLock),
}

impl fmt::Debug for LockAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acquired(guard) => formatter.debug_tuple("Acquired").field(guard).finish(),
            Self::WouldBlock(pending) => {
                formatter.debug_tuple("WouldBlock").field(pending).finish()
            }
        }
    }
}

/// RAII ownership of an acquired OS lock.
pub(crate) struct FileLockGuard {
    kind: LockKind,
    path: PathBuf,
    file: File,
    // Keep the identity handle alive with the locking file. `same-file`
    // consumes an owned clone, so both handles cover the full guard lifetime.
    _identity: Handle,
}

impl fmt::Debug for FileLockGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileLockGuard")
            .field("kind", &self.kind)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        // Closing the file also releases the lock. An explicit unlock avoids
        // retaining it until the final close if `File` internals ever change.
        let _ = self.file.unlock();
    }
}

fn duration_millis_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

pub(super) fn ensure_config_root(root: &Path) -> Result<(), ConfigError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => validate_config_root(root, &metadata)?,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(root).map_err(|source| ConfigError::Io {
                operation: "create config directory",
                path: root.to_path_buf(),
                source,
            })?;
        }
        Err(source) => {
            return Err(ConfigError::Io {
                operation: "inspect config directory",
                path: root.to_path_buf(),
                source,
            });
        }
    }

    let metadata = fs::symlink_metadata(root).map_err(|source| ConfigError::Io {
        operation: "inspect config directory",
        path: root.to_path_buf(),
        source,
    })?;
    validate_config_root(root, &metadata)?;
    secure_root_permissions(root)
}

fn validate_config_root(root: &Path, metadata: &fs::Metadata) -> Result<(), ConfigError> {
    if metadata_is_indirect(metadata) || !metadata.is_dir() {
        return Err(ConfigError::UnsafePath {
            path: root.to_path_buf(),
            reason: "config root must be a real directory".to_string(),
        });
    }
    Ok(())
}

pub(super) fn validate_regular_file_if_exists(path: &Path) -> Result<bool, ConfigError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata_is_indirect(&metadata) || !metadata.is_file() => {
            Err(ConfigError::UnsafePath {
                path: path.to_path_buf(),
                reason: "expected a non-symlink regular file".to_string(),
            })
        }
        Ok(_) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(ConfigError::Io {
            operation: "inspect config file",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_lock_path_before_open(kind: LockKind, path: &Path) -> Result<(), ConfigError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_lock_metadata(kind, path, &metadata),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ConfigError::Io {
            operation: kind.inspect_path_operation(),
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_required_lock_path(kind: LockKind, path: &Path) -> Result<(), ConfigError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(kind.unsafe_path(path, "path disappeared while its file was open"));
        }
        Err(source) => {
            return Err(ConfigError::Io {
                operation: kind.inspect_path_operation(),
                path: path.to_path_buf(),
                source,
            });
        }
    };
    validate_lock_metadata(kind, path, &metadata)
}

fn validate_lock_metadata(
    kind: LockKind,
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ConfigError> {
    if metadata_is_indirect(metadata) || !metadata.is_file() {
        return Err(kind.unsafe_path(path, "must be a non-symlink regular file"));
    }
    validate_single_link(kind, path, metadata)
}

#[cfg(windows)]
fn metadata_is_indirect(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_indirect(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn validate_open_lock(kind: LockKind, path: &Path, file: &File) -> Result<(), ConfigError> {
    let metadata = file.metadata().map_err(|source| ConfigError::Io {
        operation: kind.inspect_file_operation(),
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(kind.unsafe_path(path, "handle must refer to a regular file"));
    }
    validate_single_link(kind, path, &metadata)
}

#[cfg(unix)]
fn validate_single_link(
    kind: LockKind,
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.nlink() != 1 {
        return Err(kind.unsafe_path(path, "must have exactly one hard link"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_single_link(
    _kind: LockKind,
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), ConfigError> {
    Ok(())
}

#[cfg(unix)]
fn configure_lock_creation(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn configure_lock_creation(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn secure_root_permissions(root: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(|source| ConfigError::Io {
        operation: "secure config directory permissions",
        path: root.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn secure_root_permissions(_root: &Path) -> Result<(), ConfigError> {
    Ok(())
}

#[cfg(unix)]
fn secure_lock_permissions(kind: LockKind, path: &Path, file: &File) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| ConfigError::Io {
            operation: kind.secure_permissions_operation(),
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn secure_lock_permissions(_kind: LockKind, _path: &Path, _file: &File) -> Result<(), ConfigError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::{Child, Command};
    use std::thread;
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::*;

    const SUBPROCESS_MODE_ENV: &str = "ZANN_CLIENT_LOCK_HELPER_MODE";
    const SUBPROCESS_ROOT_ENV: &str = "ZANN_CLIENT_LOCK_HELPER_ROOT";
    const SUBPROCESS_MODE_HOLD_AUTH: &str = "hold-auth-v1";

    struct ChildGuard(Option<Child>);

    impl ChildGuard {
        fn child_mut(&mut self) -> &mut Child {
            self.0.as_mut().expect("child is present")
        }

        fn wait(mut self) -> std::process::ExitStatus {
            let mut child = self.0.take().expect("child is present");
            child.wait().expect("wait for lock helper")
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[test]
    fn lock_kinds_have_fixed_distinct_paths() {
        let root = Path::new("client-root");

        assert_eq!(
            LockKind::Config.path_in(root),
            root.join(CONFIG_LOCK_FILENAME)
        );
        assert_eq!(
            LockKind::CredentialOperation.path_in(root),
            root.join(CREDENTIAL_OPERATION_LOCK_FILENAME)
        );
        assert_eq!(
            LockKind::AuthOperation.path_in(root),
            root.join(AUTH_OPERATION_LOCK_FILENAME)
        );
        assert_eq!(
            LockKind::SyncCommit.path_in(root),
            root.join(SYNC_COMMIT_LOCK_FILENAME)
        );
        assert_eq!(
            LOCK_ORDER,
            [
                LockKind::AuthOperation,
                LockKind::CredentialOperation,
                LockKind::SyncCommit,
                LockKind::Config,
            ]
        );
        for adjacent in LOCK_ORDER.windows(2) {
            assert!(lock_order_allows(adjacent[0], adjacent[1]));
            assert!(!lock_order_allows(adjacent[1], adjacent[0]));
        }
        for kind in LOCK_ORDER {
            assert!(!lock_order_allows(kind, kind));
        }
    }

    #[test]
    fn lock_files_remain_empty_and_are_released_with_the_guard() {
        let temp = TempDir::new().expect("temp directory");
        let first = LockKind::AuthOperation
            .pending_at(temp.path())
            .expect("open first lock")
            .acquire_blocking(Duration::from_secs(1))
            .expect("acquire first lock");

        let second = LockKind::AuthOperation
            .pending_at(temp.path())
            .expect("open second lock");
        let second = match second.try_acquire().expect("try second lock") {
            LockAttempt::Acquired(_) => panic!("second handle acquired a contended lock"),
            LockAttempt::WouldBlock(pending) => pending,
        };

        assert_eq!(
            first.file.metadata().expect("inspect lock file").len(),
            0,
            "lock ownership must not write process data"
        );
        drop(first);
        assert_eq!(
            fs::read(LockKind::AuthOperation.path_in(temp.path()))
                .expect("read released empty lock file"),
            Vec::<u8>::new()
        );

        let second = match second.try_acquire().expect("retry second lock") {
            LockAttempt::Acquired(guard) => guard,
            LockAttempt::WouldBlock(_) => panic!("lock remained held after guard drop"),
        };
        assert_eq!(second.kind, LockKind::AuthOperation);
    }

    #[test]
    fn blocking_acquisition_reports_the_fixed_path_and_timeout() {
        let temp = TempDir::new().expect("temp directory");
        let _held = LockKind::Config
            .pending_at(temp.path())
            .expect("open first lock")
            .acquire_blocking(Duration::from_secs(1))
            .expect("acquire first lock");

        let error = LockKind::Config
            .pending_at(temp.path())
            .expect("open second lock")
            .acquire_blocking(Duration::from_millis(20))
            .expect_err("second acquisition must time out");

        match error {
            ConfigError::Busy { path, timeout_ms } => {
                assert_eq!(path, temp.path().join(CONFIG_LOCK_FILENAME));
                assert_eq!(timeout_ms, 20);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(feature = "session")]
    #[tokio::test(flavor = "current_thread")]
    async fn async_acquisition_yields_the_current_thread_executor() {
        let temp = TempDir::new().expect("temp directory");
        let held = LockKind::Config
            .pending_at(temp.path())
            .expect("open held config lock")
            .acquire_blocking(Duration::from_secs(1))
            .expect("acquire held config lock");
        let root = temp.path().to_path_buf();
        let waiter = tokio::spawn(async move {
            LockKind::Config
                .pending_at(&root)
                .expect("open async config waiter")
                .acquire_async(Duration::from_secs(1))
                .await
        });

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !waiter.is_finished(),
            "contended async acquisition must yield instead of timing out inline"
        );
        drop(held);
        let acquired = tokio::time::timeout(Duration::from_millis(250), waiter)
            .await
            .expect("async waiter resumes on current-thread runtime")
            .expect("async waiter task")
            .expect("async waiter acquires released lock");
        assert_eq!(acquired.kind, LockKind::Config);
    }

    #[cfg(feature = "session")]
    #[tokio::test(flavor = "current_thread")]
    async fn cancelling_nested_async_acquisition_releases_outer_sync_gate() {
        let temp = TempDir::new().expect("temp directory");
        let held_config = LockKind::Config
            .pending_at(temp.path())
            .expect("open held config lock")
            .acquire_blocking(Duration::from_secs(1))
            .expect("acquire held config lock");
        let root = temp.path().to_path_buf();
        let waiter = tokio::spawn(async move {
            let sync_commit = LockKind::SyncCommit
                .pending_at(&root)?
                .acquire_async(Duration::from_secs(1))
                .await?;
            let config = LockKind::Config
                .pending_at(&root)?
                .acquire_async(Duration::from_secs(1))
                .await?;
            Ok::<_, ConfigError>((sync_commit, config))
        });

        tokio::time::sleep(Duration::from_millis(30)).await;
        let probe = LockKind::SyncCommit
            .pending_at(temp.path())
            .expect("open sync-gate probe");
        assert!(matches!(
            probe.try_acquire().expect("probe held sync gate"),
            LockAttempt::WouldBlock(_)
        ));

        waiter.abort();
        assert!(waiter
            .await
            .expect_err("cancel nested waiter")
            .is_cancelled());
        drop(held_config);
        let released = LockKind::SyncCommit
            .pending_at(temp.path())
            .expect("reopen sync gate after cancellation")
            .acquire_async(Duration::from_millis(100))
            .await
            .expect("cancellation drops the outer sync gate");
        assert_eq!(released.kind, LockKind::SyncCommit);
    }

    #[test]
    fn subprocess_holds_auth_lock() {
        if std::env::var(SUBPROCESS_MODE_ENV).ok().as_deref() != Some(SUBPROCESS_MODE_HOLD_AUTH) {
            return;
        }

        let root = PathBuf::from(
            std::env::var_os(SUBPROCESS_ROOT_ENV).expect("subprocess lock root is set"),
        );
        let _guard = LockKind::AuthOperation
            .pending_at(&root)
            .expect("helper opens auth lock")
            .acquire_blocking(Duration::from_secs(2))
            .expect("helper acquires auth lock");
        fs::write(root.join("helper-ready"), []).expect("publish helper readiness");

        let release = root.join("helper-release");
        let started = Instant::now();
        while !release.exists() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "parent did not release lock helper"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn auth_lock_serializes_distinct_processes() {
        let temp = TempDir::new().expect("temp directory");
        let helper_name = "config::locking::tests::subprocess_holds_auth_lock";
        let child = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg(helper_name)
            .arg("--test-threads=1")
            .env(SUBPROCESS_MODE_ENV, SUBPROCESS_MODE_HOLD_AUTH)
            .env(SUBPROCESS_ROOT_ENV, temp.path())
            .spawn()
            .expect("spawn lock helper");
        let mut child = ChildGuard(Some(child));

        let ready = temp.path().join("helper-ready");
        let started = Instant::now();
        while !ready.exists() {
            if let Some(status) = child.child_mut().try_wait().expect("inspect lock helper") {
                panic!("lock helper exited before readiness: {status}");
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "lock helper did not become ready"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let error = LockKind::AuthOperation
            .pending_at(temp.path())
            .expect("parent opens auth lock")
            .acquire_blocking(Duration::from_millis(30))
            .expect_err("helper must exclude parent process");
        assert!(matches!(error, ConfigError::Busy { timeout_ms: 30, .. }));

        fs::write(temp.path().join("helper-release"), []).expect("release helper");
        assert!(child.wait().success(), "lock helper failed");

        LockKind::AuthOperation
            .pending_at(temp.path())
            .expect("parent reopens auth lock")
            .acquire_blocking(Duration::from_secs(1))
            .expect("parent acquires released auth lock");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_lock_path() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("temp directory");
        let target = temp.path().join("target");
        fs::write(&target, []).expect("write target");
        symlink(&target, LockKind::Config.path_in(temp.path())).expect("create symlink");

        let error = LockKind::Config
            .pending_at(temp.path())
            .expect_err("symlink must be rejected");
        assert!(matches!(error, ConfigError::UnsafePath { .. }));
    }

    #[test]
    fn rejects_a_directory_lock_path() {
        let temp = TempDir::new().expect("temp directory");
        fs::create_dir(LockKind::Config.path_in(temp.path())).expect("create lock directory");

        let error = LockKind::Config
            .pending_at(temp.path())
            .expect_err("directory must be rejected");
        assert!(matches!(error, ConfigError::UnsafePath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_hard_link_lock_path_without_changing_target_permissions() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = TempDir::new().expect("temp directory");
        let target = temp.path().join("target");
        fs::write(&target, []).expect("write target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640))
            .expect("set target permissions");
        fs::hard_link(&target, LockKind::CredentialOperation.path_in(temp.path()))
            .expect("create hard link");

        let error = LockKind::CredentialOperation
            .pending_at(temp.path())
            .expect_err("hard link must be rejected");
        assert!(matches!(error, ConfigError::UnsafePath { .. }));
        assert_eq!(fs::metadata(target).expect("target metadata").nlink(), 2);
        assert_eq!(
            fs::metadata(temp.path().join("target"))
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_path_replacement_between_open_and_identity_check() {
        let temp = TempDir::new().expect("temp directory");
        let displaced = temp.path().join("displaced.lock");

        let error = PendingFileLock::open_with(temp.path(), LockKind::AuthOperation, |path| {
            fs::rename(path, &displaced).expect("displace opened lock");
            fs::write(path, []).expect("replace lock path");
        })
        .expect_err("replacement must be rejected");

        match error {
            ConfigError::UnsafePath { reason, .. } => {
                assert!(reason.contains("does not identify the opened lock file"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn creates_private_root_and_lock_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("temp directory");
        let root = temp.path().join("nested-client-root");
        let lock = LockKind::AuthOperation
            .pending_at(&root)
            .expect("open lock");

        assert_eq!(
            fs::metadata(&root)
                .expect("root metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(lock.path)
                .expect("lock metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
