//! Everything that talks to the zann core and to a zann server.
//!
//! Split by who owns the state on the other side: [`local`] drives the vault on
//! this machine, [`remote`] drives a login against a server. Both are
//! synchronous — the core blocks on its own tokio runtime and master key
//! derivation is deliberately expensive — so callers push the work onto a
//! worker thread with [`off_thread`].

pub mod local;
pub mod remote;

use std::cell::RefCell;
use std::ffi::OsString;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use cosmic::iced::futures::channel::oneshot;
use zann_ffi::SqliteFileLocation;

const LOCAL_DB_FILENAME: &str = "local.sqlite";

/// A database selected by the composition root.
///
/// Native filesystem paths remain [`PathBuf`]s all the way to SQLx. The URI
/// variant exists only for the public compatibility input `ZANN_DB_URL` and
/// callers that explicitly pass a `sqlite:` URI.
#[derive(Clone, Debug)]
pub struct DatabaseLocation {
    file: Arc<SqliteFileLocation>,
}

impl DatabaseLocation {
    /// Resolves `ZANN_DB_URL`, then `~/.zann/local.sqlite`, exactly once for a
    /// session. Non-UTF-8 environment values are preserved as filesystem paths.
    pub fn resolve_default() -> Result<Self, String> {
        match std::env::var_os("ZANN_DB_URL") {
            Some(value) => Self::from_os_input(value),
            None => Self::try_from(local_root().join(LOCAL_DB_FILENAME)),
        }
    }

    fn from_os_input(value: OsString) -> Result<Self, String> {
        match value.into_string() {
            Ok(value) => Self::try_from(value),
            Err(value) => Self::try_from(PathBuf::from(value)),
        }
    }

    /// Directory shared by the database, client config, and remembered-unlock
    /// state. Non-file SQLite URIs fail closed because they have no such root.
    pub fn client_root(&self) -> &Path {
        self.file.root()
    }

    pub fn path(&self) -> &Path {
        self.file.path()
    }

    pub(crate) fn file_location(&self) -> &SqliteFileLocation {
        &self.file
    }
}

impl TryFrom<PathBuf> for DatabaseLocation {
    type Error = String;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        SqliteFileLocation::from_path(&path)
            .map(|file| Self {
                file: Arc::new(file),
            })
            .map_err(|err| err.to_string())
    }
}

impl TryFrom<String> for DatabaseLocation {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.starts_with("sqlite:") {
            SqliteFileLocation::from_uri(&value)
                .map(|file| Self {
                    file: Arc::new(file),
                })
                .map_err(|err| err.to_string())
        } else {
            Self::try_from(PathBuf::from(value))
        }
    }
}

fn local_root() -> PathBuf {
    dirs::home_dir()
        .map(|home| home.join(".zann"))
        .unwrap_or_else(|| PathBuf::from("."))
}

#[derive(Clone)]
struct ActiveDatabase {
    id: u64,
    location: DatabaseLocation,
}

thread_local! {
    static ACTIVE_DATABASES: RefCell<Vec<ActiveDatabase>> = const { RefCell::new(Vec::new()) };
}

static NEXT_ACTIVE_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

/// Keeps `Remote::new` bound to the already-open session database. The marker
/// is intentionally `!Send`: moving the UI session across threads fails closed
/// instead of consulting a different thread's active composition root.
pub(crate) struct ActiveDatabaseGuard {
    id: u64,
    _not_send: PhantomData<Rc<()>>,
}

pub(crate) fn activate_database(location: DatabaseLocation) -> ActiveDatabaseGuard {
    let id = NEXT_ACTIVE_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
    ACTIVE_DATABASES.with(|active| {
        active.borrow_mut().push(ActiveDatabase { id, location });
    });
    ActiveDatabaseGuard {
        id,
        _not_send: PhantomData,
    }
}

pub(crate) fn active_database_location() -> Result<DatabaseLocation, String> {
    ACTIVE_DATABASES.with(|active| {
        active
            .borrow()
            .last()
            .map(|entry| entry.location.clone())
            .ok_or_else(|| {
                "remote login is unavailable until the local database session is open".to_string()
            })
    })
}

impl Drop for ActiveDatabaseGuard {
    fn drop(&mut self) {
        ACTIVE_DATABASES.with(|active| active.borrow_mut().retain(|entry| entry.id != self.id));
    }
}

/// Runs a blocking call on its own thread and awaits the result.
pub async fn off_thread<T, F>(work: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    let (sender, receiver) = oneshot::channel();
    std::thread::spawn(move || {
        let _ = sender.send(work());
    });
    receiver
        .await
        .unwrap_or_else(|_| Err("background task did not finish".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_special_characters_are_paths_not_sqlite_uris() {
        let location = DatabaseLocation::try_from("/tmp/zann # ? %.sqlite".to_string())
            .expect("literal path location");
        assert_eq!(location.path(), Path::new("/tmp/zann # ? %.sqlite"));
    }

    #[test]
    fn only_explicit_sqlite_inputs_use_legacy_uri_compatibility() {
        let uri = "sqlite:///tmp/zann.sqlite?mode=rwc".to_string();
        let location = DatabaseLocation::try_from(uri).expect("durable SQLite URI");
        assert_eq!(location.path(), Path::new("/tmp/zann.sqlite"));
    }

    #[test]
    fn non_durable_sqlite_uri_fails_before_session_activation() {
        for uri in ["sqlite::memory:", "sqlite://?mode=memory", "sqlite:"] {
            assert!(
                DatabaseLocation::try_from(uri.to_string()).is_err(),
                "{uri} must fail closed"
            );
        }
    }

    #[test]
    fn production_backends_do_not_stringify_paths_into_sqlite_uris() {
        let forbidden = [
            ["format!(\"sqlite", "://"].concat(),
            ["connect_sqlite_", "path_with_max"].concat(),
            ["connect_sqlite_", "with_max"].concat(),
            ["strip_prefix(\"sqlite", "://\")"].concat(),
        ];
        for (name, source) in [
            ("backend/mod.rs", include_str!("mod.rs")),
            ("backend/local.rs", include_str!("local.rs")),
            ("backend/remote.rs", include_str!("remote.rs")),
            ("session.rs", include_str!("../session.rs")),
        ] {
            for pattern in &forbidden {
                assert!(
                    !source.contains(pattern),
                    "{name} must use the shared durable file-location API"
                );
            }
        }
    }

    #[test]
    fn nested_active_database_guard_restores_and_cleans_up() {
        let first = DatabaseLocation::try_from(PathBuf::from("/tmp/zann-first.sqlite"))
            .expect("first location");
        let second = DatabaseLocation::try_from(PathBuf::from("/tmp/zann-second.sqlite"))
            .expect("second location");
        let first_guard = activate_database(first.clone());
        assert_eq!(
            active_database_location().expect("first active").path(),
            first.path()
        );

        {
            let _second_guard = activate_database(second.clone());
            assert_eq!(
                active_database_location().expect("second active").path(),
                second.path()
            );
        }

        assert_eq!(
            active_database_location().expect("first restored").path(),
            first.path()
        );
        drop(first_guard);
        assert!(active_database_location().is_err());
    }
}
