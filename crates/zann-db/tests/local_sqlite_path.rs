#![cfg(feature = "sqlite")]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sqlx_core::row::Row;
use sqlx_sqlite::Sqlite;
use uuid::Uuid;
use zann_db::{
    connect_sqlite_file_with_max, connect_sqlite_path_with_max, migrate_local,
    open_existing_sqlite, SqliteFileLocation,
};

static CWD_LOCK: Mutex<()> = Mutex::new(());

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "zann-sqlite-location-{label}-{}",
            Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&path).expect("create test tree");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("secure test tree");
        }
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct CurrentDirGuard(PathBuf);

impl CurrentDirGuard {
    fn change_to(path: &Path) -> Self {
        let original = std::env::current_dir().expect("read current directory");
        std::env::set_current_dir(path).expect("change current directory");
        Self(original)
    }
}

impl Drop for CurrentDirGuard {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.0).expect("restore current directory");
    }
}

async fn create_migrated_database(path: &Path) {
    let pool = connect_sqlite_path_with_max(path, 1)
        .await
        .expect("create SQLite test database");
    migrate_local(&pool)
        .await
        .expect("migrate SQLite test database");
    pool.close().await;
}

#[tokio::test]
async fn sqlite_path_connector_does_not_interpret_filename_as_a_uri() {
    let tree = TempTree::new("delimiters");
    let path = tree.path().join("literal #? %.sqlite");

    let pool = connect_sqlite_path_with_max(&path, 1)
        .await
        .expect("connect to literal SQLite path");
    migrate_local(&pool)
        .await
        .expect("migrate database at literal path");
    let storage_count: i64 =
        sqlx_core::query::query::<Sqlite>(r#"SELECT COUNT(*) AS count FROM storages"#)
            .fetch_one(&pool)
            .await
            .expect("query database at literal path")
            .try_get("count")
            .expect("decode storage count");
    assert_eq!(storage_count, 1);
    assert!(
        path.exists(),
        "connector must use the exact filesystem path"
    );

    pool.close().await;
}

#[tokio::test]
async fn percent_encoded_query_uri_uses_one_decoded_database_and_root() {
    let tree = TempTree::new("percent-uri");
    let path = tree.path().join("encoded # ? %.sqlite");
    let encoded = path
        .to_str()
        .expect("UTF-8 test path")
        .replace('%', "%25")
        .replace(' ', "%20")
        .replace('#', "%23")
        .replace('?', "%3F");
    let uri = format!("sqlite:{encoded}?mode=rwc&cache=private");

    let location = SqliteFileLocation::from_uri(&uri).expect("parse durable SQLite URI");
    assert_eq!(location.path(), path);
    assert_eq!(location.root(), tree.path());

    let pool = connect_sqlite_file_with_max(&location, 1)
        .await
        .expect("connect to decoded URI path");
    assert!(
        path.exists(),
        "SQLite and adjacent state must agree on path"
    );
    pool.close().await;
}

#[test]
fn legacy_uri_parser_accepts_sqlx_relative_and_absolute_forms() {
    let _lock = CWD_LOCK.lock().expect("cwd lock");
    let cwd = std::env::current_dir().expect("current directory");
    let relative =
        SqliteFileLocation::from_uri("sqlite:relative.sqlite").expect("parse sqlite:path form");
    assert_eq!(relative.path(), cwd.join("relative.sqlite"));
    assert_eq!(relative.root(), cwd);

    let tree = TempTree::new("absolute-uri");
    let absolute_path = tree.path().join("absolute.sqlite");
    let absolute_uri = format!("sqlite:{}", absolute_path.display());
    let absolute =
        SqliteFileLocation::from_uri(&absolute_uri).expect("parse sqlite:/absolute form");
    assert_eq!(absolute.path(), absolute_path);
    assert_eq!(absolute.root(), tree.path());
}

#[test]
fn legacy_uri_parser_rejects_non_durable_sqlite_semantics() {
    for uri in [
        "sqlite::memory:",
        "sqlite://:memory:",
        "sqlite:%3Amemory%3A",
        "sqlite:",
        "sqlite://",
        "sqlite:?mode=rwc",
        "sqlite://named?mode=memory",
        "sqlite://?mode=memory",
        "sqlite:file:nested.sqlite",
        "sqlite://durable.sqlite?vfs=memdb",
    ] {
        assert!(
            SqliteFileLocation::from_uri(uri).is_err(),
            "{uri} must not be accepted as a durable SQLite file"
        );
    }
    assert!(SqliteFileLocation::from_uri("relative.sqlite").is_err());
}

#[test]
fn resolved_relative_and_uri_like_native_names_stay_literal_after_cwd_change() {
    let _lock = CWD_LOCK.lock().expect("cwd lock");
    let tree = TempTree::new("relative-stability");
    let first = tree.path().join("first");
    let second = tree.path().join("second");
    std::fs::create_dir_all(&first).expect("create first cwd");
    std::fs::create_dir_all(&second).expect("create second cwd");
    let _cwd = CurrentDirGuard::change_to(&first);

    let relative =
        SqliteFileLocation::from_path(Path::new("relative.sqlite")).expect("resolve relative path");
    let memory_name =
        SqliteFileLocation::from_path(Path::new(":memory:")).expect("resolve literal :memory:");
    let file_uri_name = SqliteFileLocation::from_path(Path::new("file:x?mode=memory"))
        .expect("resolve literal file-like name");

    std::env::set_current_dir(&second).expect("mutate cwd after resolution");

    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    runtime.block_on(async {
        for location in [&relative, &memory_name, &file_uri_name] {
            let pool = connect_sqlite_file_with_max(location, 1)
                .await
                .expect("connect to resolved literal path");
            pool.close().await;
        }
    });

    assert_eq!(relative.path(), first.join("relative.sqlite"));
    assert!(first.join("relative.sqlite").exists());
    assert!(first.join(":memory:").exists());
    assert!(first.join("file:x?mode=memory").exists());
    assert!(!second.join("relative.sqlite").exists());
}

#[tokio::test]
async fn existing_database_factory_never_creates_or_accepts_ambiguous_paths() {
    let tree = TempTree::new("existing-invalid");
    let missing = tree.path().join("missing.sqlite");
    assert!(open_existing_sqlite(&missing).await.is_err());
    assert!(!missing.exists(), "missing database must not be created");
    assert!(open_existing_sqlite(Path::new("relative.sqlite"))
        .await
        .is_err());
    assert!(open_existing_sqlite(tree.path()).await.is_err());

    let nested = tree.path().join("nested");
    std::fs::create_dir(&nested).expect("create nested directory");
    let unnormalized = nested.join("..").join("missing.sqlite");
    assert!(open_existing_sqlite(&unnormalized).await.is_err());
}

#[tokio::test]
async fn existing_database_factory_pins_single_pool_and_logical_identity() {
    let tree = TempTree::new("existing-valid");
    let path = tree.path().join("state.sqlite");
    create_migrated_database(&path).await;

    let database = open_existing_sqlite(&path)
        .await
        .expect("open existing migrated database");
    assert_eq!(database.location().path(), path);
    assert_eq!(database.location().root(), tree.path());
    assert_eq!(database.pool().size(), 1);
    database
        .verify_identity()
        .await
        .expect("reverify filesystem and logical identity");
}

#[cfg(unix)]
#[tokio::test]
async fn existing_database_factory_rejects_symlink_components_and_final_symlink() {
    use std::os::unix::fs::symlink;

    let tree = TempTree::new("existing-symlink");
    let real = tree.path().join("real");
    std::fs::create_dir(&real).expect("create real directory");
    let path = real.join("state.sqlite");
    create_migrated_database(&path).await;

    let linked_parent = tree.path().join("linked-parent");
    symlink(&real, &linked_parent).expect("create parent symlink");
    assert!(open_existing_sqlite(&linked_parent.join("state.sqlite"))
        .await
        .is_err());

    let linked_file = tree.path().join("linked.sqlite");
    symlink(&path, &linked_file).expect("create file symlink");
    assert!(open_existing_sqlite(&linked_file).await.is_err());

    let sidecar_target = tree.path().join("sidecar-target");
    std::fs::write(&sidecar_target, b"not a SQLite sidecar").expect("write sidecar target");
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar_database = tree.path().join(format!("sidecar-{}.sqlite", &suffix[1..]));
        create_migrated_database(&sidecar_database).await;
        let mut sidecar = sidecar_database.as_os_str().to_os_string();
        sidecar.push(suffix);
        symlink(&sidecar_target, PathBuf::from(sidecar)).expect("create sidecar symlink");
        assert!(
            open_existing_sqlite(&sidecar_database).await.is_err(),
            "{suffix} symlink must be rejected before WAL mode opens"
        );
    }
}

#[tokio::test]
async fn existing_database_factory_rejects_nonregular_sidecars() {
    let tree = TempTree::new("existing-sidecar-directory");
    let path = tree.path().join("state.sqlite");
    create_migrated_database(&path).await;
    let mut journal = path.as_os_str().to_os_string();
    journal.push("-journal");
    std::fs::create_dir(PathBuf::from(journal)).expect("create nonregular journal sidecar");

    assert!(open_existing_sqlite(&path).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn existing_database_factory_rejects_hardlinks() {
    let tree = TempTree::new("existing-hardlink");
    let path = tree.path().join("state.sqlite");
    create_migrated_database(&path).await;
    let alias = tree.path().join("alias.sqlite");
    std::fs::hard_link(&path, &alias).expect("create hard link");

    assert!(open_existing_sqlite(&path).await.is_err());
    assert!(open_existing_sqlite(&alias).await.is_err());

    let sidecar_database = tree.path().join("sidecar.sqlite");
    create_migrated_database(&sidecar_database).await;
    let sidecar_target = tree.path().join("hardlinked-sidecar-target");
    std::fs::write(&sidecar_target, []).expect("create sidecar target");
    let mut wal = sidecar_database.as_os_str().to_os_string();
    wal.push("-wal");
    std::fs::hard_link(&sidecar_target, PathBuf::from(wal))
        .expect("create hard-linked WAL sidecar");
    assert!(open_existing_sqlite(&sidecar_database).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn existing_database_factory_detects_path_replacement_after_open() {
    let tree = TempTree::new("existing-replacement");
    let path = tree.path().join("state.sqlite");
    create_migrated_database(&path).await;
    let database = open_existing_sqlite(&path)
        .await
        .expect("open existing database");

    let original = tree.path().join("original.sqlite");
    std::fs::rename(&path, &original).expect("move opened database inode");
    std::fs::copy(&original, &path).expect("install exact logical clone at original path");

    assert!(database.verify_identity().await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn existing_database_factory_enforces_private_directory_and_file_modes() {
    use std::os::unix::fs::PermissionsExt;

    let tree = TempTree::new("existing-permissions");
    let path = tree.path().join("state.sqlite");
    create_migrated_database(&path).await;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
        .expect("widen database permissions");
    let database = open_existing_sqlite(&path)
        .await
        .expect("private root permits tightening the database");
    let mode = std::fs::metadata(&path)
        .expect("database metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    drop(database);

    std::fs::set_permissions(tree.path(), std::fs::Permissions::from_mode(0o755))
        .expect("widen state root");
    assert!(open_existing_sqlite(&path).await.is_err());
    std::fs::set_permissions(tree.path(), std::fs::Permissions::from_mode(0o700))
        .expect("restore state root permissions for cleanup");
}
