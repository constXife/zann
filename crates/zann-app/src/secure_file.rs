//! Owner-only file and directory permissions for secret-bearing local state.
//!
//! Server-side policy (`crates/zann-server/SECURITY.md`) requires `0600` for
//! secret files and `0700` for data directories. This module gives the shared
//! clients the same guarantees for their `~/.zann` state.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// Writes a small secret-bearing file atomically with owner-only permissions.
///
/// The contents land in a fresh temp file next to the target, which is flushed,
/// chmod'ed `0600` and renamed over the target, so a crash mid-write can never
/// leave a truncated world-readable file behind.
pub fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
        })?;
        let tmp_path = parent.join(format!(".{}.tmp", uuid::Uuid::now_v7().simple()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;
        let result = (|| {
            file.write_all(contents)?;
            file.sync_all()?;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            Ok(())
        })();
        drop(file);
        match result {
            Ok(()) => fs::rename(&tmp_path, path),
            Err(err) => {
                let _ = fs::remove_file(&tmp_path);
                Err(err)
            }
        }
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents)
    }
}

/// Creates (or truncates) a writable secret-bearing file with owner-only
/// permissions, for callers that stream into it.
pub fn create_private_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Creates (if missing) a data directory and enforces owner-only permissions
/// on it, including when it already exists.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("zann-secure-file-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn write_private_creates_owner_only_file_and_leaves_no_temp() {
        let root = scratch("write");
        let target = root.join("config.json");

        write_private(&target, b"secret").expect("write");

        assert_eq!(mode(&target), 0o600);
        assert_eq!(fs::read_to_string(&target).expect("read"), "secret");
        let leftovers: Vec<_> = fs::read_dir(&root)
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.file_name().is_some_and(|name| name != "config.json"))
            .collect();
        assert!(leftovers.is_empty(), "no temp leftovers: {leftovers:?}");
    }

    #[test]
    fn write_private_replaces_world_readable_existing_file() {
        let root = scratch("replace");
        let target = root.join("config.json");
        fs::write(&target, b"old").expect("seed");
        #[cfg(unix)]
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).expect("loosen");

        write_private(&target, b"new").expect("rewrite");

        assert_eq!(mode(&target), 0o600);
        assert_eq!(fs::read_to_string(&target).expect("read"), "new");
    }

    #[test]
    fn create_private_file_is_owner_only() {
        let root = scratch("create");
        let target = root.join("export.json");

        let file = create_private_file(&target).expect("create");
        drop(file);

        assert_eq!(mode(&target), 0o600);
    }

    #[test]
    fn ensure_private_dir_tightens_existing_directory() {
        let root = scratch("dir");
        let nested = root.join("a").join("b");

        ensure_private_dir(&nested).expect("ensure");

        assert_eq!(mode(&nested), 0o700);
        #[cfg(unix)]
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o755)).expect("loosen");
        ensure_private_dir(&nested).expect("re-ensure");
        assert_eq!(mode(&nested), 0o700);
    }
}
