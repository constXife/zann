//! Fixtures shared by the `local_vault` integration tests.

use std::ops::Deref;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

/// A temporary client root addressed by its canonical, symlink-free path.
///
/// The SQLite sync store rejects symlinks in the database's parent path, and
/// the platform temp root is one on macOS (`/var` → `/private/var`). The
/// directory is removed when this value is dropped.
pub struct CanonicalTempDir {
    _temp: TempDir,
    canonical: PathBuf,
}

impl CanonicalTempDir {
    pub fn new() -> Self {
        let temp = TempDir::new().expect("temporary client root");
        let canonical =
            std::fs::canonicalize(temp.path()).expect("canonical temporary client root");
        Self {
            _temp: temp,
            canonical,
        }
    }

    pub fn path(&self) -> &Path {
        &self.canonical
    }
}

impl Deref for CanonicalTempDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.canonical
    }
}

impl AsRef<Path> for CanonicalTempDir {
    fn as_ref(&self) -> &Path {
        &self.canonical
    }
}
