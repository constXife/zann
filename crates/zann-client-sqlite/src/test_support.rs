//! Fixtures shared by this crate's unit tests.

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

/// A temporary directory pinned to its canonical, symlink-free absolute
/// path so SQLite location validation observes the real filesystem
/// identity even when the platform temp root contains symlinks
/// (`/var` → `/private/var` on macOS).
pub(crate) struct CanonicalTempDir {
    _temp: TempDir,
    canonical: PathBuf,
}

impl CanonicalTempDir {
    pub(crate) fn new(context: &str) -> Self {
        let temp = TempDir::new().expect(context);
        let canonical = fs::canonicalize(temp.path()).expect("canonical temporary directory");
        Self {
            _temp: temp,
            canonical,
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.canonical
    }
}
