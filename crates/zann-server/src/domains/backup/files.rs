use super::BackupError;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub(super) fn open_private(path: &Path) -> Result<File, BackupError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.permissions().mode() & 0o077 != 0 {
        return Err(BackupError::Invalid("backup_requires_private_regular_file"));
    }
    Ok(file)
}

pub(super) fn output(path: Option<&Path>) -> Result<tempfile::NamedTempFile, BackupError> {
    match path {
        Some(path) => Ok(tempfile::NamedTempFile::new_in(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?),
        None => Ok(tempfile::NamedTempFile::new()?),
    }
}
