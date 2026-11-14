//! Privileged shared-vault recovery. CLI is only an argument/terminal adapter.
mod error;
mod files;
mod format;
mod reader;
mod restore;
mod stream;
#[cfg(test)]
mod tests;

pub use error::BackupError;
pub use restore::import_file;
pub use stream::export;

pub struct ExportOptions {
    pub vaults: Vec<String>,
    pub all_shared: bool,
    pub include_deleted: bool,
    pub output: Option<std::path::PathBuf>,
    pub confirmed: bool,
}

pub struct ImportOptions {
    pub input: std::path::PathBuf,
    pub owner_email: String,
    pub confirmed: bool,
}

#[derive(Debug, Default)]
pub struct ImportReport {
    pub vaults: usize,
    pub items: usize,
}
