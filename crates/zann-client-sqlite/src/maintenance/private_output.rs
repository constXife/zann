//! A fresh 0600 sibling is published only after the complete stream is synced.
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

pub(crate) struct PrivateOutput {
    file: Option<File>,
    temporary: PathBuf,
    target: PathBuf,
    published: bool,
}

impl PrivateOutput {
    pub(crate) fn create(target: &Path) -> io::Result<Self> {
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| io::Error::other("export destination requires a parent directory"))?;
        let mut directories = fs::DirBuilder::new();
        directories.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directories.mode(0o700);
        }
        directories.create(parent)?;
        let temporary = parent.join(format!(".zann-export-{}.tmp", uuid::Uuid::now_v7()));
        let file = super::secure_file::create_new_private_file(&temporary)?;
        Ok(Self {
            file: Some(file),
            temporary,
            target: target.to_owned(),
            published: false,
        })
    }

    /// Sync and close before acquiring the short final authorization lease.
    pub(crate) fn seal(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.take() {
            file.sync_all()?;
        }
        Ok(())
    }

    pub(crate) fn publish(mut self) -> io::Result<()> {
        if self.file.is_some() {
            return Err(io::Error::other("export output is not sealed"));
        }
        fs::rename(&self.temporary, &self.target)?;
        self.published = true;
        #[cfg(unix)]
        File::open(self.target.parent().expect("validated parent"))?.sync_all()?;
        Ok(())
    }
}

impl Write for PrivateOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("export output is sealed"))?
            .write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("export output is sealed"))?
            .flush()
    }
}

impl Drop for PrivateOutput {
    fn drop(&mut self) {
        self.file.take();
        if !self.published {
            let _ = fs::remove_file(&self.temporary);
        }
    }
}
