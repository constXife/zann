//! Reopenable authenticated input: canonical parsers never need a plaintext file.
use super::*;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
type Generation = (Arc<AtomicU64>, u64, std::time::Instant);

#[derive(Clone)]
pub struct BackupInput {
    path: PathBuf,
    archive: Option<Arc<zann_crypto::backup::UnlockedArchive>>,
    operation: Option<Arc<zann_client::app::SessionOperation>>,
    generation: Option<Generation>,
}
impl BackupInput {
    pub fn plain(path: PathBuf) -> Self {
        Self {
            path,
            archive: None,
            operation: None,
            generation: None,
        }
    }
    pub fn encrypted(
        path: PathBuf,
        archive: Arc<zann_crypto::backup::UnlockedArchive>,
        operation: Arc<zann_client::app::SessionOperation>,
        generation: Generation,
    ) -> Self {
        Self {
            path,
            archive: Some(archive),
            operation: Some(operation),
            generation: Some(generation),
        }
    }
    pub fn open(&self) -> Result<Box<dyn Read + Send>, anyhow::Error> {
        let file = File::open(&self.path)?;
        let reader: Box<dyn Read + Send> = match &self.archive {
            Some(archive) => Box::new(archive.reader(file)?),
            None => Box::new(file),
        };
        // Bound total decoded size too: compression/recipient framing must not
        // turn a bounded source into an unbounded JSON allocation.
        Ok(Box::new(InputReader {
            reader,
            operation: self.operation.clone(),
            generation: self.generation.clone(),
            remaining: 50 * 1024 * 1024,
        }))
    }
}
struct InputReader {
    reader: Box<dyn Read + Send>,
    operation: Option<Arc<zann_client::app::SessionOperation>>,
    generation: Option<Generation>,
    remaining: u64,
}
impl Read for InputReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self
            .generation
            .as_ref()
            .is_some_and(|(current, expected, expires)| {
                current.load(Ordering::SeqCst) != *expected || std::time::Instant::now() >= *expires
            })
        {
            return Err(std::io::Error::other("backup session changed"));
        }
        if self
            .operation
            .as_ref()
            .is_some_and(|op| op.is_cancelled() || std::time::Instant::now() >= op.deadline())
        {
            return Err(std::io::Error::other(
                "backup operation cancelled or expired",
            ));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut extra = [0];
            return match self.reader.read(&mut extra)? {
                0 => Ok(0),
                _ => Err(std::io::Error::other("backup exceeds 50 MiB")),
            };
        }
        let length = bytes.len().min(self.remaining as usize);
        let read = self.reader.read(&mut bytes[..length])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}
