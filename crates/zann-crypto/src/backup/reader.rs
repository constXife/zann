use super::*;

pub struct ArchiveReader<R: Read> {
    reader: R,
    archive: std::sync::Arc<UnlockedArchive>,
    buffer: Zeroizing<Vec<u8>>,
    position: usize,
    index: u64,
    finished: bool,
    failed: bool,
}
impl<R: Read> ArchiveReader<R> {
    pub(super) fn new(reader: R, archive: std::sync::Arc<UnlockedArchive>) -> Self {
        Self {
            reader,
            archive,
            buffer: Zeroizing::new(Vec::new()),
            position: 0,
            index: 0,
            finished: false,
            failed: false,
        }
    }
    fn frame(&mut self) -> Result<(), ArchiveError> {
        let mut length = [0; 4];
        self.reader.read_exact(&mut length)?;
        let length = u32::from_le_bytes(length);
        let mut flag = [0];
        self.reader.read_exact(&mut flag)?;
        if length as usize > CHUNK_BYTES
            || flag[0] > 1
            || (flag[0] == 1 && length != 0)
            || (flag[0] == 0 && length == 0)
        {
            return Err(ArchiveError::new("backup_archive_frame_invalid"));
        }
        let mut ciphertext = vec![0; length as usize + TAG_BYTES];
        self.reader.read_exact(&mut ciphertext)?;
        let aad = frame_aad(&self.archive.fingerprint, self.index, length, flag[0] == 1);
        self.buffer = decrypt(
            self.archive.key.as_bytes(),
            &nonce(self.index),
            &ciphertext,
            &aad,
        )?;
        self.position = 0;
        self.index = self
            .index
            .checked_add(1)
            .ok_or_else(|| ArchiveError::new("backup_archive_frame_limit"))?;
        if flag[0] == 1 {
            let mut trailing = [0];
            if self.reader.read(&mut trailing)? != 0 {
                return Err(ArchiveError::new("backup_archive_trailing_data"));
            }
            self.finished = true;
        }
        Ok(())
    }
}
impl<R: Read> Read for ArchiveReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(io::Error::other(ArchiveError::new(
                "backup_archive_reader_failed",
            )));
        }
        if self.position == self.buffer.len() && !self.finished {
            if let Err(error) = self.frame() {
                self.failed = true;
                return Err(io::Error::other(error));
            }
        }
        let count = output.len().min(self.buffer.len() - self.position);
        output[..count].copy_from_slice(&self.buffer[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}
