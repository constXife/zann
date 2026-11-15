use super::*;

/// Dropping without finish leaves an invalid archive. No implicit finalization.
pub struct ArchiveWriter<W: Write> {
    writer: W,
    key: SecretKey,
    fingerprint: [u8; 32],
    buffer: Zeroizing<Vec<u8>>,
    index: u64,
    failed: bool,
}
impl<W: Write> ArchiveWriter<W> {
    pub fn new<'a>(
        mut writer: W,
        recipients: impl IntoIterator<Item = &'a RecipientKey>,
    ) -> Result<Self, ArchiveError> {
        let recipients = recipients
            .into_iter()
            .take(MAX_RECIPIENTS + 1)
            .collect::<Vec<_>>();
        let (header, dek) = ArchiveHeader::create(&recipients)?;
        let fingerprint = *blake3::hash(&header.bytes).as_bytes();
        let key = derived(&dek, "zann backup v1 payload");
        header.write(&mut writer)?;
        Ok(Self {
            writer,
            key,
            fingerprint,
            buffer: Zeroizing::new(Vec::with_capacity(CHUNK_BYTES)),
            index: 0,
            failed: false,
        })
    }
    fn frame(&mut self, final_frame: bool) -> Result<(), ArchiveError> {
        if self.failed {
            return Err(ArchiveError::new("backup_archive_writer_failed"));
        }
        // Burn this writer on every failed attempt: never reuse an AEAD nonce.
        self.failed = true;
        let length = self.buffer.len() as u32;
        let aad = frame_aad(&self.fingerprint, self.index, length, final_frame);
        let ciphertext = encrypt(self.key.as_bytes(), &nonce(self.index), &self.buffer, &aad)?;
        self.writer.write_all(&length.to_le_bytes())?;
        self.writer.write_all(&[u8::from(final_frame)])?;
        self.writer.write_all(&ciphertext)?;
        self.index = self
            .index
            .checked_add(1)
            .ok_or_else(|| ArchiveError::new("backup_archive_frame_limit"))?;
        use zeroize::Zeroize;
        self.buffer.zeroize();
        self.buffer.clear();
        self.failed = false;
        Ok(())
    }
    pub fn finish(mut self) -> Result<W, ArchiveError> {
        if !self.buffer.is_empty() {
            self.frame(false)?;
        }
        self.frame(true)?;
        self.writer.flush()?;
        Ok(self.writer)
    }
}
impl<W: Write> Write for ArchiveWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::other(ArchiveError::new(
                "backup_archive_writer_failed",
            )));
        }
        let count = bytes.len().min(CHUNK_BYTES - self.buffer.len());
        self.buffer.extend_from_slice(&bytes[..count]);
        if self.buffer.len() == CHUNK_BYTES {
            self.frame(false).map_err(io::Error::other)?;
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
