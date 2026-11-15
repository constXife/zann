use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    version: u32,
    archive_id: [u8; 32],
    chunk_bytes: u32,
    recipients: Vec<RecipientDescriptor>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    nonce: [u8; 12],
    wrapped_dek: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    context: Context,
    slots: Vec<Slot>,
}

pub struct ArchiveHeader {
    header: Header,
    pub(super) bytes: Vec<u8>,
    tag: [u8; 16],
}
impl ArchiveHeader {
    pub fn read(reader: &mut impl Read) -> Result<Self, ArchiveError> {
        let mut magic = [0; 8];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(ArchiveError::new("backup_archive_version"));
        }
        let mut length = [0; 4];
        reader.read_exact(&mut length)?;
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > MAX_HEADER_BYTES {
            return Err(ArchiveError::new("backup_archive_header_limit"));
        }
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes)?;
        let header: Header = serde_json::from_slice(&bytes)?;
        if header.context.version != 1 || header.context.chunk_bytes != CHUNK_BYTES as u32 {
            return Err(ArchiveError::new("backup_archive_version"));
        }
        if header.context.recipients.is_empty()
            || header.context.recipients.len() > MAX_RECIPIENTS
            || header.slots.len() != header.context.recipients.len()
        {
            return Err(ArchiveError::new("backup_recipient_limit"));
        }
        if !header
            .context
            .recipients
            .iter()
            .any(RecipientDescriptor::portable)
        {
            return Err(ArchiveError::new("backup_portable_recipient_required"));
        }
        for (i, descriptor) in header.context.recipients.iter().enumerate() {
            descriptor.validate()?;
            if header.context.recipients[..i].contains(descriptor)
                || header.slots[i].wrapped_dek.len() != 32 + TAG_BYTES
            {
                return Err(ArchiveError::new("backup_recipient_invalid"));
            }
        }
        let mut tag = [0; 16];
        reader.read_exact(&mut tag)?;
        Ok(Self { header, bytes, tag })
    }
    pub fn recipients(&self) -> &[RecipientDescriptor] {
        &self.header.context.recipients
    }
    pub fn unlock(self, key: &RecipientKey) -> Result<UnlockedArchive, ArchiveError> {
        let index = self
            .recipients()
            .iter()
            .position(|d| d == &key.descriptor)
            .ok_or_else(|| ArchiveError::new("backup_recipient_mismatch"))?;
        let slot = &self.header.slots[index];
        let mut aad = serde_json::to_vec(&self.header.context)?;
        aad.extend_from_slice(&(index as u32).to_le_bytes());
        let dek = decrypt(key.key.as_bytes(), &slot.nonce, &slot.wrapped_dek, &aad)?;
        let dek = SecretKey::from_bytes(
            dek.as_slice()
                .try_into()
                .map_err(|_| ArchiveError::new("backup_recipient_invalid"))?,
        );
        let auth = derived(&dek, "zann backup v1 header");
        decrypt(auth.as_bytes(), &[0; 12], &self.tag, &self.bytes)?;
        Ok(UnlockedArchive::new(self, dek))
    }
    pub(super) fn create(keys: &[&RecipientKey]) -> Result<(Self, SecretKey), ArchiveError> {
        if keys.is_empty() || keys.len() > MAX_RECIPIENTS {
            return Err(ArchiveError::new("backup_recipient_limit"));
        }
        if !keys.iter().any(|key| key.descriptor.portable()) {
            return Err(ArchiveError::new("backup_portable_recipient_required"));
        }
        for (i, key) in keys.iter().enumerate() {
            key.descriptor.validate()?;
            if keys[..i].iter().any(|k| k.descriptor == key.descriptor) {
                return Err(ArchiveError::new("backup_recipient_invalid"));
            }
        }
        let context = Context {
            version: 1,
            archive_id: random(),
            chunk_bytes: CHUNK_BYTES as u32,
            recipients: keys.iter().map(|k| k.descriptor.clone()).collect(),
        };
        let dek = SecretKey::from_bytes(random());
        let context_bytes = serde_json::to_vec(&context)?;
        let mut slots = Vec::with_capacity(keys.len());
        for (i, key) in keys.iter().enumerate() {
            let nonce = random();
            let mut aad = context_bytes.clone();
            aad.extend_from_slice(&(i as u32).to_le_bytes());
            let wrapped_dek = encrypt(key.key.as_bytes(), &nonce, dek.as_bytes(), &aad)?;
            let checked = decrypt(key.key.as_bytes(), &nonce, &wrapped_dek, &aad)?;
            if !crate::secret_bytes_equal(&checked, dek.as_bytes()) {
                return Err(ArchiveError::new("backup_wrap_verification"));
            }
            slots.push(Slot { nonce, wrapped_dek });
        }
        let header = Header { context, slots };
        let bytes = serde_json::to_vec(&header)?;
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(ArchiveError::new("backup_archive_header_limit"));
        }
        let auth = derived(&dek, "zann backup v1 header");
        let tag = encrypt(auth.as_bytes(), &[0; 12], &[], &bytes)?
            .try_into()
            .map_err(|_| ArchiveError::new("backup_archive_encrypt"))?;
        Ok((Self { header, bytes, tag }, dek))
    }
    pub(super) fn write(&self, writer: &mut impl Write) -> Result<(), ArchiveError> {
        writer.write_all(MAGIC)?;
        writer.write_all(&(self.bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&self.bytes)?;
        writer.write_all(&self.tag)?;
        Ok(())
    }
}
/// One verified header/DEK lease, reused by each canonical parser pass.
pub struct UnlockedArchive {
    pub(super) header: ArchiveHeader,
    pub(super) key: SecretKey,
    pub(super) fingerprint: [u8; 32],
}
impl UnlockedArchive {
    fn new(header: ArchiveHeader, dek: SecretKey) -> Self {
        let key = derived(&dek, "zann backup v1 payload");
        let fingerprint = *blake3::hash(&header.bytes).as_bytes();
        Self {
            header,
            key,
            fingerprint,
        }
    }
    pub fn reader<R: Read>(
        self: &std::sync::Arc<Self>,
        mut reader: R,
    ) -> Result<ArchiveReader<R>, ArchiveError> {
        let header = ArchiveHeader::read(&mut reader)?;
        if !crate::secret_bytes_equal(&header.bytes, &self.header.bytes)
            || !crate::secret_bytes_equal(&header.tag, &self.header.tag)
        {
            return Err(ArchiveError::new("backup_archive_changed"));
        }
        Ok(ArchiveReader::new(reader, self.clone()))
    }
}
