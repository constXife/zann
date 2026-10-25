use super::*;

/// Identifies one local projection of one remote vault.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SyncScope {
    pub(super) storage_id: Uuid,
    pub(super) vault_id: Uuid,
}

impl SyncScope {
    pub fn new(storage_id: Uuid, vault_id: Uuid) -> Result<Self, SyncModelError> {
        if storage_id.is_nil() || vault_id.is_nil() {
            return Err(SyncModelError::InvalidIdentifier);
        }
        Ok(Self {
            storage_id,
            vault_id,
        })
    }

    #[must_use]
    pub fn storage_id(&self) -> Uuid {
        self.storage_id
    }

    #[must_use]
    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }
}

/// The only server-side vault/encryption pairings understood by clean sync.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultPlane {
    PersonalClient,
    SharedServer,
}

/// Provenance required for history received from the authoritative server.
///
/// Adapters map this to their local `Server` source and `Confirmed` status.
/// Local/UI, pending, rejected, and conflict history is outside this authority
/// and must not be deleted while applying a pull page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryAuthority {
    ServerConfirmed,
}

/// An opaque, bounded server cursor.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SyncCursor {
    pub(super) encoded: String,
    pub(super) sequence: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CursorPayload {
    pub(super) seq: i64,
}

impl SyncCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, SyncModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES {
            return Err(SyncModelError::InvalidCursor);
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value.as_bytes())
            .map_err(|_| SyncModelError::InvalidCursor)?;
        if decoded.len() > 64 || base64::engine::general_purpose::STANDARD.encode(&decoded) != value
        {
            return Err(SyncModelError::InvalidCursor);
        }
        let payload: CursorPayload =
            serde_json::from_slice(&decoded).map_err(|_| SyncModelError::InvalidCursor)?;
        if payload.seq < 0 {
            return Err(SyncModelError::InvalidCursor);
        }
        Ok(Self {
            encoded: value,
            sequence: payload.seq,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    #[must_use]
    pub fn sequence(&self) -> i64 {
        self.sequence
    }
}

impl fmt::Debug for SyncCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncCursor")
            .field("bytes", &self.encoded.len())
            .finish()
    }
}

/// A positive server sequence number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SyncSeq(pub(super) i64);

impl SyncSeq {
    pub fn new(value: i64) -> Result<Self, SyncModelError> {
        if value < 1 {
            return Err(SyncModelError::InvalidSequence);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn get(self) -> i64 {
        self.0
    }
}

/// A canonical BLAKE3 digest: exactly 32 bytes / 64 lowercase hex characters.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ContentChecksum(pub(super) [u8; 32]);

impl ContentChecksum {
    pub fn parse(value: &str) -> Result<Self, SyncModelError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(SyncModelError::InvalidChecksum);
        }
        let mut bytes = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(chunk[0]).ok_or(SyncModelError::InvalidChecksum)?;
            let low = hex_nibble(chunk[1]).ok_or(SyncModelError::InvalidChecksum)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    pub(crate) fn for_ciphertext(ciphertext: &[u8]) -> Result<Self, SyncModelError> {
        let encoded = zann_crypto::payload_checksum(ciphertext);
        Self::parse(&encoded)
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            use fmt::Write as _;
            let _ = write!(&mut output, "{byte:02x}");
        }
        output
    }
}

impl fmt::Debug for ContentChecksum {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContentChecksum(<redacted>)")
    }
}

pub(super) fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
