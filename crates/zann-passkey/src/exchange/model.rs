use super::*;
use zann_core::{EncryptedPayload, FieldKind, FieldValue};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct LoginMetadata {
    pub username: Option<String>,
    pub password: Option<String>,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct ExchangeMetadata {
    pub v: u8,
    pub title: Option<String>,
    pub login: Option<LoginMetadata>,
    pub urls: Vec<String>,
    pub note: Option<String>,
}
impl ExchangeMetadata {
    pub fn empty() -> Self {
        Self {
            v: 1,
            title: None,
            login: None,
            urls: Vec::new(),
            note: None,
        }
    }
    pub fn validate(&self) -> Result<(), ExchangeError> {
        if self.v != 1 || self.urls.len() > 32 {
            return Err(ExchangeError::new("passkey_metadata_invalid"));
        }
        for value in self
            .title
            .iter()
            .chain(self.note.iter())
            .chain(self.urls.iter())
        {
            json::bounded_text(value, MAX_SECRET_BYTES)?;
        }
        if let Some(login) = &self.login {
            for value in login.username.iter().chain(login.password.iter()) {
                json::bounded_text(value, MAX_SECRET_BYTES)?;
            }
        }
        Ok(())
    }
    fn has_data(&self) -> bool {
        self.title.is_some() || self.login.is_some() || !self.urls.is_empty() || self.note.is_some()
    }
    pub fn from_payload(payload: &EncryptedPayload) -> Result<Self, PasskeyError> {
        let Some(field) = payload.fields.get(EXCHANGE_METADATA_FIELD) else {
            return Ok(Self::empty());
        };
        if field.kind != FieldKind::Password
            || field.meta.is_some()
            || field.value.len() > MAX_SECRET_BYTES
        {
            return Err(PasskeyError::Payload);
        }
        zann_core::bounded_json::validate_json_shape(field.value.as_bytes(), 1024)
            .map_err(|error| PasskeyError::Metadata(error.into()))?;
        let metadata: Self = serde_json::from_str(&field.value)
            .map_err(|error| PasskeyError::Metadata(error.into()))?;
        metadata.validate().map_err(|_| PasskeyError::Payload)?;
        Ok(metadata)
    }
    pub fn attach(&self, payload: &mut EncryptedPayload) -> Result<(), ExchangeError> {
        self.validate()?;
        if self.has_data() {
            let mut encoded = Zeroizing::new(serde_json::to_string(self)?);
            if encoded.len() > MAX_SECRET_BYTES {
                return Err(ExchangeError::new("passkey_metadata_limit"));
            }
            payload.fields.insert(
                EXCHANGE_METADATA_FIELD.into(),
                FieldValue {
                    kind: FieldKind::Password,
                    value: std::mem::take(&mut *encoded),
                    meta: None,
                },
            );
        }
        Ok(())
    }
}

pub struct ExchangeEntry {
    pub id: Vec<u8>,
    pub title: String,
    pub credentials: Vec<Credential>,
    pub metadata: ExchangeMetadata,
    pub favorite: bool,
    pub tags: Vec<String>,
}
impl ExchangeEntry {
    pub fn payload(&self, index: usize) -> Result<EncryptedPayload, ExchangeError> {
        let credential = self
            .credentials
            .get(index)
            .ok_or_else(|| ExchangeError::new("passkey_credential_missing"))?;
        let mut payload = credential.to_payload()?;
        self.metadata.attach(&mut payload)?;
        Ok(payload)
    }
}
pub struct ExchangeDocument {
    pub entries: Vec<ExchangeEntry>,
    pub ignored_records: u64,
}
impl ExchangeDocument {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            ignored_records: 0,
        }
    }
    pub fn credential_count(&self) -> usize {
        self.entries.iter().map(|e| e.credentials.len()).sum()
    }
    pub(super) fn validate(&self) -> Result<(), ExchangeError> {
        if self.credential_count() > MAX_EXCHANGE_ENTRIES
            || self.entries.len() > MAX_EXCHANGE_ENTRIES
        {
            return Err(ExchangeError::new("passkey_exchange_limit"));
        }
        let mut identities = std::collections::BTreeSet::new();
        let mut entry_ids = std::collections::BTreeSet::new();
        let mut total = 0usize;
        for entry in &self.entries {
            if !entry_ids.insert(&entry.id) {
                return Err(ExchangeError::new("passkey_duplicate_item"));
            }
            if entry.id.is_empty() || entry.id.len() > 64 || entry.tags.len() > 32 {
                return Err(ExchangeError::new("passkey_metadata_invalid"));
            }
            json::bounded_text(&entry.title, 1024)?;
            for tag in &entry.tags {
                json::bounded_text(tag, 128)?;
            }
            for (index, credential) in entry.credentials.iter().enumerate() {
                credential.validate()?;
                if !identities.insert(credential.identity()) {
                    return Err(ExchangeError::new("passkey_duplicate_credential"));
                }
                let mut counter = ByteCount { length: 0 };
                serde_json::to_writer(&mut counter, &entry.payload(index)?)?;
                total = total
                    .checked_add(counter.length)
                    .ok_or_else(|| ExchangeError::new("passkey_exchange_limit"))?;
                if total > MAX_EXCHANGE_BYTES {
                    return Err(ExchangeError::new("passkey_exchange_limit"));
                }
            }
        }
        Ok(())
    }
}
impl Default for ExchangeDocument {
    fn default() -> Self {
        Self::new()
    }
}

struct ByteCount {
    length: usize,
}
impl Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.length = self
            .length
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("passkey exchange limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
