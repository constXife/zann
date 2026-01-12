use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::instrument;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind {
    Text,
    Password,
    Url,
    Otp,
    Note,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FieldMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiline: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copyable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readonly: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldValue {
    pub kind: FieldKind,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<FieldMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub v: u32,
    #[serde(rename = "typeId")]
    pub type_id: String,
    #[serde(default)]
    pub fields: HashMap<String, FieldValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, String>>,
}

#[derive(Debug)]
pub enum PayloadError {
    InvalidJson(serde_json::Error),
}

impl std::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(err) => write!(f, "invalid json: {err}"),
        }
    }
}

impl std::error::Error for PayloadError {}

impl EncryptedPayload {
    #[must_use]
    pub fn new(type_id: impl Into<String>) -> Self {
        Self {
            v: 1,
            type_id: type_id.into(),
            fields: HashMap::new(),
            extra: None,
        }
    }

    #[instrument(level = "debug", skip(self))]
    pub fn to_bytes(&self) -> Result<Vec<u8>, PayloadError> {
        serde_json::to_vec(self).map_err(PayloadError::InvalidJson)
    }

    #[instrument(level = "debug", skip(bytes), fields(bytes_len = bytes.len()))]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PayloadError> {
        serde_json::from_slice(bytes).map_err(PayloadError::InvalidJson)
    }
}
