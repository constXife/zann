use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use tracing::instrument;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind {
    Text,
    Password,
    Url,
    Otp,
    Note,
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
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

impl fmt::Debug for FieldMeta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FieldMeta(<redacted>)")
    }
}

impl Zeroize for FieldMeta {
    fn zeroize(&mut self) {
        self.masked.zeroize();
        self.multiline.zeroize();
        self.copyable.zeroize();
        self.readonly.zeroize();
        self.placeholder.zeroize();
    }
}

impl Drop for FieldMeta {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for FieldMeta {}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldValue {
    pub kind: FieldKind,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<FieldMeta>,
}

impl fmt::Debug for FieldValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FieldValue")
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .field("meta", &self.meta.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Zeroize for FieldValue {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.meta.zeroize();
    }
}

impl Drop for FieldValue {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for FieldValue {}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedPayload {
    pub v: u32,
    #[serde(rename = "typeId")]
    pub type_id: String,
    #[serde(default)]
    pub fields: HashMap<String, FieldValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, String>>,
}

impl fmt::Debug for EncryptedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedPayload")
            .field("version", &self.v)
            .field("type_id", &"<redacted>")
            .field("field_count", &self.fields.len())
            .field(
                "extra_count",
                &self.extra.as_ref().map(HashMap::len).unwrap_or(0),
            )
            .finish()
    }
}

impl Zeroize for EncryptedPayload {
    fn zeroize(&mut self) {
        self.v.zeroize();
        self.type_id.zeroize();
        for (mut name, mut field) in std::mem::take(&mut self.fields) {
            name.zeroize();
            field.zeroize();
        }
        if let Some(extra) = self.extra.take() {
            for (mut name, mut value) in extra {
                name.zeroize();
                value.zeroize();
            }
        }
    }
}

impl Drop for EncryptedPayload {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for EncryptedPayload {}

pub enum PayloadError {
    InvalidJson(serde_json::Error),
}

impl fmt::Debug for PayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PayloadError::InvalidJson(<redacted>)")
    }
}

impl std::fmt::Display for PayloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(_) => formatter.write_str("invalid payload json"),
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

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "sentinel-secret-value";

    fn secret_payload() -> EncryptedPayload {
        let mut payload = EncryptedPayload::new("sentinel-secret-type");
        payload.fields.insert(
            "sentinel-secret-field".to_string(),
            FieldValue {
                kind: FieldKind::Password,
                value: SENTINEL.to_string(),
                meta: Some(FieldMeta {
                    placeholder: Some("sentinel-secret-placeholder".to_string()),
                    ..FieldMeta::default()
                }),
            },
        );
        payload.extra = Some(HashMap::from([(
            "sentinel-secret-extra-key".to_string(),
            "sentinel-secret-extra-value".to_string(),
        )]));
        payload
    }

    #[test]
    fn payload_debug_redacts_every_sensitive_string() {
        let payload = secret_payload();
        let rendered = format!(
            "{payload:?} {:?} {:?}",
            payload.fields["sentinel-secret-field"], payload.fields["sentinel-secret-field"].meta
        );
        for sentinel in [
            SENTINEL,
            "sentinel-secret-type",
            "sentinel-secret-field",
            "sentinel-secret-placeholder",
            "sentinel-secret-extra-key",
            "sentinel-secret-extra-value",
        ] {
            assert!(!rendered.contains(sentinel));
        }
    }

    #[test]
    fn payload_graph_zeroize_wipes_keys_values_and_metadata() {
        let mut payload = secret_payload();
        payload.zeroize();
        assert_eq!(payload.v, 0);
        assert!(payload.type_id.is_empty());
        assert!(payload.fields.is_empty());
        assert!(payload.extra.is_none());
    }

    #[test]
    fn payload_errors_are_redacted() {
        let input = format!(r#"{{"{SENTINEL}":"unterminated""#);
        let error = EncryptedPayload::from_bytes(input.as_bytes()).expect_err("invalid JSON");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(SENTINEL));
        assert_eq!(
            rendered,
            "PayloadError::InvalidJson(<redacted>) invalid payload json"
        );
    }

    #[test]
    fn typed_payload_rejects_unknown_fields_without_rendering_them() {
        let bytes = br#"{
            "v": 1,
            "typeId": "login",
            "fields": {},
            "sentinel-secret-unknown": "sentinel-secret-value"
        }"#;
        let error = EncryptedPayload::from_bytes(bytes).expect_err("unknown payload member");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("sentinel-secret"));
    }
}
