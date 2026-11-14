//! Toolkit-neutral item draft policy. Payloads use the canonical domain schema;
//! field templates are the same data consumed by the desktop frontend.
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;
pub use zann_core::secrets::FieldKind;
use zann_core::secrets::{EncryptedPayload, FieldValue, PayloadError};

mod autofill;
pub use autofill::{MatchMode, MatchRules, MATCH_RULES_KEY};

#[derive(Deserialize)]
pub struct FieldDefinition {
    pub key: String,
    #[serde(rename = "type", deserialize_with = "decode_kind")]
    pub kind: FieldKind,
    pub label: String,
}
#[derive(Deserialize)]
pub struct FieldSchema {
    pub main: Vec<FieldDefinition>,
    pub advanced: Vec<FieldDefinition>,
}
fn decode_kind<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<FieldKind, D::Error> {
    let name = String::deserialize(decoder)?;
    let name = if name == "secret" { "password" } else { &name };
    serde_json::from_value(serde_json::Value::String(name.into())).map_err(serde::de::Error::custom)
}
pub fn field_schemas() -> &'static BTreeMap<String, FieldSchema> {
    static SCHEMAS: OnceLock<BTreeMap<String, FieldSchema>> = OnceLock::new();
    SCHEMAS.get_or_init(|| {
        serde_json::from_str(include_str!("../../../schemas/item_fields.json"))
            .expect("embedded item field schema must validate")
    })
}

#[derive(Clone)]
pub struct DraftField {
    pub key: String,
    pub value: FieldValue,
}
impl DraftField {
    pub fn blank() -> Self {
        Self {
            key: String::new(),
            value: FieldValue {
                kind: FieldKind::Text,
                value: String::new(),
                meta: None,
            },
        }
    }
    pub fn multiline(&self) -> bool {
        self.value
            .meta
            .as_ref()
            .and_then(|meta| meta.multiline)
            .unwrap_or(self.value.kind == FieldKind::Note)
    }
    pub fn masked(&self) -> bool {
        self.value
            .meta
            .as_ref()
            .and_then(|meta| meta.masked)
            .unwrap_or(matches!(
                self.value.kind,
                FieldKind::Password | FieldKind::Otp
            ))
    }
}
impl std::fmt::Debug for DraftField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DraftField(<redacted>)")
    }
}

pub struct ItemDraft {
    pub path: String,
    pub type_id: String,
    pub fields: Vec<DraftField>,
    payload: EncryptedPayload,
}
impl std::fmt::Debug for ItemDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemDraft(<redacted>)")
    }
}
/// What saving a draft writes: the trimmed path, the title taken from its
/// last non-empty segment, the type and the validated canonical payload.
pub struct ItemSave {
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub payload_json: String,
}
impl std::fmt::Debug for ItemSave {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemSave(<redacted>)")
    }
}
#[derive(Debug, thiserror::Error)]
pub enum DraftError {
    #[error("invalid login match rules: {0}")]
    Autofill(#[source] zann_autofill::AutofillError),
    #[error("invalid item payload: {0}")]
    Payload(#[source] PayloadError),
    #[error("item path is required")]
    Path,
    #[error("item name must be non-empty and contain no slash")]
    Name,
    #[error("item type is required")]
    Type,
    #[error("at least one field is required")]
    Fields,
    #[error("field key is invalid")]
    FieldKey,
    #[error("field keys must be unique")]
    DuplicateKey,
    #[error("unknown item type has no creation template")]
    UnknownType,
}
impl DraftError {
    pub fn translation_key(&self) -> &'static str {
        match self {
            Self::Autofill(_) => "errors.match_rules_invalid",
            Self::Path => "errors.path_invalid",
            Self::Name => "errors.item_name_invalid",
            Self::Fields => "errors.fields_required",
            Self::FieldKey => "errors.field_key_invalid",
            Self::DuplicateKey => "errors.field_key_duplicate",
            Self::Type | Self::UnknownType | Self::Payload(_) => "errors.invalid_payload",
        }
    }
}
fn template_fields(type_id: &str) -> Result<Vec<DraftField>, DraftError> {
    let schema = field_schemas()
        .get(type_id)
        .ok_or(DraftError::UnknownType)?;
    let fields: Vec<_> = schema
        .main
        .iter()
        .map(|field| DraftField {
            key: field.key.clone(),
            value: FieldValue {
                kind: field.kind,
                value: String::new(),
                meta: None,
            },
        })
        .collect();
    Ok(if fields.is_empty() {
        vec![DraftField::blank()]
    } else {
        fields
    })
}
impl ItemDraft {
    /// The editable name, separate from the folder containing the item.
    pub fn name(&self) -> &str {
        self.path
            .rsplit('/')
            .find(|segment| !segment.trim().is_empty())
            .unwrap_or(&self.path)
            .trim()
    }

    pub fn folder(&self) -> Option<&str> {
        crate::folder_of(
            self.path
                .trim()
                .trim_end_matches(|c: char| c == '/' || c.is_whitespace()),
        )
    }

    /// Applies the two location inputs atomically; a name cannot move an item
    /// into another folder or disappear into the folder's final segment.
    pub fn set_location(&mut self, name: &str, folder: &str) -> Result<(), DraftError> {
        let name = name.trim();
        if name.is_empty() || name.contains('/') {
            return Err(DraftError::Name);
        }
        let folder = folder.trim().trim_end_matches('/');
        self.path = if folder.is_empty() {
            name.to_string()
        } else {
            format!("{folder}/{name}")
        };
        Ok(())
    }

    pub fn create(type_id: &str) -> Result<Self, DraftError> {
        Ok(Self {
            path: String::new(),
            type_id: type_id.into(),
            fields: template_fields(type_id)?,
            payload: EncryptedPayload::new(type_id),
        })
    }
    pub fn edit(path: String, payload_json: &str) -> Result<Self, DraftError> {
        let payload =
            EncryptedPayload::from_bytes(payload_json.as_bytes()).map_err(DraftError::Payload)?;
        let mut fields: Vec<_> = payload
            .fields
            .iter()
            .map(|(key, value)| DraftField {
                key: key.clone(),
                value: value.clone(),
            })
            .collect();
        fields.sort_by(|a, b| crate::item_detail::compare_field_keys(&a.key, &b.key));
        let draft = Self {
            path,
            type_id: payload.type_id.clone(),
            fields,
            payload,
        };
        draft.validate_match_rules()?;
        Ok(draft)
    }
    /// Changing an untouched template may replace its empty fields. Populated
    /// drafts retain every value; unknown existing types may still be edited.
    pub fn set_type(&mut self, type_id: String) -> Result<bool, DraftError> {
        let replace = self
            .fields
            .iter()
            .all(|field| field.key.trim().is_empty() || field.value.value.is_empty());
        if self.type_id == type_id {
            return Ok(false);
        }
        let fields = if replace {
            Some(template_fields(&type_id)?)
        } else {
            None
        };
        self.type_id = type_id;
        if let Some(fields) = fields {
            self.fields = fields;
        }
        Ok(replace)
    }
    pub fn save(&self) -> Result<ItemSave, DraftError> {
        let payload_json = self.payload_json()?;
        let path = self.path.trim();
        Ok(ItemSave {
            title: self.name().to_string(),
            path: path.to_string(),
            type_id: self.type_id.clone(),
            payload_json,
        })
    }
    pub fn payload_json(&self) -> Result<String, DraftError> {
        self.validate_match_rules()?;
        if self.path.trim().is_empty() {
            return Err(DraftError::Path);
        }
        if self.type_id.trim().is_empty() {
            return Err(DraftError::Type);
        }
        if self.fields.is_empty() {
            return Err(DraftError::Fields);
        }
        let mut seen = HashSet::new();
        let mut fields = HashMap::new();
        for field in &self.fields {
            let key = field.key.trim();
            if key.is_empty()
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            {
                return Err(DraftError::FieldKey);
            }
            if !seen.insert(key) {
                return Err(DraftError::DuplicateKey);
            }
            fields.insert(key.into(), field.value.clone());
        }
        let mut payload = self.payload.clone();
        payload.type_id = self.type_id.clone();
        payload.fields = fields;
        let bytes = payload.to_bytes().map_err(DraftError::Payload)?;
        Ok(String::from_utf8(bytes).expect("JSON serialization produces UTF-8"))
    }
}
