//! The `zann-ui-core` item draft as a UniFFI object. Templates, field
//! validation and payload construction stay in `ItemDraft`; the shell edits
//! fields by index and asks for the payload on save.

use std::sync::{Arc, Mutex};

use zann_ui_core::item_editor::{
    field_schemas, DraftError, DraftField, FieldDefinition, FieldKind, ItemDraft,
};

use crate::{CoreError, CoreResult, ItemCreate, ItemDetail, ItemUpdate};

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum FieldKindFfi {
    Text,
    Password,
    Url,
    Otp,
    Note,
}

impl From<FieldKind> for FieldKindFfi {
    fn from(kind: FieldKind) -> Self {
        match kind {
            FieldKind::Text => Self::Text,
            FieldKind::Password => Self::Password,
            FieldKind::Url => Self::Url,
            FieldKind::Otp => Self::Otp,
            FieldKind::Note => Self::Note,
        }
    }
}

impl From<FieldKindFfi> for FieldKind {
    fn from(kind: FieldKindFfi) -> Self {
        match kind {
            FieldKindFfi::Text => Self::Text,
            FieldKindFfi::Password => Self::Password,
            FieldKindFfi::Url => Self::Url,
            FieldKindFfi::Otp => Self::Otp,
            FieldKindFfi::Note => Self::Note,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum DraftErrorKindFfi {
    Payload,
    Path,
    Name,
    Type,
    Fields,
    FieldKey,
    DuplicateKey,
    UnknownType,
}

impl From<DraftError> for CoreError {
    fn from(error: DraftError) -> Self {
        let translation_key = error.translation_key().to_string();
        let message = error.to_string();
        let kind = match error {
            DraftError::Payload(_) => DraftErrorKindFfi::Payload,
            DraftError::Path => DraftErrorKindFfi::Path,
            DraftError::Name => DraftErrorKindFfi::Name,
            DraftError::Type => DraftErrorKindFfi::Type,
            DraftError::Fields => DraftErrorKindFfi::Fields,
            DraftError::FieldKey => DraftErrorKindFfi::FieldKey,
            DraftError::DuplicateKey => DraftErrorKindFfi::DuplicateKey,
            DraftError::UnknownType => DraftErrorKindFfi::UnknownType,
        };
        Self::Draft {
            kind,
            translation_key,
            message,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FieldDefinitionFfi {
    pub key: String,
    pub kind: FieldKindFfi,
    pub label: String,
}

impl From<&FieldDefinition> for FieldDefinitionFfi {
    fn from(definition: &FieldDefinition) -> Self {
        Self {
            key: definition.key.clone(),
            kind: definition.kind.into(),
            label: definition.label.clone(),
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemTypeSchemaFfi {
    pub type_id: String,
    pub main: Vec<FieldDefinitionFfi>,
    pub advanced: Vec<FieldDefinitionFfi>,
}

/// The item types a draft can be created as, with their field templates.
#[uniffi::export]
pub fn item_type_schemas() -> Vec<ItemTypeSchemaFfi> {
    field_schemas()
        .iter()
        .map(|(type_id, schema)| ItemTypeSchemaFfi {
            type_id: type_id.clone(),
            main: schema.main.iter().map(Into::into).collect(),
            advanced: schema.advanced.iter().map(Into::into).collect(),
        })
        .collect()
}

#[derive(Clone, uniffi::Record)]
pub struct DraftFieldFfi {
    pub key: String,
    pub kind: FieldKindFfi,
    pub value: String,
    pub masked: bool,
    pub multiline: bool,
}

impl std::fmt::Debug for DraftFieldFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DraftFieldFfi(<redacted>)")
    }
}

impl From<&DraftField> for DraftFieldFfi {
    fn from(field: &DraftField) -> Self {
        Self {
            key: field.key.clone(),
            kind: field.value.kind.into(),
            value: field.value.value.clone(),
            masked: field.masked(),
            multiline: field.multiline(),
        }
    }
}

#[derive(uniffi::Object)]
pub struct ItemDraftFfi(Mutex<ItemDraft>);

impl ItemDraftFfi {
    fn with_field<T>(&self, index: u64, edit: impl FnOnce(&mut DraftField) -> T) -> CoreResult<T> {
        let mut draft = self.0.lock().expect("lock poisoned");
        usize::try_from(index)
            .ok()
            .and_then(|index| draft.fields.get_mut(index))
            .map(edit)
            .ok_or_else(|| CoreError::InvalidArgument("field index".to_string()))
    }
}

#[uniffi::export]
impl ItemDraftFfi {
    /// A new draft from the type's field template.
    #[uniffi::constructor]
    pub fn create(type_id: String) -> CoreResult<Arc<Self>> {
        Ok(Arc::new(Self(Mutex::new(ItemDraft::create(&type_id)?))))
    }

    /// A draft of an existing item; unknown payload parts survive the save.
    #[uniffi::constructor]
    pub fn edit(detail: ItemDetail) -> CoreResult<Arc<Self>> {
        Ok(Arc::new(Self(Mutex::new(ItemDraft::edit(
            detail.path,
            &detail.payload_json,
        )?))))
    }

    pub fn path(&self) -> String {
        self.0.lock().expect("lock poisoned").path.clone()
    }

    pub fn name(&self) -> String {
        self.0.lock().expect("lock poisoned").name().to_string()
    }

    pub fn folder(&self) -> Option<String> {
        self.0
            .lock()
            .expect("lock poisoned")
            .folder()
            .map(str::to_string)
    }

    pub fn set_location(&self, name: String, folder: String) -> CoreResult<()> {
        Ok(self
            .0
            .lock()
            .expect("lock poisoned")
            .set_location(&name, &folder)?)
    }

    pub fn set_path(&self, path: String) {
        self.0.lock().expect("lock poisoned").path = path;
    }

    pub fn type_id(&self) -> String {
        self.0.lock().expect("lock poisoned").type_id.clone()
    }

    /// Returns whether the untouched template fields were replaced.
    pub fn set_type(&self, type_id: String) -> CoreResult<bool> {
        Ok(self.0.lock().expect("lock poisoned").set_type(type_id)?)
    }

    pub fn fields(&self) -> Vec<DraftFieldFfi> {
        self.0
            .lock()
            .expect("lock poisoned")
            .fields
            .iter()
            .map(Into::into)
            .collect()
    }

    pub fn set_field_key(&self, index: u64, key: String) -> CoreResult<()> {
        self.with_field(index, |field| field.key = key)
    }

    pub fn set_field_value(&self, index: u64, value: String) -> CoreResult<()> {
        self.with_field(index, |field| field.value.value = value)
    }

    pub fn set_field_kind(&self, index: u64, kind: FieldKindFfi) -> CoreResult<()> {
        self.with_field(index, |field| field.value.kind = kind.into())
    }

    pub fn add_field(&self) {
        self.0
            .lock()
            .expect("lock poisoned")
            .fields
            .push(DraftField::blank());
    }

    pub fn remove_field(&self, index: u64) -> CoreResult<()> {
        let mut draft = self.0.lock().expect("lock poisoned");
        let index = usize::try_from(index)
            .ok()
            .filter(|index| *index < draft.fields.len())
            .ok_or_else(|| CoreError::InvalidArgument("field index".to_string()))?;
        draft.fields.remove(index);
        Ok(())
    }

    /// The validated request for `CoreFacade::item_create`.
    pub fn create_request(&self) -> CoreResult<ItemCreate> {
        let save = self.0.lock().expect("lock poisoned").save()?;
        Ok(ItemCreate {
            title: save.title,
            path: save.path,
            type_id: save.type_id,
            payload_json: save.payload_json,
        })
    }

    /// The validated request for `CoreFacade::item_update`.
    pub fn update_request(&self) -> CoreResult<ItemUpdate> {
        let save = self.0.lock().expect("lock poisoned").save()?;
        Ok(ItemUpdate {
            title: save.title,
            path: save.path,
            type_id: save.type_id,
            payload_json: save.payload_json,
        })
    }
}
