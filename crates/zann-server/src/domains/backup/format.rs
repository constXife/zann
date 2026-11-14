use super::BackupError;
use chrono::{DateTime, Utc};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;
use zann_crypto::secrets::{EncryptedPayload, FieldValue};

pub(super) const EXPORT_VERSION: u32 = 1;
pub(super) const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;
pub(super) const MAX_VAULTS: usize = 4096;
pub(super) const MAX_ITEMS: usize = 1_000_000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SharedExportVault {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub item_count: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SharedExportItem {
    pub id: String,
    pub path: String,
    pub name: String,
    pub type_id: String,
    #[serde(deserialize_with = "required_optional")]
    pub tags: Option<Vec<String>>,
    pub favorite: bool,
    #[serde(deserialize_with = "payload")]
    pub payload: EncryptedPayload,
    pub checksum: String,
    pub version: i64,
    #[serde(deserialize_with = "required_optional")]
    pub deleted_at: Option<String>,
    pub updated_at: String,
}

fn required_optional<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

pub(super) fn validate_vault(vault: &SharedExportVault) -> Result<Uuid, BackupError> {
    crate::domains::vaults::contract::validate_vault_metadata(&vault.slug, &vault.name)
        .map_err(|e| BackupError::Invalid(e.code()))?;
    uuid(&vault.id)
}

pub(super) fn uuid(text: &str) -> Result<Uuid, BackupError> {
    text.parse::<Uuid>()
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or(BackupError::Invalid("invalid_backup_uuid"))
}

pub(super) fn timestamp(text: &str) -> Result<DateTime<Utc>, BackupError> {
    DateTime::parse_from_rfc3339(text)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| BackupError::Invalid("invalid_backup_timestamp"))
}

pub(super) fn validate_item(item: &SharedExportItem) -> Result<Uuid, BackupError> {
    use crate::domains::items::contract;
    contract::canonical_create_location(&item.path, Some(&item.name))
        .map_err(|e| BackupError::Invalid(e.code()))?;
    contract::validate_server_typed_payload(&item.payload, &item.type_id)
        .map_err(|e| BackupError::Invalid(e.code()))?;
    contract::validate_checksum(&item.checksum).map_err(|e| BackupError::Invalid(e.code()))?;
    if item.version < 1
        || !(zann_core::ItemMetadata {
            tags: item.tags.clone(),
            favorite: item.favorite,
        })
        .validate()
    {
        return Err(BackupError::Invalid("invalid_backup_item_metadata"));
    }
    timestamp(&item.updated_at)?;
    if let Some(deleted) = &item.deleted_at {
        timestamp(deleted)?;
    }
    uuid(&item.id)
}

// Only the map framing differs from the canonical payload: duplicate map keys
// must be refused, never collapsed by HashMap during backup admission.
fn payload<'de, D: Deserializer<'de>>(d: D) -> Result<EncryptedPayload, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        v: u32,
        #[serde(rename = "typeId")]
        type_id: String,
        #[serde(deserialize_with = "unique_map")]
        fields: HashMap<String, FieldValue>,
        #[serde(default, deserialize_with = "optional_unique_map")]
        extra: Option<HashMap<String, String>>,
    }
    let wire = Wire::deserialize(d)?;
    Ok(EncryptedPayload {
        v: wire.v,
        type_id: wire.type_id,
        fields: wire.fields,
        extra: wire.extra,
    })
}

fn optional_unique_map<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<HashMap<String, String>>, D::Error> {
    struct Optional;
    impl<'de> Visitor<'de> for Optional {
        type Value = Option<HashMap<String, String>>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an optional map")
        }
        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            unique_map(d).map(Some)
        }
    }
    d.deserialize_option(Optional)
}

fn unique_map<'de, D: Deserializer<'de>, V: Deserialize<'de>>(
    d: D,
) -> Result<HashMap<String, V>, D::Error> {
    struct Unique<V>(std::marker::PhantomData<V>);
    impl<'de, V: Deserialize<'de>> Visitor<'de> for Unique<V> {
        type Value = HashMap<String, V>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map with unique keys")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut result = HashMap::new();
            while let Some(key) = map.next_key::<String>()? {
                if result.contains_key(&key) {
                    return Err(de::Error::custom("duplicate backup key"));
                }
                result.insert(key, map.next_value()?);
            }
            Ok(result)
        }
    }
    d.deserialize_map(Unique(std::marker::PhantomData))
}
