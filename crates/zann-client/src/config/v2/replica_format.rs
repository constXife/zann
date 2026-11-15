//! Read-only structural cutover probe; never constructs or writes a dynamic Config.
use super::*;

#[derive(Clone, Copy)]
enum Context {
    Other,
    Metadata,
    Contexts,
    LegacyConnection,
}
struct ReplicaProbe(Context);
impl<'de> DeserializeSeed<'de> for ReplicaProbe {
    type Value = bool;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for ReplicaProbe {
    type Value = bool;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON configuration structure")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        let mut old = false;
        while let Some(key) = map.next_key::<String>()? {
            if matches!(self.0, Context::Metadata | Context::LegacyConnection)
                && matches!(key.as_str(), "storage_id" | "expected_master_key_fp")
            {
                old = true;
            }
            let context = match (self.0, key.as_str()) {
                (Context::Contexts, _) => Context::LegacyConnection,
                (_, "metadata") => Context::Metadata,
                (_, "contexts") => Context::Contexts,
                _ => Context::Other,
            };
            old |= map.next_value_seed(ReplicaProbe(context))?;
        }
        Ok(old)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<bool, A::Error> {
        let mut old = false;
        while let Some(found) = sequence.next_element_seed(ReplicaProbe(Context::Other))? {
            old |= found;
        }
        Ok(old)
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_unit<E: de::Error>(self) -> Result<bool, E> {
        Ok(false)
    }
}

pub(super) fn reject_connection_replica_fields(
    path: &Path,
    bytes: &[u8],
) -> Result<(), ConfigError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let old = ReplicaProbe(Context::Other)
        .deserialize(&mut deserializer)
        .map_err(|source| ConfigError::Malformed {
            path: path.to_path_buf(),
            source,
        })?;
    deserializer
        .end()
        .map_err(|source| ConfigError::Malformed {
            path: path.to_path_buf(),
            source,
        })?;
    if old {
        return Err(ConfigError::InvalidConfig { path: "$.connections.*.metadata".into(), reason: "pre-profile replica configuration: export all accounts with the previous build, then connect/import into a fresh client root; original files are unchanged".into() });
    }
    Ok(())
}
