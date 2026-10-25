use super::*;

pub(super) fn read_file(path: &Path, operation: &'static str) -> Result<Vec<u8>, ConfigError> {
    validate_regular_file_if_exists(path)?;
    let file = File::open(path).map_err(|source| ConfigError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| ConfigError::Io {
        operation: "inspect open config file",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(ConfigError::UnsafePath {
            path: path.to_path_buf(),
            reason: "opened path is not a regular file".to_string(),
        });
    }
    let limit = json_size_limit(path);
    if metadata.len() > limit {
        return Err(ConfigError::ConfigTooLarge {
            path: path.to_path_buf(),
            max_bytes: limit,
        });
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ConfigError::Io {
            operation,
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        bytes.zeroize();
        return Err(ConfigError::ConfigTooLarge {
            path: path.to_path_buf(),
            max_bytes: limit,
        });
    }
    Ok(bytes)
}

pub(super) fn json_size_limit(path: &Path) -> u64 {
    match path.file_name().and_then(|name| name.to_str()) {
        Some(CONFIG_RESTORE_JOURNAL_FILENAME) => RESTORE_JOURNAL_MAX_BYTES,
        Some(CREDENTIAL_TRANSACTION_JOURNAL_FILENAME) => CREDENTIAL_TRANSACTION_JOURNAL_MAX_BYTES,
        Some(AUTH_OPERATION_INTENT_FILENAME) => AUTH_OPERATION_INTENT_MAX_BYTES,
        _ => CONFIG_MAX_BYTES,
    }
}

#[derive(Clone)]
pub(super) struct DuplicateFreeJson {
    pub(super) nodes: Rc<Cell<usize>>,
    pub(super) max_nodes: usize,
}

impl DuplicateFreeJson {
    pub(super) fn new(max_nodes: usize) -> Self {
        Self {
            nodes: Rc::new(Cell::new(0)),
            max_nodes,
        }
    }

    pub(super) fn consume<E: de::Error>(&self) -> Result<(), E> {
        let next = self.nodes.get().checked_add(1).ok_or_else(|| {
            de::Error::custom("JSON node/member budget exceeds addressable range")
        })?;
        if next > self.max_nodes {
            return Err(de::Error::custom("JSON node/member budget exceeded"));
        }
        self.nodes.set(next);
        Ok(())
    }
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ZeroizingJsonKey(pub(super) String);

impl Drop for ZeroizingJsonKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> DeserializeSeed<'de> for DuplicateFreeJson {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.consume()?;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DuplicateFreeJson {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("valid JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E> {
        value.zeroize();
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(self.clone())?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            self.consume()?;
            if !seen.insert(ZeroizingJsonKey(key)) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            map.next_value_seed(self.clone())?;
        }
        Ok(())
    }
}

pub(super) fn validate_json_shape(bytes: &[u8], max_nodes: usize) -> Result<(), serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateFreeJson::new(max_nodes).deserialize(&mut deserializer)?;
    deserializer.end()
}

pub(super) fn parse_config(path: &Path, bytes: &[u8]) -> Result<ConfigV2, ConfigError> {
    validate_json_shape(bytes, JSON_NODE_LIMIT).map_err(|source| ConfigError::Malformed {
        path: path.to_path_buf(),
        source,
    })?;
    let probe: ConfigVersionProbe =
        serde_json::from_slice(bytes).map_err(|source| ConfigError::Malformed {
            path: path.to_path_buf(),
            source,
        })?;
    let version = probe
        .schema_version
        .ok_or_else(|| ConfigError::MissingSchemaVersion {
            path: path.to_path_buf(),
        })?;
    if version > u64::from(CONFIG_SCHEMA_VERSION) {
        return Err(ConfigError::FutureSchema {
            found: version,
            supported: CONFIG_SCHEMA_VERSION,
        });
    }
    if version != u64::from(CONFIG_SCHEMA_VERSION) {
        return Err(ConfigError::UnsupportedSchema {
            found: version,
            supported: CONFIG_SCHEMA_VERSION,
        });
    }
    let config: ConfigV2 =
        serde_json::from_slice(bytes).map_err(|source| ConfigError::Malformed {
            path: path.to_path_buf(),
            source,
        })?;
    validate_config(&config)?;
    if let Some(repository_root) = path.parent() {
        validate_repository_credential_ids(&config, repository_root)?;
    }
    Ok(config)
}

pub(super) struct LimitedBuffer {
    pub(super) bytes: Vec<u8>,
    pub(super) limit: usize,
    pub(super) exceeded: bool,
}

impl LimitedBuffer {
    pub(super) fn new(limit: u64) -> Self {
        Self {
            bytes: Vec::new(),
            limit: limit as usize,
            exceeded: false,
        }
    }

    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for LimitedBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(next_len) = self.bytes.len().checked_add(buffer.len()) else {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized JSON exceeds configured limit",
            ));
        };
        if next_len > self.limit {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized JSON exceeds configured limit",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn serialize_bounded<T: Serialize>(
    value: &T,
    limit: u64,
    logical_path: &str,
) -> Result<Vec<u8>, ConfigError> {
    let mut output = LimitedBuffer::new(limit);
    if let Err(source) = serde_json::to_writer_pretty(&mut output, value) {
        if output.exceeded {
            return Err(ConfigError::ConfigTooLarge {
                path: PathBuf::from(logical_path),
                max_bytes: limit,
            });
        }
        return Err(ConfigError::Serialization(source));
    }
    if output.write_all(b"\n").is_err() {
        return Err(ConfigError::ConfigTooLarge {
            path: PathBuf::from(logical_path),
            max_bytes: limit,
        });
    }
    Ok(output.finish())
}

pub(super) fn serialize_config(config: &ConfigV2) -> Result<Vec<u8>, ConfigError> {
    validate_config(config)?;
    serialize_bounded(config, CONFIG_MAX_BYTES, CONFIG_V2_FILENAME)
}
