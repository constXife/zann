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
        Some(ACCOUNT_REQUESTS_FILENAME) => ACCOUNT_REQUESTS_MAX_BYTES,
        Some(CONFIG_RESTORE_JOURNAL_FILENAME) => RESTORE_JOURNAL_MAX_BYTES,
        Some(CREDENTIAL_TRANSACTION_JOURNAL_FILENAME) => CREDENTIAL_TRANSACTION_JOURNAL_MAX_BYTES,
        Some(AUTH_OPERATION_INTENT_FILENAME) | Some(AUTH_RECOVERY_INTENTS_FILENAME) => {
            AUTH_OPERATION_INTENT_MAX_BYTES
        }
        _ => CONFIG_MAX_BYTES,
    }
}

pub(super) use zann_core::bounded_json::validate_json_shape;

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
    if probe.identity.is_some() {
        return Err(ConfigError::InvalidConfig { path: "$.identity".into(), reason: "pre-keyring configuration: export with the previous build, then connect and import into a fresh client root; existing files are unchanged".into() });
    }
    reject_connection_replica_fields(path, bytes)?;
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
