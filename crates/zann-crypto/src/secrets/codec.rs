//! Version admission before decoding the current payload schema.
use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serializer};
use tracing::instrument;

use super::EncryptedPayload;

pub const PAYLOAD_VERSION: u32 = 1;

pub enum PayloadError {
    // Retain the original diagnostic for structured inspection. Its rendering
    // can contain field names/values, so Display and Debug never forward it.
    InvalidJson(serde_json::Error),
    UnsupportedPayloadVersion(u32),
}

impl fmt::Debug for PayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(_) => formatter.write_str("PayloadError::InvalidJson(<redacted>)"),
            Self::UnsupportedPayloadVersion(version) => formatter
                .debug_tuple("UnsupportedPayloadVersion")
                .field(version)
                .finish(),
        }
    }
}

impl fmt::Display for PayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(_) => formatter.write_str("invalid payload json"),
            Self::UnsupportedPayloadVersion(version) => {
                write!(formatter, "unsupported payload version: {version}")
            }
        }
    }
}

impl std::error::Error for PayloadError {}

fn check_version(version: u32) -> Result<(), PayloadError> {
    if version != PAYLOAD_VERSION {
        return Err(PayloadError::UnsupportedPayloadVersion(version));
    }
    Ok(())
}

pub(super) fn serialize_version<S: Serializer>(
    version: &u32,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    check_version(*version).map_err(serde::ser::Error::custom)?;
    serializer.serialize_u32(*version)
}

impl EncryptedPayload {
    #[must_use]
    pub fn new(type_id: impl Into<String>) -> Self {
        Self {
            v: PAYLOAD_VERSION,
            type_id: type_id.into(),
            fields: HashMap::new(),
            extra: None,
        }
    }

    #[instrument(level = "debug", skip(self))]
    pub fn to_bytes(&self) -> Result<Vec<u8>, PayloadError> {
        check_version(self.v)?;
        serde_json::to_vec(self).map_err(PayloadError::InvalidJson)
    }

    #[instrument(level = "debug", skip(bytes), fields(bytes_len = bytes.len()))]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PayloadError> {
        // This is the persisted-payload admission boundary. Raw Serde remains
        // available to wire DTOs so their owning request validators can return
        // structured errors; writers still cannot serialize unsupported v.
        // IgnoredAny skips field bodies without interpreting their schema or
        // allocating a second plaintext tree. `v` may appear last in JSON.
        #[derive(Deserialize)]
        struct VersionProbe {
            v: u32,
        }
        let probe: VersionProbe =
            serde_json::from_slice(bytes).map_err(PayloadError::InvalidJson)?;
        check_version(probe.v)?;
        serde_json::from_slice(bytes).map_err(PayloadError::InvalidJson)
    }
}
