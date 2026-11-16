//! Bounded external passkey exchange. Wire codecs and validation have one owner.
use crate::{Credential, PasskeyError, RpId, UserEntity};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fmt,
    io::{Read, Write},
};
use zann_crypto::es256::Es256Key;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
mod bitwarden;
mod cose;
mod cxf;
mod json;
mod keepass;
mod model;
pub use cose::decode_cose_private_key;
pub use cxf::{write_cxf, CxfExportContext};
pub use model::*;

pub const MAX_EXCHANGE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_EXCHANGE_ENTRIES: usize = 4096;
const MAX_JSON_NODES: usize = 1_000_000;
const MAX_SECRET_BYTES: usize = 64 * 1024;
pub const EXCHANGE_METADATA_FIELD: &str = "exchange_metadata";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeFormat {
    Cxf,
    Bitwarden,
    KeepassXcPasskey,
    KeepassXml,
}

pub struct ExchangeError {
    kind: &'static str,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}
impl ExchangeError {
    fn new(kind: &'static str) -> Self {
        Self { kind, source: None }
    }
    fn source(
        kind: &'static str,
        error: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            kind,
            source: Some(error.into()),
        }
    }
    pub fn kind(&self) -> &'static str {
        self.kind
    }
}
impl fmt::Debug for ExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("external passkey exchange failed")
    }
}
impl std::error::Error for ExchangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}
impl From<PasskeyError> for ExchangeError {
    fn from(error: PasskeyError) -> Self {
        Self::source("passkey_validation", error)
    }
}
impl From<serde_json::Error> for ExchangeError {
    fn from(error: serde_json::Error) -> Self {
        Self::source(
            "passkey_json_invalid",
            crate::error::JsonDiagnostic::from(error),
        )
    }
}
impl From<std::io::Error> for ExchangeError {
    fn from(error: std::io::Error) -> Self {
        Self::source("passkey_exchange_io", error)
    }
}

pub fn import(
    reader: impl Read,
    format: ExchangeFormat,
) -> Result<ExchangeDocument, ExchangeError> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take((MAX_EXCHANGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_EXCHANGE_BYTES {
        return Err(ExchangeError::new("passkey_exchange_limit"));
    }
    let document = match format {
        ExchangeFormat::KeepassXml => keepass::xml(&bytes)?,
        _ => {
            zann_core::bounded_json::validate_json_shape(&bytes, MAX_JSON_NODES)?;
            let value = json::SensitiveJson(serde_json::from_slice(&bytes)?);
            match format {
                ExchangeFormat::Cxf => cxf::read(&value.0)?,
                ExchangeFormat::Bitwarden => bitwarden::read(&value.0)?,
                ExchangeFormat::KeepassXcPasskey => keepass::passkey(&value.0)?,
                ExchangeFormat::KeepassXml => unreachable!(),
            }
        }
    };
    document.validate()?;
    Ok(document)
}
fn bytes(value: &str, maximum: usize) -> Result<Zeroizing<Vec<u8>>, ExchangeError> {
    if value.is_empty() || value.len() > maximum.div_ceil(3) * 4 {
        return Err(ExchangeError::new("passkey_encoding_invalid"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| ExchangeError::source("passkey_encoding_invalid", e))?;
    let decoded = Zeroizing::new(decoded);
    if decoded.is_empty() || decoded.len() > maximum {
        return Err(ExchangeError::new("passkey_encoding_invalid"));
    }
    Ok(decoded)
}
fn credential(
    rp_id: &str,
    rp_name: &str,
    id: Vec<u8>,
    user: UserEntity,
    key: Es256Key,
    created_at: Option<DateTime<Utc>>,
) -> Result<Credential, ExchangeError> {
    let credential = Credential {
        exchange_metadata: None,
        rp_id: RpId::parse(rp_id).map_err(PasskeyError::Origin)?,
        rp_name: rp_name.into(),
        id,
        user,
        key,
        created_at,
    };
    credential.validate()?;
    Ok(credential)
}
