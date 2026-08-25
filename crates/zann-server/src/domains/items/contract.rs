use serde::Serialize;
use std::io::Write;
use zann_crypto::EncryptedPayload;

pub(crate) const MAX_ITEM_PATH_BYTES: usize = 500;
pub(crate) const MAX_ITEM_NAME_BYTES: usize = 200;
pub(crate) const MAX_ITEM_PATH_SEGMENTS: usize = 32;
pub(crate) const MAX_TYPE_ID_BYTES: usize = 128;
pub(crate) const MAX_PLAINTEXT_PAYLOAD_BYTES: usize = 256 * 1_024;
pub(crate) const MAX_CIPHERTEXT_BYTES: usize = MAX_PLAINTEXT_PAYLOAD_BYTES + 256;
pub(crate) const MAX_PUSH_CHANGES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ItemContractError {
    InvalidPath,
    InvalidName,
    InvalidType,
    TypeChangeNotSupported,
    InvalidChecksum,
    ChecksumMismatch,
    InvalidVersion,
    InvalidPayload,
    PayloadTooLarge,
}

impl ItemContractError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidPath => "invalid_path",
            Self::InvalidName => "invalid_name",
            Self::InvalidType => "invalid_type",
            Self::TypeChangeNotSupported => "type_change_not_supported",
            Self::InvalidChecksum => "invalid_checksum",
            Self::ChecksumMismatch => "checksum_mismatch",
            Self::InvalidVersion => "invalid_version",
            Self::InvalidPayload => "invalid_payload",
            Self::PayloadTooLarge => "payload_too_large",
        }
    }
}

pub(crate) fn canonical_create_version(version: Option<i64>) -> Result<i64, ItemContractError> {
    let version = version.unwrap_or(1);
    if version != 1 {
        return Err(ItemContractError::InvalidVersion);
    }
    Ok(version)
}

pub(crate) fn next_item_version(version: i64) -> Result<i64, ItemContractError> {
    if version < 1 {
        return Err(ItemContractError::InvalidVersion);
    }
    version
        .checked_add(1)
        .ok_or(ItemContractError::InvalidVersion)
}

pub(crate) fn canonical_create_location(
    path: &str,
    supplied_name: Option<&str>,
) -> Result<(String, String), ItemContractError> {
    validate_path(path)?;
    let name = basename(path);
    if let Some(supplied_name) = supplied_name {
        validate_name(supplied_name)?;
        if supplied_name != name {
            return Err(ItemContractError::InvalidName);
        }
    }
    Ok((path.to_string(), name.to_string()))
}

pub(crate) fn canonical_update_location(
    current_path: &str,
    new_path: Option<&str>,
    new_name: Option<&str>,
) -> Result<(String, String), ItemContractError> {
    let mut path = new_path.unwrap_or(current_path).to_string();
    validate_path(&path)?;

    if let Some(name) = new_name {
        validate_name(name)?;
        if new_path.is_some() {
            if basename(&path) != name {
                return Err(ItemContractError::InvalidName);
            }
        } else {
            path = replace_basename(&path, name);
            validate_path(&path)?;
        }
    }

    let name = basename(&path).to_string();
    Ok((path, name))
}

pub(crate) fn validate_path(path: &str) -> Result<(), ItemContractError> {
    if path.is_empty() || path.len() > MAX_ITEM_PATH_BYTES || path.trim() != path {
        return Err(ItemContractError::InvalidPath);
    }
    let mut count = 0_usize;
    for segment in path.split('/') {
        count += 1;
        if count > MAX_ITEM_PATH_SEGMENTS
            || segment.is_empty()
            || segment.len() > MAX_ITEM_NAME_BYTES
            || segment == "."
            || segment == ".."
            || segment.starts_with('.')
            || segment.trim() != segment
        {
            return Err(ItemContractError::InvalidPath);
        }
    }
    Ok(())
}

pub(crate) fn validate_name(name: &str) -> Result<(), ItemContractError> {
    if name.is_empty()
        || name.len() > MAX_ITEM_NAME_BYTES
        || name.trim() != name
        || name.contains('/')
        || name == "."
        || name == ".."
        || name.starts_with('.')
    {
        return Err(ItemContractError::InvalidName);
    }
    Ok(())
}

pub(crate) fn canonical_type_id(type_id: &str) -> Result<String, ItemContractError> {
    if type_id.is_empty() || type_id.len() > MAX_TYPE_ID_BYTES || type_id.trim() != type_id {
        return Err(ItemContractError::InvalidType);
    }
    Ok(type_id.to_string())
}

pub(crate) fn validate_existing_type_id(
    current_type_id: &str,
    requested_type_id: Option<&str>,
) -> Result<(), ItemContractError> {
    let Some(requested_type_id) = requested_type_id else {
        return Ok(());
    };
    let requested_type_id = canonical_type_id(requested_type_id)?;
    if requested_type_id != current_type_id {
        return Err(ItemContractError::TypeChangeNotSupported);
    }
    Ok(())
}

pub(crate) fn validate_personal_ciphertext(
    payload_enc: &[u8],
    checksum: &str,
) -> Result<(), ItemContractError> {
    validate_ciphertext(payload_enc)?;
    validate_checksum(checksum)?;
    if zann_crypto::payload_checksum(payload_enc) != checksum {
        return Err(ItemContractError::ChecksumMismatch);
    }
    Ok(())
}

pub(crate) fn validate_ciphertext(payload_enc: &[u8]) -> Result<(), ItemContractError> {
    if payload_enc.is_empty() || payload_enc.len() > MAX_CIPHERTEXT_BYTES {
        return Err(ItemContractError::PayloadTooLarge);
    }
    Ok(())
}

pub(crate) fn validate_checksum(checksum: &str) -> Result<(), ItemContractError> {
    if checksum.len() != 64
        || !checksum
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ItemContractError::InvalidChecksum);
    }
    Ok(())
}

pub(crate) fn validate_typed_payload(
    payload: &EncryptedPayload,
    type_id: &str,
) -> Result<(), ItemContractError> {
    let type_id = canonical_type_id(type_id)?;
    if payload.v != 1 || payload.type_id != type_id {
        return Err(ItemContractError::InvalidPayload);
    }

    serialized_typed_payload_len(payload).map(|_| ())
}

pub(crate) fn serialized_typed_payload_len(
    payload: &EncryptedPayload,
) -> Result<usize, ItemContractError> {
    let mut writer = BoundedWriter {
        written: 0,
        exceeded: false,
    };
    match payload.serialize(&mut serde_json::Serializer::new(&mut writer)) {
        Ok(()) => Ok(writer.written),
        Err(_) if writer.exceeded => Err(ItemContractError::PayloadTooLarge),
        Err(_) => Err(ItemContractError::InvalidPayload),
    }
}

/// Validates the canonical server-encrypted wire shape, including the strict
/// field contract for item types that have a domain-specific representation.
pub(crate) fn validate_server_typed_payload(
    payload: &EncryptedPayload,
    type_id: &str,
) -> Result<(), ItemContractError> {
    validate_typed_payload(payload, type_id)?;
    if type_id == crate::domains::secrets::service::SECRET_TYPE_ID {
        crate::domains::secrets::service::validate_secret_typed_payload(payload)
            .map_err(|_| ItemContractError::InvalidPayload)?;
    }
    Ok(())
}

pub(crate) fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn replace_basename(path: &str, name: &str) -> String {
    match path.rsplit_once('/') {
        Some((parent, _)) => format!("{parent}/{name}"),
        None => name.to_string(),
    }
}

struct BoundedWriter {
    written: usize,
    exceeded: bool,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.written.saturating_add(bytes.len()) > MAX_PLAINTEXT_PAYLOAD_BYTES {
            self.exceeded = true;
            return Err(std::io::Error::other("typed payload exceeds limit"));
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_item_location_rejects_hidden_trimmed_and_mismatched_names() {
        assert!(canonical_create_location("folder/item", Some("item")).is_ok());
        for path in [
            " folder/item",
            "folder/.item",
            "folder/../item",
            "folder//item",
        ] {
            assert_eq!(
                canonical_create_location(path, None),
                Err(ItemContractError::InvalidPath)
            );
        }
        assert_eq!(
            canonical_create_location("folder/item", Some("other")),
            Err(ItemContractError::InvalidName)
        );
        assert_eq!(
            canonical_create_location(&"segment/".repeat(MAX_ITEM_PATH_SEGMENTS), None),
            Err(ItemContractError::InvalidPath)
        );
        assert_eq!(
            canonical_create_location(&format!("folder/{}", "x".repeat(201)), None),
            Err(ItemContractError::InvalidPath)
        );
        assert_eq!(
            canonical_update_location("folder/item", Some("other/new"), Some("item")),
            Err(ItemContractError::InvalidName)
        );
    }

    #[test]
    fn typed_payload_requires_version_and_matching_type() {
        let valid = EncryptedPayload::new("login");
        assert!(validate_typed_payload(&valid, "login").is_ok());
        let mut wrong_version = EncryptedPayload::new("login");
        wrong_version.v = 2;
        assert_eq!(
            validate_typed_payload(&wrong_version, "login"),
            Err(ItemContractError::InvalidPayload)
        );
        assert_eq!(
            validate_typed_payload(&valid, "note"),
            Err(ItemContractError::InvalidPayload)
        );
    }

    #[test]
    fn existing_item_type_is_immutable_until_history_carries_a_type() {
        assert!(validate_existing_type_id("login", Some("login")).is_ok());
        assert_eq!(
            validate_existing_type_id("login", Some("note")),
            Err(ItemContractError::TypeChangeNotSupported)
        );
    }

    #[test]
    fn personal_ciphertext_requires_canonical_checksum_and_exact_blake3() {
        let ciphertext = [1_u8, 2, 3];
        let checksum = zann_crypto::payload_checksum(&ciphertext);
        assert!(validate_personal_ciphertext(&ciphertext, &checksum).is_ok());
        assert_eq!(
            validate_personal_ciphertext(&ciphertext, &checksum.to_uppercase()),
            Err(ItemContractError::InvalidChecksum)
        );
        assert_eq!(
            validate_personal_ciphertext(&[4_u8], &checksum),
            Err(ItemContractError::ChecksumMismatch)
        );
        assert_eq!(
            canonical_type_id(" login"),
            Err(ItemContractError::InvalidType)
        );
    }

    #[test]
    fn item_generations_start_at_one_and_never_saturate() {
        assert_eq!(canonical_create_version(None), Ok(1));
        assert_eq!(canonical_create_version(Some(1)), Ok(1));
        assert_eq!(
            canonical_create_version(Some(0)),
            Err(ItemContractError::InvalidVersion)
        );
        assert_eq!(next_item_version(1), Ok(2));
        assert_eq!(
            next_item_version(i64::MAX),
            Err(ItemContractError::InvalidVersion)
        );
    }
}
