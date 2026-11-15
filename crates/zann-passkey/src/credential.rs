use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use zann_core::{EncryptedPayload, FieldKind, FieldValue};
use zann_crypto::es256::Es256Key;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{PasskeyError, RpId, PASSKEY_ALGORITHM, PASSKEY_TYPE_ID};

pub const MAX_CREDENTIAL_ID_BYTES: usize = 1023;
pub const MAX_USER_HANDLE_BYTES: usize = 64;
const MAX_LABEL_BYTES: usize = 1024;
const MAX_PKCS8_BYTES: usize = 512;
const MAX_ENCODED_FIELD_BYTES: usize = MAX_CREDENTIAL_ID_BYTES.div_ceil(3) * 4;

/// User metadata is private; no Debug/Serialize projection crosses IPC implicitly.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UserEntity {
    pub id: Vec<u8>,
    pub name: String,
    pub display_name: String,
}

/// No Debug or Clone: private keys have explicit custody and zeroizing storage.
pub struct Credential {
    pub(crate) rp_id: RpId,
    pub(crate) rp_name: String,
    pub(crate) id: Vec<u8>,
    pub(crate) user: UserEntity,
    pub(crate) key: Es256Key,
    pub(crate) created_at: DateTime<Utc>,
}

impl Credential {
    pub fn rp_id(&self) -> &RpId {
        &self.rp_id
    }
    pub fn credential_id(&self) -> &[u8] {
        &self.id
    }
    pub fn user_handle(&self) -> &[u8] {
        &self.user.id
    }
    pub fn public_key(&self) -> [u8; 65] {
        self.key.public_key()
    }

    pub(crate) fn validate(&self) -> Result<(), PasskeyError> {
        validate_id(&self.id)?;
        validate_user(&self.user)?;
        validate_label(&self.rp_name)
    }

    /// Canonical encrypted Item payload. Never use this as a UI or IPC response.
    pub fn to_payload(&self) -> Result<EncryptedPayload, PasskeyError> {
        self.validate()?;
        let mut payload = EncryptedPayload::new(PASSKEY_TYPE_ID);
        for (name, value, kind) in [
            ("rp_id", self.rp_id.as_str().to_string(), FieldKind::Text),
            ("rp_name", self.rp_name.clone(), FieldKind::Text),
            (
                "credential_id",
                URL_SAFE_NO_PAD.encode(&self.id),
                FieldKind::Password,
            ),
            (
                "user_handle",
                URL_SAFE_NO_PAD.encode(&self.user.id),
                FieldKind::Password,
            ),
            ("user_name", self.user.name.clone(), FieldKind::Text),
            (
                "user_display_name",
                self.user.display_name.clone(),
                FieldKind::Text,
            ),
            ("alg", PASSKEY_ALGORITHM.to_string(), FieldKind::Text),
            (
                "private_key",
                URL_SAFE_NO_PAD.encode(self.key.to_pkcs8_der().map_err(PasskeyError::Crypto)?),
                FieldKind::Password,
            ),
            ("created_at", self.created_at.to_rfc3339(), FieldKind::Text),
            ("discoverable", "true".into(), FieldKind::Text),
        ] {
            payload.fields.insert(
                name.into(),
                FieldValue {
                    kind,
                    value,
                    meta: None,
                },
            );
        }
        Ok(payload)
    }

    pub fn from_payload(payload: &EncryptedPayload) -> Result<Self, PasskeyError> {
        if payload.type_id != PASSKEY_TYPE_ID
            || payload.v != zann_core::PAYLOAD_VERSION
            || payload.fields.len() != 10
            || payload.extra.is_some()
        {
            return Err(PasskeyError::Payload);
        }
        let field = |name: &str, kind: FieldKind| {
            payload
                .fields
                .get(name)
                .filter(|field| field.kind == kind && field.value.len() <= MAX_ENCODED_FIELD_BYTES)
                .map(|field| field.value.as_str())
                .ok_or(PasskeyError::Payload)
        };
        if field("alg", FieldKind::Text)? != PASSKEY_ALGORITHM.to_string() {
            return Err(PasskeyError::Algorithm);
        }
        if field("discoverable", FieldKind::Text)? != "true" {
            return Err(PasskeyError::Payload);
        }
        let key_bytes = decode(field("private_key", FieldKind::Password)?, MAX_PKCS8_BYTES)?;
        let credential = Self {
            rp_id: RpId::parse(field("rp_id", FieldKind::Text)?).map_err(PasskeyError::Origin)?,
            rp_name: field("rp_name", FieldKind::Text)?.into(),
            id: std::mem::take(&mut *decode(
                field("credential_id", FieldKind::Password)?,
                MAX_CREDENTIAL_ID_BYTES,
            )?),
            user: UserEntity {
                id: std::mem::take(&mut *decode(
                    field("user_handle", FieldKind::Password)?,
                    MAX_USER_HANDLE_BYTES,
                )?),
                name: field("user_name", FieldKind::Text)?.into(),
                display_name: field("user_display_name", FieldKind::Text)?.into(),
            },
            key: Es256Key::from_pkcs8_der(&key_bytes).map_err(PasskeyError::Crypto)?,
            created_at: DateTime::parse_from_rfc3339(field("created_at", FieldKind::Text)?)
                .map_err(PasskeyError::Time)?
                .with_timezone(&Utc),
        };
        credential.validate()?;
        Ok(credential)
    }
}

fn decode(value: &str, max: usize) -> Result<Zeroizing<Vec<u8>>, PasskeyError> {
    if value.is_empty() || value.len() > max.div_ceil(3) * 4 {
        return Err(PasskeyError::Input);
    }
    let mut bytes = Zeroizing::new(vec![0; max]);
    let length = URL_SAFE_NO_PAD
        .decode_slice(value, &mut bytes)
        .map_err(PasskeyError::Base64)?;
    bytes.truncate(length);
    if bytes.is_empty() || bytes.len() > max {
        return Err(PasskeyError::Input);
    }
    Ok(bytes)
}

pub(crate) fn validate_id(id: &[u8]) -> Result<(), PasskeyError> {
    if id.is_empty() || id.len() > MAX_CREDENTIAL_ID_BYTES {
        return Err(PasskeyError::Input);
    }
    Ok(())
}
pub(crate) fn validate_user(user: &UserEntity) -> Result<(), PasskeyError> {
    if user.id.is_empty() || user.id.len() > MAX_USER_HANDLE_BYTES {
        return Err(PasskeyError::Input);
    }
    validate_label(&user.name)?;
    validate_label(&user.display_name)
}
pub(crate) fn validate_label(label: &str) -> Result<(), PasskeyError> {
    if label.len() > MAX_LABEL_BYTES || label.chars().any(char::is_control) {
        return Err(PasskeyError::Input);
    }
    Ok(())
}
