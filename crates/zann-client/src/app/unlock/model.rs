use super::ConfigIdentity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Device-local keyring. Only authenticated ciphertext and public KDF parameters.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceUnlock {
    pub device_id: String,
    pub identity: ConfigIdentity,
    pub wrapped_root: String,
    pub root_check: String,
    pub accounts: BTreeMap<String, AccountKeyEnvelope>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountKeyEnvelope {
    pub server_id: String,
    pub account_subject: String,
    pub ciphertext: String,
}

use super::{decode_blob, DeviceUnlockError};

pub(super) const MAX_ACCOUNTS: usize = 256;

pub(super) fn validate_account_binding(
    storage: &str,
    envelope: &AccountKeyEnvelope,
) -> Result<(), DeviceUnlockError> {
    uuid::Uuid::parse_str(storage).map_err(|_| DeviceUnlockError::Invalid("invalid storage id"))?;
    if envelope.server_id.is_empty()
        || envelope.server_id.len() > 512
        || envelope.account_subject.is_empty()
        || envelope.account_subject.len() > 512
        || envelope.ciphertext.len() > 1024
    {
        return Err(DeviceUnlockError::Invalid("invalid account key binding"));
    }
    Ok(())
}

impl DeviceUnlock {
    pub fn decode(value: &str) -> Result<Self, DeviceUnlockError> {
        if value.len() > 1024 * 1024 {
            return Err(DeviceUnlockError::Invalid("keyring is too large"));
        }
        let keyring: Self = serde_json::from_str(value)?;
        uuid::Uuid::parse_str(&keyring.device_id)
            .map_err(|_| DeviceUnlockError::Invalid("invalid device id"))?;
        let params = zann_core::api::auth::KdfParams::from(keyring.identity.kdf_params.clone())
            .to_crypto_params();
        zann_crypto::passwords::validate_kdf_policy(&params).map_err(DeviceUnlockError::Invalid)?;
        if keyring.identity.kdf_salt.len() > 128 || keyring.accounts.len() > MAX_ACCOUNTS {
            return Err(DeviceUnlockError::Invalid("keyring limits exceeded"));
        }
        for value in [&keyring.wrapped_root, &keyring.root_check] {
            if value.len() > 1024 {
                return Err(DeviceUnlockError::Invalid("keyring envelope too large"));
            }
            decode_blob(value)?;
        }
        for (storage, envelope) in &keyring.accounts {
            validate_account_binding(storage, envelope)?;
            decode_blob(&envelope.ciphertext)?;
        }
        Ok(keyring)
    }
}

impl std::fmt::Debug for DeviceUnlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceUnlock(<redacted>)")
    }
}
