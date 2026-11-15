use super::*;
use base64::Engine;

/// Public routing metadata. Deliberately no Debug: hardware IDs are sensitive.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RecipientDescriptor {
    Argon2idPassphrase {
        salt: [u8; 32],
        iterations: u32,
        memory_kb: u32,
        parallelism: u32,
    },
    Fido2HmacSecret {
        credential_id: Vec<u8>,
        salt: [u8; 32],
    },
    DeviceBiometric {
        key_id: [u8; 16],
    },
}
impl RecipientDescriptor {
    pub fn portable(&self) -> bool {
        !matches!(self, Self::DeviceBiometric { .. })
    }
    pub fn passphrase() -> Self {
        Self::Argon2idPassphrase {
            salt: random(),
            iterations: 3,
            memory_kb: 64 * 1024,
            parallelism: 1,
        }
    }
    pub fn validate(&self) -> Result<(), ArchiveError> {
        match self {
            Self::Argon2idPassphrase { .. } => {
                crate::validate_kdf_policy(&self.kdf()?).map_err(ArchiveError::new)?;
            }
            Self::Fido2HmacSecret { credential_id, .. }
                if !(1..=1023).contains(&credential_id.len()) =>
            {
                return Err(ArchiveError::new("backup_recipient_invalid"))
            }
            _ => {}
        }
        Ok(())
    }
    fn kdf(&self) -> Result<crate::KdfParams, ArchiveError> {
        let Self::Argon2idPassphrase {
            iterations,
            memory_kb,
            parallelism,
            ..
        } = self
        else {
            return Err(ArchiveError::new("backup_recipient_mismatch"));
        };
        Ok(crate::KdfParams {
            algorithm: crate::KDF_ALGORITHM.into(),
            iterations: *iterations,
            memory_kb: *memory_kb,
            parallelism: *parallelism,
        })
    }
    pub fn key_from_passphrase(&self, passphrase: &str) -> Result<RecipientKey, ArchiveError> {
        if passphrase.is_empty() || passphrase.len() > 4096 {
            return Err(ArchiveError::new("backup_passphrase_invalid"));
        }
        self.validate()?;
        let Self::Argon2idPassphrase { salt, .. } = self else {
            return Err(ArchiveError::new("backup_recipient_mismatch"));
        };
        let key = crate::derive_auth_hash(
            passphrase,
            &base64::engine::general_purpose::STANDARD.encode(salt),
            &self.kdf()?,
        )
        .map_err(ArchiveError::new)?;
        Ok(RecipientKey::new(self.clone(), SecretKey::from_bytes(key)))
    }
}
pub struct RecipientKey {
    pub(super) descriptor: RecipientDescriptor,
    pub(super) key: SecretKey,
}
impl RecipientKey {
    pub fn new(descriptor: RecipientDescriptor, key: SecretKey) -> Self {
        Self { descriptor, key }
    }
    pub fn descriptor(&self) -> &RecipientDescriptor {
        &self.descriptor
    }
    /// Separate backup wrapping from the remembered-unlock DWK derivation.
    pub fn from_hardware(
        descriptor: RecipientDescriptor,
        output: &[u8; 32],
    ) -> Result<Self, ArchiveError> {
        if !matches!(descriptor, RecipientDescriptor::Fido2HmacSecret { .. }) {
            return Err(ArchiveError::new("backup_recipient_mismatch"));
        }
        descriptor.validate()?;
        Ok(Self::new(
            descriptor,
            SecretKey::from_bytes(blake3::derive_key(
                "zann backup v1 fido2 wrapping key",
                output,
            )),
        ))
    }
}
