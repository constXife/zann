//! Remembering the unlock on a device, independent of any UI toolkit.
//!
//! The master key is wrapped with a device wrapping key (DWK) that never lands
//! in application files. Where the DWK comes from is the choice this module
//! owns: the OS credential store, or a FIDO2 authenticator that re-derives it on
//! every unlock.
//!
//! Exactly one source is active at a time. With both live the keystore would
//! always answer first and the hardware key would be decoration.
//!
//! What this module deliberately does not do: hold the master key, prompt the
//! user, or touch a settings file. Callers own all three.

use serde::{Deserialize, Serialize};
use zann_crypto::crypto::{decrypt_blob, encrypt_blob, EncryptedBlob, SecretKey};

use crate::{Keystore, KeystoreError};

/// Additional authenticated data binding a wrapped master key to this purpose.
/// Part of the on-disk format: changing it invalidates every remembered unlock.
pub const DWK_AAD: &[u8] = b"zann:dwk:wrap:v1";

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum UnlockSource {
    #[default]
    Keystore,
    HardwareKey,
}

/// One enrolled authenticator. Nothing here is secret on its own: the wrapped
/// key needs the token, and the token needs a touch.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HardwareKeyEntry {
    pub label: String,
    /// Base64. Identifies the credential to the authenticator.
    pub credential_id: String,
    /// Base64. Salt fed to `hmac-secret`; different salts give different keys.
    pub salt: String,
    /// Base64. This token's own copy of the master key.
    pub wrapped_master_key: String,
    pub enrolled_at: String,
}

/// The part of a client's settings that describes a remembered unlock. Meant to
/// be flattened into whatever settings struct a client already persists, so the
/// on-disk field names stay stable across clients.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(default)]
pub struct RememberedUnlock {
    pub unlock_source: UnlockSource,
    pub hardware_keys: Vec<HardwareKeyEntry>,
    /// Used by [`UnlockSource::Keystore`]; hardware keys carry their own copies.
    pub wrapped_master_key: Option<String>,
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum UnlockError {
    #[error("no remembered unlock on this device")]
    NotRemembered,
    #[error("keystore: {0}")]
    Keystore(#[from] KeystoreError),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error("hardware key: {0}")]
    HardwareKey(#[from] crate::fido::FidoError),
    #[error("stored unlock data is corrupt: {message}")]
    Corrupt { message: String },
    #[error("hardware keys are not supported on this platform yet")]
    UnsupportedPlatform,
}

impl UnlockError {
    /// Stable identifier for the UI to translate. Clients must not parse the
    /// message text.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotRemembered => "keystore_not_found",
            Self::Keystore(err) => match err {
                KeystoreError::Cancelled => "keystore_cancelled",
                KeystoreError::NotFound => "keystore_not_found",
                KeystoreError::Unsupported => "keystore_unsupported",
                KeystoreError::Internal { .. } => "keystore_unavailable",
            },
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::HardwareKey(err) => err.kind(),
            Self::Corrupt { .. } => "keystore_error",
            Self::UnsupportedPlatform => "hardware_key_unsupported_platform",
        }
    }
}

fn corrupt(message: impl Into<String>) -> UnlockError {
    UnlockError::Corrupt {
        message: message.into(),
    }
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn wrap(dwk: &[u8; 32], master_key: &[u8; 32]) -> Result<String, UnlockError> {
    use base64::Engine;
    let blob = encrypt_blob(&SecretKey::from_bytes(*dwk), master_key, DWK_AAD)
        .map_err(|err| corrupt(err.to_string()))?;
    Ok(b64().encode(blob.to_bytes()))
}

fn unwrap(dwk: &[u8; 32], wrapped: &str) -> Result<[u8; 32], UnlockError> {
    use base64::Engine;
    let bytes = b64()
        .decode(wrapped)
        .map_err(|err| corrupt(err.to_string()))?;
    let blob = EncryptedBlob::from_bytes(&bytes).map_err(|err| corrupt(err.to_string()))?;
    let master = decrypt_blob(&SecretKey::from_bytes(*dwk), &blob, DWK_AAD)
        .map_err(|err| corrupt(err.to_string()))?;
    master
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("unwrapped master key has the wrong length"))
}

impl RememberedUnlock {
    /// Whether anything can unlock this device without the master password.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        match self.unlock_source {
            UnlockSource::Keystore => self.wrapped_master_key.is_some(),
            UnlockSource::HardwareKey => !self.hardware_keys.is_empty(),
        }
    }

    // -- OS keystore ------------------------------------------------------

    pub fn remember_with_keystore(
        &mut self,
        keystore: &dyn Keystore,
        master_key: &[u8; 32],
    ) -> Result<(), UnlockError> {
        let dwk = SecretKey::generate();
        keystore.store_dwk(dwk.as_bytes())?;
        self.wrapped_master_key = Some(wrap(dwk.as_bytes(), master_key)?);
        self.unlock_source = UnlockSource::Keystore;
        Ok(())
    }

    pub fn unlock_with_keystore(&self, keystore: &dyn Keystore) -> Result<[u8; 32], UnlockError> {
        let wrapped = self
            .wrapped_master_key
            .as_deref()
            .ok_or(UnlockError::NotRemembered)?;
        let dwk: [u8; 32] = keystore
            .load_dwk()?
            .ok_or(UnlockError::NotRemembered)?
            .as_slice()
            .try_into()
            .map_err(|_| corrupt("stored device key has the wrong length"))?;
        unwrap(&dwk, wrapped)
    }

    /// Forget the keystore copy. Tolerates a store that never held one, so it
    /// is safe to call when switching sources.
    pub fn forget_keystore(&mut self, keystore: &dyn Keystore) -> Result<(), UnlockError> {
        self.wrapped_master_key = None;
        match keystore.delete_dwk() {
            Ok(()) | Err(KeystoreError::NotFound | KeystoreError::Unsupported) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Move a device key that an older version left in a settings file into the
    /// keystore. Returns whether the caller still has a usable remembered
    /// unlock: on failure there is nowhere safe to keep the key, so the state
    /// is cleared rather than left readable on disk.
    pub fn adopt_legacy_dwk(
        &mut self,
        keystore: &dyn Keystore,
        legacy_dwk: &str,
    ) -> Result<(), UnlockError> {
        use base64::Engine;
        let result = b64()
            .decode(legacy_dwk)
            .map_err(|err| corrupt(err.to_string()))
            .and_then(|dwk| keystore.store_dwk(&dwk).map_err(UnlockError::from));
        if result.is_err() {
            self.wrapped_master_key = None;
        }
        result
    }

    // -- Hardware keys ----------------------------------------------------

    pub fn remove_hardware_key(&mut self, credential_id: &str) {
        self.hardware_keys
            .retain(|entry| entry.credential_id != credential_id);
        if self.hardware_keys.is_empty() && self.unlock_source == UnlockSource::HardwareKey {
            self.unlock_source = UnlockSource::Keystore;
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl RememberedUnlock {
    /// Enrol the connected authenticator. Two touches; see [`crate::fido`].
    /// `enrolled_at` is passed in so this crate needs no clock.
    pub fn enroll_hardware_key(
        &mut self,
        master_key: &[u8; 32],
        label: &str,
        enrolled_at: String,
    ) -> Result<HardwareKeyEntry, UnlockError> {
        use base64::Engine;
        use rand::{rngs::OsRng, RngCore};

        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        let (credential, dwk) = crate::fido::enroll(salt)?;
        let entry = HardwareKeyEntry {
            label: if label.trim().is_empty() {
                "Hardware key".to_string()
            } else {
                label.trim().to_string()
            },
            credential_id: b64().encode(&credential.credential_id),
            salt: b64().encode(credential.salt),
            wrapped_master_key: wrap(&dwk, master_key)?,
            enrolled_at,
        };

        // Re-enrolling a token replaces its entry rather than piling up copies
        // that all open the same door.
        self.hardware_keys
            .retain(|existing| existing.credential_id != entry.credential_id);
        self.hardware_keys.push(entry.clone());
        Ok(entry)
    }

    /// The enrolled entry whose authenticator is plugged in, if any. Silent: no
    /// touch, so this is safe to poll for auto-lock.
    #[must_use]
    pub fn connected_hardware_key(&self) -> Option<&HardwareKeyEntry> {
        self.hardware_keys.iter().find(|entry| {
            credential(entry)
                .map(|credential| crate::fido::is_present(&credential))
                .unwrap_or(false)
        })
    }

    /// One touch, on whichever enrolled token is connected.
    pub fn unlock_with_hardware_key(&self) -> Result<[u8; 32], UnlockError> {
        if self.hardware_keys.is_empty() {
            return Err(UnlockError::NotRemembered);
        }
        let entry = self
            .connected_hardware_key()
            .ok_or(UnlockError::HardwareKey(crate::fido::FidoError::NoDevice))?;
        let dwk = crate::fido::derive_dwk(&credential(entry)?)?;
        unwrap(&dwk, &entry.wrapped_master_key)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl RememberedUnlock {
    pub fn enroll_hardware_key(
        &mut self,
        _master_key: &[u8; 32],
        _label: &str,
        _enrolled_at: String,
    ) -> Result<HardwareKeyEntry, UnlockError> {
        Err(UnlockError::UnsupportedPlatform)
    }

    #[must_use]
    pub fn connected_hardware_key(&self) -> Option<&HardwareKeyEntry> {
        None
    }

    pub fn unlock_with_hardware_key(&self) -> Result<[u8; 32], UnlockError> {
        Err(UnlockError::UnsupportedPlatform)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn credential(entry: &HardwareKeyEntry) -> Result<crate::fido::HardwareCredential, UnlockError> {
    use base64::Engine;
    let credential_id = b64()
        .decode(&entry.credential_id)
        .map_err(|err| corrupt(err.to_string()))?;
    let salt: [u8; 32] = b64()
        .decode(&entry.salt)
        .map_err(|err| corrupt(err.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("stored salt has the wrong length"))?;
    Ok(crate::fido::HardwareCredential {
        credential_id,
        salt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct FakeKeystore {
        stored: Mutex<Option<Vec<u8>>>,
        broken: bool,
    }

    impl FakeKeystore {
        fn working() -> Self {
            Self {
                stored: Mutex::new(None),
                broken: false,
            }
        }

        fn broken() -> Self {
            Self {
                stored: Mutex::new(None),
                broken: true,
            }
        }
    }

    impl Keystore for FakeKeystore {
        fn status(&self) -> crate::KeystoreStatus {
            crate::KeystoreStatus {
                supported: !self.broken,
                biometrics_available: false,
                reason: None,
                message: None,
            }
        }

        fn store_dwk(&self, dwk: &[u8]) -> Result<(), KeystoreError> {
            if self.broken {
                return Err(KeystoreError::Unsupported);
            }
            *self.stored.lock().unwrap() = Some(dwk.to_vec());
            Ok(())
        }

        fn load_dwk(&self) -> Result<Option<Vec<u8>>, KeystoreError> {
            if self.broken {
                return Err(KeystoreError::Unsupported);
            }
            Ok(self.stored.lock().unwrap().clone())
        }

        fn delete_dwk(&self) -> Result<(), KeystoreError> {
            *self.stored.lock().unwrap() = None;
            Ok(())
        }
    }

    const MASTER: [u8; 32] = [5u8; 32];

    #[test]
    fn keystore_round_trip_returns_the_same_master_key() {
        let keystore = FakeKeystore::working();
        let mut remembered = RememberedUnlock::default();
        assert!(!remembered.is_armed());

        remembered
            .remember_with_keystore(&keystore, &MASTER)
            .expect("remember");
        assert!(remembered.is_armed());
        assert_eq!(
            remembered.unlock_with_keystore(&keystore).expect("unlock"),
            MASTER
        );
    }

    #[test]
    fn the_wrapped_key_is_useless_without_the_device_key() {
        let keystore = FakeKeystore::working();
        let mut remembered = RememberedUnlock::default();
        remembered
            .remember_with_keystore(&keystore, &MASTER)
            .expect("remember");

        // Same settings, empty store: this is the "someone copied the settings
        // file" case, and it must not yield the master key.
        let stolen_file = remembered.clone();
        let empty_store = FakeKeystore::working();
        assert!(stolen_file.unlock_with_keystore(&empty_store).is_err());
    }

    #[test]
    fn forgetting_clears_both_halves() {
        let keystore = FakeKeystore::working();
        let mut remembered = RememberedUnlock::default();
        remembered
            .remember_with_keystore(&keystore, &MASTER)
            .expect("remember");

        remembered.forget_keystore(&keystore).expect("forget");
        assert!(remembered.wrapped_master_key.is_none());
        assert_eq!(keystore.load_dwk().unwrap(), None);
        assert!(!remembered.is_armed());
    }

    #[test]
    fn adopting_a_legacy_key_keeps_the_unlock_working() {
        use base64::Engine;
        let keystore = FakeKeystore::working();
        let dwk = [3u8; 32];
        let mut remembered = RememberedUnlock {
            wrapped_master_key: Some(wrap(&dwk, &MASTER).expect("wrap")),
            ..RememberedUnlock::default()
        };

        remembered
            .adopt_legacy_dwk(&keystore, &b64().encode(dwk))
            .expect("adopt");
        assert_eq!(
            remembered.unlock_with_keystore(&keystore).expect("unlock"),
            MASTER
        );
    }

    #[test]
    fn a_legacy_key_with_nowhere_to_go_is_dropped_rather_than_kept() {
        use base64::Engine;
        let dwk = [3u8; 32];
        let mut remembered = RememberedUnlock {
            wrapped_master_key: Some(wrap(&dwk, &MASTER).expect("wrap")),
            ..RememberedUnlock::default()
        };

        let result = remembered.adopt_legacy_dwk(&FakeKeystore::broken(), &b64().encode(dwk));
        assert!(result.is_err());
        assert!(remembered.wrapped_master_key.is_none());
        assert!(!remembered.is_armed());
    }

    #[test]
    fn removing_the_last_hardware_key_falls_back_to_the_keystore_source() {
        let mut remembered = RememberedUnlock {
            unlock_source: UnlockSource::HardwareKey,
            hardware_keys: vec![HardwareKeyEntry {
                label: "YubiKey".to_string(),
                credential_id: "abc".to_string(),
                salt: "def".to_string(),
                wrapped_master_key: "ghi".to_string(),
                enrolled_at: "2026-08-08T00:00:00Z".to_string(),
            }],
            wrapped_master_key: None,
        };

        remembered.remove_hardware_key("abc");
        assert!(remembered.hardware_keys.is_empty());
        assert_eq!(remembered.unlock_source, UnlockSource::Keystore);
        assert!(!remembered.is_armed());
    }

    #[test]
    fn settings_keep_their_on_disk_field_names() {
        let json = serde_json::to_string(&RememberedUnlock::default()).expect("serialize");
        assert!(json.contains("\"unlock_source\":\"keystore\""));
        assert!(json.contains("\"hardware_keys\":[]"));
        assert!(json.contains("\"wrapped_master_key\":null"));
    }
}
