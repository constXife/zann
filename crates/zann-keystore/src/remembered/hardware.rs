use super::*;

/// Only public credential metadata, no master key or DWK. Not serializable.
/// Dropping this value abandons enrollment without modifying remembered state.
pub struct PendingHardwareKey {
    credential: crate::HardwareCredential,
    label: String,
}

impl RememberedUnlock {
    /// Touch 1. The pending credential is not armed or persisted.
    pub fn begin_enroll(
        authenticator: &dyn crate::HardwareAuthenticator,
        label: &str,
    ) -> Result<PendingHardwareKey, UnlockError> {
        let credential = authenticator.create_credential(rand::random())?;
        Ok(PendingHardwareKey {
            credential,
            label: label.trim().to_string(),
        })
    }

    /// Touch 2 proves hmac-secret works before adding a wrapped master key.
    /// Consumes the pending credential; a failed confirmation changes no state.
    pub fn confirm_enroll(
        &mut self,
        authenticator: &dyn crate::HardwareAuthenticator,
        pending: PendingHardwareKey,
        master_key: &[u8; 32],
        enrolled_at: String,
    ) -> Result<HardwareKeyEntry, UnlockError> {
        use base64::Engine;
        let PendingHardwareKey { credential, label } = pending;
        let dwk = zeroize::Zeroizing::new(authenticator.derive_dwk(&credential)?);
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
    pub fn connected_hardware_key(
        &self,
        authenticator: &dyn crate::HardwareAuthenticator,
    ) -> Option<&HardwareKeyEntry> {
        self.hardware_keys.iter().find(|entry| {
            credential(entry)
                .map(|credential| authenticator.is_present(&credential))
                .unwrap_or(false)
        })
    }

    /// One touch, on whichever enrolled token is connected.
    pub fn unlock_with_hardware_key(
        &self,
        authenticator: &dyn crate::HardwareAuthenticator,
    ) -> Result<[u8; 32], UnlockError> {
        if self.hardware_keys.is_empty() {
            return Err(UnlockError::NotRemembered);
        }
        authenticator.status()?;
        // Validate every persisted descriptor rather than hiding corrupt data as absence.
        for entry in &self.hardware_keys {
            credential(entry)?;
        }
        let entry = self
            .connected_hardware_key(authenticator)
            .ok_or(UnlockError::HardwareKey(crate::FidoError::NotEnrolled))?;
        let dwk = zeroize::Zeroizing::new(authenticator.derive_dwk(&credential(entry)?)?);
        unwrap(&dwk, &entry.wrapped_master_key)
    }
}

fn credential(entry: &HardwareKeyEntry) -> Result<crate::HardwareCredential, UnlockError> {
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
    Ok(crate::HardwareCredential {
        credential_id,
        salt,
    })
}
