//! Native factor I/O runs outside the context gate. Only a checked lease can append.
use super::*;
use zann_keystore::{HardwareCredential, HardwareVerification};
use zeroize::Zeroizing;
impl LocalVault {
    pub fn backup_add_recipient(
        &self,
        handle: BackupHandle,
        recipient: BackupRecipient,
    ) -> LocalResult<BackupRecipientSummary> {
        let (lease, content) = self.archive_snapshot(&handle)?;
        let ArchiveContent::Prepared(keys) = content else {
            return Err(failure(BackupFailure::HandleKind));
        };
        if keys.len() >= zann_crypto::backup::MAX_RECIPIENTS {
            return Err(failure(BackupFailure::RecipientLimit));
        }
        if matches!(&recipient, BackupRecipient::Biometric)
            && keys.iter().any(|key| {
                matches!(
                    key.descriptor(),
                    RecipientDescriptor::DeviceBiometric { .. }
                )
            })
        {
            return Err(failure(BackupFailure::RecipientDuplicate));
        }
        let _active = self.syncs.register(
            lease.operation.operation_id(),
            lease.operation.cancellation_handle(),
        );
        let key = match &recipient {
            BackupRecipient::Passphrase { passphrase } => RecipientDescriptor::passphrase()
                .key_from_passphrase(passphrase)
                .map_err(crypto)?,
            BackupRecipient::Hardware { pin, built_in_uv } => {
                let verification = verification(pin.as_deref(), *built_in_uv)?;
                let credential = self
                    .authenticator
                    .create_credential(*SecretKey::generate().as_bytes(), verification)
                    .map_err(|e| unlock_error(e.into()))?;
                let output = Zeroizing::new(
                    self.authenticator
                        .derive_dwk(&credential, verification)
                        .map_err(|e| unlock_error(e.into()))?,
                );
                let descriptor = RecipientDescriptor::Fido2HmacSecret {
                    credential_id: credential.credential_id,
                    salt: credential.salt,
                };
                RecipientKey::from_hardware(descriptor, &output).map_err(crypto)?
            }
            BackupRecipient::Biometric => self.backup_biometric_recipient(&lease)?,
        };
        let _context = self.context_gate.read().expect("context");
        lease.check(self)?;
        let mut pending = self.archive.lock().expect("archive");
        let work = pending
            .as_mut()
            .filter(|w| {
                zann_crypto::secret_bytes_equal(w.token.as_bytes(), handle.token().as_bytes())
            })
            .ok_or_else(|| failure(BackupFailure::HandleInvalid))?;
        let ArchiveContent::Prepared(keys) = &mut work.content else {
            return Err(failure(BackupFailure::HandleKind));
        };
        if keys.len() >= zann_crypto::backup::MAX_RECIPIENTS
            || keys.iter().any(|k| k.descriptor() == key.descriptor())
        {
            return Err(failure(BackupFailure::RecipientLimit));
        }
        let result = summary(keys.len(), key.descriptor());
        keys.push(Arc::new(key));
        Ok(result)
    }
    fn backup_biometric_recipient(&self, lease: &ArchiveLease) -> LocalResult<RecipientKey> {
        if !self.backup_keys.status().biometrics_available {
            return Err(failure(BackupFailure::BiometricsUnavailable));
        }
        let pool = self.pool();
        let repo = zann_db::local::MetadataRepo::new(&pool);
        let stored = self
            .runtime
            .block_on(repo.get_value_bounded("backup_biometric_key_id", 36))
            .map_err(unlock::keyring_error)?;
        {
            let _context = self.context_gate.read().expect("context");
            lease.check(self)?;
        }
        let (id, key) = match stored {
            Some(value) => {
                let id = Uuid::parse_str(&value).map_err(BackupError::source)?;
                let key = self
                    .backup_keys
                    .load(id.as_bytes())
                    .map_err(|e| unlock_error(e.into()))?
                    .ok_or_else(|| failure(BackupFailure::BiometricKeyMissing))?;
                let key = Zeroizing::new(key);
                let key = SecretKey::from_bytes(
                    key.as_slice()
                        .try_into()
                        .map_err(|_| failure(BackupFailure::BiometricKeyInvalid))?,
                );
                (id, key)
            }
            None => {
                let id = Uuid::now_v7();
                let key = SecretKey::generate();
                self.backup_keys
                    .store(id.as_bytes(), key.as_bytes())
                    .map_err(|e| unlock_error(e.into()))?;
                let verified = (|| {
                    let actual = Zeroizing::new(
                        self.backup_keys
                            .load(id.as_bytes())
                            .map_err(|e| unlock_error(e.into()))?
                            .ok_or_else(|| failure(BackupFailure::BiometricKeyMissing))?,
                    );
                    if !zann_crypto::secret_bytes_equal(&actual, key.as_bytes()) {
                        return Err(failure(BackupFailure::WrapVerification));
                    }
                    let _context = self.context_gate.read().expect("context");
                    lease.check(self)?;
                    Ok(())
                })();
                if let Err(original) = verified {
                    if let Err(cleanup) = self.backup_keys.delete(id.as_bytes()) {
                        return Err(
                            BackupError::source(BiometricCleanup { original, cleanup }).into()
                        );
                    }
                    return Err(original);
                }
                // Once dispatched, await the exact CAS outcome without a session
                // gate. Keep the OS key on an ambiguous/competing commit: deleting
                // it could leave durable metadata pointing to a missing key.
                if !self
                    .runtime
                    .block_on(repo.compare_exchange_value(
                        "backup_biometric_key_id",
                        None,
                        &id.to_string(),
                    ))
                    .map_err(unlock::keyring_error)?
                {
                    return Err(failure(BackupFailure::BiometricKeyChanged));
                }
                (id, key)
            }
        };
        Ok(RecipientKey::new(
            RecipientDescriptor::DeviceBiometric {
                key_id: *id.as_bytes(),
            },
            key,
        ))
    }
    pub(super) fn unlock_backup_recipient(
        &self,
        descriptor: &RecipientDescriptor,
        recipient: &BackupRecipient,
    ) -> LocalResult<RecipientKey> {
        match (descriptor, recipient) {
            (
                RecipientDescriptor::Argon2idPassphrase { .. },
                BackupRecipient::Passphrase { passphrase },
            ) => descriptor.key_from_passphrase(passphrase).map_err(crypto),
            (
                RecipientDescriptor::Fido2HmacSecret {
                    credential_id,
                    salt,
                },
                BackupRecipient::Hardware { pin, built_in_uv },
            ) => {
                let output = Zeroizing::new(
                    self.authenticator
                        .derive_dwk(
                            &HardwareCredential {
                                credential_id: credential_id.clone(),
                                salt: *salt,
                            },
                            verification(pin.as_deref(), *built_in_uv)?,
                        )
                        .map_err(|e| unlock_error(e.into()))?,
                );
                RecipientKey::from_hardware(descriptor.clone(), &output).map_err(crypto)
            }
            (RecipientDescriptor::DeviceBiometric { key_id }, BackupRecipient::Biometric) => {
                if !self.backup_keys.status().biometrics_available {
                    return Err(failure(BackupFailure::BiometricsUnavailable));
                }
                let key = Zeroizing::new(
                    self.backup_keys
                        .load(key_id)
                        .map_err(|e| unlock_error(e.into()))?
                        .ok_or_else(|| failure(BackupFailure::BiometricKeyMissing))?,
                );
                Ok(RecipientKey::new(
                    descriptor.clone(),
                    SecretKey::from_bytes(
                        key.as_slice()
                            .try_into()
                            .map_err(|_| failure(BackupFailure::BiometricKeyInvalid))?,
                    ),
                ))
            }
            _ => Err(failure(BackupFailure::RecipientMismatch)),
        }
    }
}
fn verification(pin: Option<&str>, built_in: bool) -> LocalResult<HardwareVerification<'_>> {
    match (pin, built_in) {
        (Some(_), true) => Err(failure(BackupFailure::RecipientInvalid)),
        (Some(pin), false) => Ok(HardwareVerification::Pin(pin)),
        (None, true) => Ok(HardwareVerification::BuiltIn),
        (None, false) => Ok(HardwareVerification::Presence),
    }
}
#[derive(Debug)]
struct BiometricCleanup {
    original: LocalError,
    cleanup: zann_keystore::KeystoreError,
}
impl std::fmt::Display for BiometricCleanup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "biometric key enrollment failed; cleanup failed ({})",
            self.cleanup
        )
    }
}
impl std::error::Error for BiometricCleanup {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
