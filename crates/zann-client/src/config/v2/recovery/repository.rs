use super::*;

impl ConfigRepository {
    pub(crate) fn prepare_recovery(
        &self,
        preparation: &RecoveryPreparation,
        store: &dyn CredentialStore,
    ) -> Result<RecoveryIntent, ConfigError> {
        if !preparation.confirmed {
            return Err(conflict("successor code has not been confirmed"));
        }
        ensure_config_root(self.paths.root())?;
        let _credentials = self.credential_operation_lock()?;
        let encoded = CredentialSecret(preparation.secrets.encode());
        let digest = stable_hash(&[b"recovery-bundle-v1", encoded.expose_secret().as_bytes()]);
        let credential = credential_id(
            self.paths.root(),
            preparation.operation_id,
            &preparation.target,
        )?;
        {
            let _config = self.exclusive_lock()?;
            let intents = self.read_recovery_intents()?;
            if let Some(existing) = intents.operations.get(&preparation.operation_id) {
                if existing.target != preparation.target || existing.bundle_digest != digest {
                    return Err(conflict("operation already has a different preparation"));
                }
                let existing = existing.clone();
                drop(_config);
                self.read_recovery_secrets(&existing, store)?;
                return Ok(existing);
            }
            if intents.operations.len() >= MAX_CLIENT_RECOVERY_OPERATIONS {
                return Err(conflict("too many pending recovery operations"));
            }
        }
        // Keystore calls can prompt; the config lock is deliberately released.
        store.validate(&credential, &encoded).map_err(store_error)?;
        store.put(&credential, &encoded).map_err(store_error)?;
        let actual = store
            .get(&credential)
            .map_err(store_error)?
            .ok_or(ConfigError::RecoveryCredentialMismatch)?;
        if !zann_crypto::tokens::constant_time_equal(
            actual.expose_secret().as_bytes(),
            encoded.expose_secret().as_bytes(),
        ) {
            return Err(ConfigError::RecoveryCredentialMismatch);
        }
        let intent = RecoveryIntent {
            operation_id: preparation.operation_id,
            target: preparation.target.clone(),
            credential_id: credential,
            bundle_digest: digest,
            phase: RecoveryIntentPhase::Prepared,
            consume_digest: None,
            status: None,
        };
        let _config = self.exclusive_lock()?;
        let mut intents = self.read_recovery_intents()?;
        if intents.operations.contains_key(&intent.operation_id) {
            return Err(conflict("operation appeared during credential publication"));
        }
        intents
            .operations
            .insert(intent.operation_id, intent.clone());
        self.write_recovery_intents(&intents)?;
        // Any ambiguous journal error retains the unique keystore entry.
        Ok(intent)
    }
    pub(crate) fn pending_recoveries(&self) -> Result<Vec<RecoveryIntent>, ConfigError> {
        let _config = self.exclusive_lock()?;
        Ok(self
            .read_recovery_intents()?
            .operations
            .into_values()
            .collect())
    }
    pub(crate) fn recovery_secrets(
        &self,
        id: Uuid,
        observed: &VerifiedEndpointBinding,
        store: &dyn CredentialStore,
    ) -> Result<RecoverySecrets, ConfigError> {
        let intent = {
            let _config = self.exclusive_lock()?;
            self.read_recovery_intents()?
                .operations
                .remove(&id)
                .ok_or(conflict("unknown recovery operation"))?
        };
        if !intent.target.matches(observed) {
            return Err(conflict("verified server binding changed"));
        }
        self.read_recovery_secrets(&intent, store)
    }
    fn read_recovery_secrets(
        &self,
        intent: &RecoveryIntent,
        store: &dyn CredentialStore,
    ) -> Result<RecoverySecrets, ConfigError> {
        let secret = store
            .get(&intent.credential_id)
            .map_err(store_error)?
            .ok_or(ConfigError::RecoveryCredentialMismatch)?;
        let digest = stable_hash(&[b"recovery-bundle-v1", secret.expose_secret().as_bytes()]);
        if !zann_crypto::tokens::constant_time_equal(
            digest.as_bytes(),
            intent.bundle_digest.as_bytes(),
        ) {
            return Err(ConfigError::RecoveryCredentialMismatch);
        }
        RecoverySecrets::decode(secret.expose_secret())
            .map_err(|source| ConfigError::RecoverySecret { source })
    }
    pub(crate) fn mark_recovery_dispatched(
        &self,
        id: Uuid,
        observed: &VerifiedEndpointBinding,
        consume_digest: [u8; 32],
    ) -> Result<RecoveryIntent, ConfigError> {
        let _credentials = self.credential_operation_lock()?;
        let _config = self.exclusive_lock()?;
        let mut intents = self.read_recovery_intents()?;
        let intent = intents
            .operations
            .get_mut(&id)
            .ok_or(conflict("unknown recovery operation"))?;
        if !intent.target.matches(observed) {
            return Err(conflict("verified server binding changed"));
        }
        let digest = HEXLOWER.encode(&consume_digest);
        if intent.phase == RecoveryIntentPhase::Prepared {
            intent.consume_digest = Some(digest);
            intent.phase = RecoveryIntentPhase::Dispatched;
        } else if intent.phase != RecoveryIntentPhase::Dispatched
            || intent.consume_digest.as_deref() != Some(digest.as_str())
        {
            return Err(conflict("consume body changed after dispatch"));
        }
        let result = intent.clone();
        self.write_recovery_intents(&intents)?;
        Ok(result)
    }
    pub(crate) fn observe_recovery(
        &self,
        id: Uuid,
        observed: &VerifiedEndpointBinding,
        status: RecoveryStatus,
    ) -> Result<RecoveryIntent, ConfigError> {
        let _config = self.exclusive_lock()?;
        let mut intents = self.read_recovery_intents()?;
        let intent = intents
            .operations
            .get_mut(&id)
            .ok_or(conflict("unknown recovery operation"))?;
        if !intent.target.matches(observed)
            || intent.phase == RecoveryIntentPhase::Prepared
            || status.operation_id != id
        {
            return Err(conflict(
                "status arrived before dispatch or for another operation",
            ));
        }
        if let Some(old) = &intent.status {
            if status.user_id != old.user_id
                || status.auth_epoch != old.auth_epoch
                || status.account_key_epoch != old.account_key_epoch
                || status.expires_at != old.expires_at
                || status.revision < old.revision
                || (status.revision == old.revision && status != *old)
                || (old.state.is_terminal() && status != *old)
            {
                return Err(conflict("status generation changed or moved backwards"));
            }
        }
        intent.phase = if status.state == zann_core::recovery::RecoveryState::Completed {
            RecoveryIntentPhase::Completed
        } else if status.state.is_terminal() {
            RecoveryIntentPhase::Stopped
        } else {
            RecoveryIntentPhase::Consumed
        };
        intent.status = Some(status);
        let result = intent.clone();
        self.write_recovery_intents(&intents)?;
        Ok(result)
    }
    pub(crate) fn discard_prepared_recovery(
        &self,
        id: Uuid,
        store: &dyn CredentialStore,
    ) -> Result<(), ConfigError> {
        let _credentials = self.credential_operation_lock()?;
        let credential = {
            let _config = self.exclusive_lock()?;
            let mut intents = self.read_recovery_intents()?;
            let intent = intents
                .operations
                .get(&id)
                .ok_or(conflict("unknown recovery operation"))?;
            if intent.phase != RecoveryIntentPhase::Prepared {
                return Err(conflict("dispatched recovery secrets must be retained"));
            }
            let credential = intent.credential_id.clone();
            intents.operations.remove(&id);
            self.write_recovery_intents(&intents)?;
            credential
        };
        store.delete(&credential).map_err(store_error)
    }
}
