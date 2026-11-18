use super::*;

impl ConfigRepository {
    pub(super) fn read_recovery_intents(&self) -> Result<RecoveryIntents, ConfigError> {
        let path = self.paths.recovery_intents();
        if !validate_regular_file_if_exists(&path)? {
            return Ok(RecoveryIntents {
                journal_version: 1,
                operations: BTreeMap::new(),
            });
        }
        let bytes = read_file(&path, "read recovery intents")?;
        validate_json_shape(&bytes, 1024).map_err(|source| {
            ConfigError::MalformedRecoveryIntents {
                path: path.clone(),
                source,
            }
        })?;
        let intents: RecoveryIntents = serde_json::from_slice(&bytes)
            .map_err(|source| ConfigError::MalformedRecoveryIntents { path, source })?;
        self.validate_recovery_intents(&intents)?;
        Ok(intents)
    }
    pub(super) fn write_recovery_intents(
        &self,
        intents: &RecoveryIntents,
    ) -> Result<(), ConfigError> {
        self.validate_recovery_intents(intents)?;
        let bytes = serialize_bounded(
            intents,
            AUTH_OPERATION_INTENT_MAX_BYTES,
            AUTH_RECOVERY_INTENTS_FILENAME,
        )?;
        atomic_write(&self.paths.recovery_intents(), &bytes)
    }
    fn validate_recovery_intents(&self, intents: &RecoveryIntents) -> Result<(), ConfigError> {
        if intents.journal_version != 1 || intents.operations.len() > MAX_CLIENT_RECOVERY_OPERATIONS
        {
            return Err(conflict(
                "unsupported recovery journal or capacity exceeded",
            ));
        }
        for (id, intent) in &intents.operations {
            if *id != intent.operation_id || id.get_version_num() != 4 {
                return Err(conflict("operation identifier mismatch"));
            }
            intent.target.validate()?;
            if credential_id(self.paths.root(), *id, &intent.target)? != intent.credential_id {
                return Err(conflict("recovery target or credential binding mismatch"));
            }
            if !valid_digest(&intent.bundle_digest)
                || intent
                    .consume_digest
                    .as_ref()
                    .is_some_and(|d| !valid_digest(d))
            {
                return Err(conflict("invalid recovery digest"));
            }
            if (intent.phase == RecoveryIntentPhase::Prepared) != intent.consume_device.is_none()
                || (intent.phase == RecoveryIntentPhase::Prepared)
                    != intent.consume_digest.is_none()
            {
                return Err(conflict("recovery dispatch binding missing"));
            }
            if intent
                .status
                .as_ref()
                .is_some_and(|s| s.successor_code_version <= 0)
            {
                return Err(conflict("invalid successor code version"));
            }
            let consistent = match (intent.phase, intent.status.as_ref()) {
                (RecoveryIntentPhase::Prepared | RecoveryIntentPhase::Dispatched, None) => true,
                (RecoveryIntentPhase::Consumed, Some(status)) => !status.state.is_terminal(),
                (RecoveryIntentPhase::Completed, Some(status)) => {
                    status.state == zann_core::recovery::RecoveryState::Completed
                }
                (RecoveryIntentPhase::Stopped, Some(status)) => {
                    status.state.is_terminal()
                        && status.state != zann_core::recovery::RecoveryState::Completed
                }
                _ => false,
            };
            if !consistent {
                return Err(conflict("recovery phase/status mismatch"));
            }
            if let Some(status) = &intent.status {
                if status.operation_id != *id
                    || status.auth_epoch <= 0
                    || status.revision <= 0
                    || status.account_key_epoch.is_some_and(|e| e <= 0)
                {
                    return Err(conflict("invalid recovery status binding"));
                }
            }
        }
        Ok(())
    }
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
