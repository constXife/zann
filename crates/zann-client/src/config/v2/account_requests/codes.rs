//! Durable staged recovery-code credentials.
use super::*;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryCodeCandidate {
    pub(crate) id: Uuid,
    endpoint: StoredBinding,
    storage: String,
    subject: String,
    pub(crate) revision: i64,
    credential: CredentialId,
}
impl ConfigRepository {
    pub(crate) fn prepare_recovery_code(
        &self,
        endpoint: VerifiedEndpointBinding,
        storage: String,
        subject: String,
        revision: i64,
        current_candidate: Option<Uuid>,
        store: &dyn CredentialStore,
    ) -> Result<(RecoveryCodeCandidate, zeroize::Zeroizing<String>), ConfigError> {
        ensure_config_root(self.paths.root())?;
        let _credentials = self.credential_operation_lock()?;
        let (existing, obsolete) = {
            let _config = self.exclusive_lock()?;
            let mut journal = self.read_account_requests()?;
            let mut obsolete = Vec::new();
            journal.codes.retain(|c| {
                let same =
                    c.endpoint.matches(&endpoint) && c.storage == storage && c.subject == subject;
                if same && c.revision < revision && current_candidate != Some(c.id) {
                    obsolete.push(c.credential.clone());
                    false
                } else {
                    true
                }
            });
            let existing = journal
                .codes
                .iter()
                .find(|c| {
                    c.revision == revision
                        && c.endpoint.matches(&endpoint)
                        && c.storage == storage
                        && c.subject == subject
                })
                .cloned();
            if existing.is_none() && journal.codes.len() >= 4 {
                return Err(account_conflict("too many pending recovery codes"));
            }
            self.write_account_requests(&journal)?;
            (existing, obsolete)
        };
        // A newer server security revision fences every removed candidate; its
        // ID also differs from the active server code. Ambiguous active codes stay.
        for credential in obsolete {
            store
                .delete(&credential)
                .map_err(|source| ConfigError::RecoveryCredential { source })?;
        }
        if let Some(existing) = existing {
            let code = store
                .get(&existing.credential)
                .map_err(|source| ConfigError::RecoveryCredential { source })?
                .ok_or(ConfigError::RecoveryCredentialMismatch)?;
            if !zann_crypto::recovery::valid_recovery_code(code.expose_secret()) {
                return Err(ConfigError::RecoveryCredentialMismatch);
            }
            return Ok((
                existing,
                zeroize::Zeroizing::new(code.expose_secret().to_owned()),
            ));
        }
        let id = Uuid::new_v4();
        let credential = operation_credential(
            self.paths.root(),
            id,
            b"account-recovery-code-v1",
            &[
                endpoint.address().as_bytes(),
                endpoint.server_id().as_bytes(),
                endpoint.server_fingerprint().as_bytes(),
                storage.as_bytes(),
                subject.as_bytes(),
            ],
        )?;
        let code = zann_crypto::recovery::generate_server_recovery_key();
        let secret = CredentialSecret(code.clone());
        store
            .validate(&credential, &secret)
            .map_err(|source| ConfigError::RecoveryCredential { source })?;
        store
            .put(&credential, &secret)
            .map_err(|source| ConfigError::RecoveryCredential { source })?;
        let actual = store
            .get(&credential)
            .map_err(|source| ConfigError::RecoveryCredential { source })?
            .ok_or(ConfigError::RecoveryCredentialMismatch)?;
        if !zann_crypto::tokens::constant_time_equal(
            actual.expose_secret().as_bytes(),
            code.as_bytes(),
        ) {
            return Err(ConfigError::RecoveryCredentialMismatch);
        }
        let candidate = RecoveryCodeCandidate {
            id,
            endpoint: StoredBinding::from(&endpoint),
            storage,
            subject,
            revision,
            credential,
        };
        let _config = self.exclusive_lock()?;
        let mut journal = self.read_account_requests()?;
        journal.codes.push(candidate.clone());
        self.write_account_requests(&journal)?;
        Ok((candidate, code))
    }
    pub(crate) fn confirmed_recovery_code(
        &self,
        candidate: &RecoveryCodeCandidate,
        endpoint: &VerifiedEndpointBinding,
        storage: &str,
        subject: &str,
        confirmation: &str,
        store: &dyn CredentialStore,
    ) -> Result<CredentialSecret, ConfigError> {
        if !candidate.endpoint.matches(endpoint)
            || candidate.storage != storage
            || candidate.subject != subject
        {
            return Err(account_conflict("recovery code account changed"));
        }
        let _credentials = self.credential_operation_lock()?;
        {
            let _config = self.exclusive_lock()?;
            if !self
                .read_account_requests()?
                .codes
                .iter()
                .any(|c| c.id == candidate.id && c.credential == candidate.credential)
            {
                return Err(account_conflict("unknown recovery code candidate"));
            }
        }
        let actual = store
            .get(&candidate.credential)
            .map_err(|source| ConfigError::RecoveryCredential { source })?
            .ok_or(ConfigError::RecoveryCredentialMismatch)?;
        if !zann_crypto::tokens::constant_time_equal(
            actual.expose_secret().as_bytes(),
            confirmation.as_bytes(),
        ) {
            return Err(ConfigError::RecoveryCredentialMismatch);
        }
        Ok(actual)
    }
    /// After the server receipt the user holds the only copy: the journal entry
    /// is removed first, then the secret, so a crash can orphan but never keep a
    /// journal reference to a deleted credential.
    pub(crate) fn forget_activated_recovery_code(
        &self,
        id: Uuid,
        store: &dyn CredentialStore,
    ) -> Result<(), ConfigError> {
        let _credentials = self.credential_operation_lock()?;
        let credential = {
            let _config = self.exclusive_lock()?;
            let mut journal = self.read_account_requests()?;
            let index = journal
                .codes
                .iter()
                .position(|c| c.id == id)
                .ok_or(account_conflict("unknown activated recovery code"))?;
            let credential = journal.codes.remove(index).credential;
            self.write_account_requests(&journal)?;
            credential
        };
        store
            .delete(&credential)
            .map_err(|source| ConfigError::RecoveryCredential { source })
    }
}
