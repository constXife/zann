use super::*;

#[derive(Clone, Debug)]
pub struct ConfigRepository {
    pub(super) paths: ClientPaths,
}

pub(super) struct CredentialTransactionPlan {
    pub(super) journal: CredentialTransactionJournal,
    pub(super) journal_bytes: Vec<u8>,
    pub(super) candidate_config: ConfigV2,
    pub(super) source_primary_bytes: Vec<u8>,
    pub(super) candidate_bytes: Vec<u8>,
    pub(super) credential_ids: BTreeMap<CredentialKind, CredentialId>,
    pub(super) predecessor_journal_bytes: Option<Vec<u8>>,
}

pub(super) struct CredentialTransactionSource {
    pub(super) config: ConfigV2,
    pub(super) source_primary_bytes: Vec<u8>,
    pub(super) source_backup: Option<(ConfigV2, String)>,
    pub(super) carried_retired_slots: BTreeSet<CredentialSlotRef>,
    pub(super) predecessor_journal_bytes: Option<Vec<u8>>,
}

pub(super) struct CredentialWriteSpec<'a> {
    pub(super) connection_id: &'a ConnectionId,
    pub(super) profile_name: &'a str,
    pub(super) bundle: &'a CredentialBundle,
}

pub(super) fn ensure_password_login_transaction_source(
    intent: &AuthOperationIntent,
    source: &CredentialTransactionSource,
) -> Result<(), ConfigError> {
    if intent.operation != AuthOperationKind::PasswordLogin
        || source.config.revision != intent.source.revision
        || byte_digest(&source.source_primary_bytes) != intent.source.raw_digest
    {
        return Err(ConfigError::AuthOperationIntentConflict {
            path: PathBuf::from(AUTH_OPERATION_INTENT_FILENAME),
            reason: "password-login credential transaction is not based on its exact armed source"
                .to_string(),
        });
    }
    Ok(())
}
