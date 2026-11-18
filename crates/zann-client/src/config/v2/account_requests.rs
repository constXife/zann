//! Secret-free dispatch receipts for account-security and restricted recovery.
use super::*;
use crate::account_access::intents::{PublicReceipt, PublicRequest};
use uuid::Uuid;
const MAX_REQUESTS: usize = 32;
const MAX_BYTES: usize = ACCOUNT_REQUESTS_MAX_BYTES as usize;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountRequestIntent {
    pub(crate) id: Uuid,
    pub(crate) authority: Option<Uuid>,
    endpoint: StoredBinding,
    pub(crate) path: String,
    pub(crate) public_body: PublicRequest,
    pub(crate) receipt: Option<PublicReceipt>,
}
impl AccountRequestIntent {
    pub(crate) fn matches(&self, endpoint: &VerifiedEndpointBinding) -> bool {
        self.endpoint.matches(endpoint)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    requests: Vec<AccountRequestIntent>,
    codes: Vec<RecoveryCodeCandidate>,
}
impl ConfigRepository {
    fn account_requests_path(&self) -> PathBuf {
        self.paths.root().join(ACCOUNT_REQUESTS_FILENAME)
    }
    fn read_account_requests(&self) -> Result<Journal, ConfigError> {
        let path = self.account_requests_path();
        if !validate_regular_file_if_exists(&path)? {
            return Ok(Journal {
                version: 1,
                requests: Vec::new(),
                codes: Vec::new(),
            });
        }
        let bytes = read_file(&path, "read account request journal")?;
        if bytes.len() > MAX_BYTES {
            return Err(account_conflict("account journal exceeds limit"));
        }
        validate_json_shape(&bytes, 20000).map_err(|source| {
            ConfigError::MalformedRecoveryIntents {
                path: path.clone(),
                source,
            }
        })?;
        let journal: Journal = serde_json::from_slice(&bytes)
            .map_err(|source| ConfigError::MalformedRecoveryIntents { path, source })?;
        if journal.version != 1 || journal.requests.len() > MAX_REQUESTS || journal.codes.len() > 4
        {
            return Err(account_conflict("invalid account journal"));
        }
        for request in &journal.requests {
            request.endpoint.validate()?;
            if request.id.get_version_num() != 4
                || request.path.len() > 256
                || !request.path.starts_with("v1/")
            {
                return Err(account_conflict("invalid account intent"));
            }
        }
        Ok(journal)
    }
    fn write_account_requests(&self, journal: &Journal) -> Result<(), ConfigError> {
        let bytes = serialize_bounded(journal, MAX_BYTES as u64, ACCOUNT_REQUESTS_FILENAME)?;
        atomic_write(&self.account_requests_path(), &bytes)
    }
    pub(crate) fn stage_account_request(
        &self,
        endpoint: VerifiedEndpointBinding,
        authority: Option<Uuid>,
        path: &str,
        public_body: PublicRequest,
    ) -> Result<AccountRequestIntent, ConfigError> {
        ensure_config_root(self.paths.root())?;
        let _config = self.exclusive_lock()?;
        let mut journal = self.read_account_requests()?;
        let canonical = serialize_bounded(
            &public_body,
            ACCOUNT_REQUESTS_MAX_BYTES,
            ACCOUNT_REQUESTS_FILENAME,
        )?;
        for existing in &journal.requests {
            if existing.receipt.is_none()
                && existing.endpoint.matches(&endpoint)
                && existing.authority == authority
                && existing.path == path
                && serialize_bounded(
                    &existing.public_body,
                    ACCOUNT_REQUESTS_MAX_BYTES,
                    ACCOUNT_REQUESTS_FILENAME,
                )? == canonical
            {
                return Ok(existing.clone());
            }
        }
        if journal.requests.len() == MAX_REQUESTS {
            let completed = journal
                .requests
                .iter()
                .position(|r| r.receipt.is_some())
                .ok_or(account_conflict("too many ambiguous security requests"))?;
            journal.requests.remove(completed);
        }
        let intent = AccountRequestIntent {
            id: Uuid::new_v4(),
            authority,
            endpoint: StoredBinding::from(&endpoint),
            path: path.into(),
            public_body,
            receipt: None,
        };
        journal.requests.push(intent.clone());
        self.write_account_requests(&journal)?;
        Ok(intent)
    }
    pub(crate) fn finish_account_request(
        &self,
        id: Uuid,
        receipt: PublicReceipt,
    ) -> Result<(), ConfigError> {
        let _config = self.exclusive_lock()?;
        let mut journal = self.read_account_requests()?;
        let request = journal
            .requests
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or(account_conflict("unknown security request"))?;
        if let Some(old) = &request.receipt {
            if serialize_bounded(old, ACCOUNT_REQUESTS_MAX_BYTES, ACCOUNT_REQUESTS_FILENAME)?
                != serialize_bounded(
                    &receipt,
                    ACCOUNT_REQUESTS_MAX_BYTES,
                    ACCOUNT_REQUESTS_FILENAME,
                )?
            {
                return Err(account_conflict("security receipt changed"));
            }
        }
        request.receipt = Some(receipt);
        self.write_account_requests(&journal)
    }
    pub(crate) fn recovery_code_request(
        &self,
        id: Uuid,
        endpoint: &VerifiedEndpointBinding,
        active: bool,
    ) -> Result<Option<PublicRequest>, ConfigError> {
        let _config = self.exclusive_lock()?;
        Ok(self.read_account_requests()?.requests.into_iter().rev().find(|r|r.authority.is_none()&&r.matches(endpoint)&&(active || !matches!(r.receipt,Some(PublicReceipt::Rejected{..})))&&matches!(&r.public_body,PublicRequest::Code{candidate_id,..} if *candidate_id==id)).map(|r|r.public_body))
    }
    pub(crate) fn pending_account_requests(
        &self,
        authority: Uuid,
        endpoint: &VerifiedEndpointBinding,
    ) -> Result<Vec<AccountRequestIntent>, ConfigError> {
        let _config = self.exclusive_lock()?;
        Ok(self
            .read_account_requests()?
            .requests
            .into_iter()
            .filter(|r| {
                r.authority == Some(authority) && r.matches(endpoint) && r.receipt.is_none()
            })
            .collect())
    }
}
fn account_conflict(reason: &'static str) -> ConfigError {
    ConfigError::RecoveryIntentConflict { reason }
}

mod codes;
pub(crate) use codes::RecoveryCodeCandidate;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBinding {
    address: String,
    server_id: String,
    fingerprint: String,
}
impl From<&VerifiedEndpointBinding> for StoredBinding {
    fn from(endpoint: &VerifiedEndpointBinding) -> Self {
        Self {
            address: endpoint.address().into(),
            server_id: endpoint.server_id().into(),
            fingerprint: endpoint.server_fingerprint().into(),
        }
    }
}
impl StoredBinding {
    fn matches(&self, endpoint: &VerifiedEndpointBinding) -> bool {
        self.address == endpoint.address()
            && self.server_id == endpoint.server_id()
            && self.fingerprint == endpoint.server_fingerprint()
    }
    fn validate(&self) -> Result<(), ConfigError> {
        if normalize_address(&self.address, "$.account_requests.address")? != self.address {
            return Err(account_conflict("noncanonical security endpoint"));
        }
        validate_required_metadata("$.account_requests.server_id", &self.server_id)?;
        validate_required_metadata("$.account_requests.fingerprint", &self.fingerprint)
    }
}

#[cfg(test)]
mod tests;
