//! Browser ceremonies retain native context through commit and encrypted delivery.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use passkey_engine as pk;
use zann_client::browser_ipc::{passkey::decode, PasskeyCandidate, PasskeyOperation};
use zann_db::services::PreparedItemBatch;
mod ceremony;

fn policy(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> LocalError {
    LocalError::BrowserPolicy(error.into())
}
impl LocalVault {
    fn passkey_scope(&self) -> LocalResult<BrowserScope> {
        Ok(BrowserScope {
            storage_id: self.storage_id()?.to_string(),
            vault_id: self.vault_id()?.to_string(),
            generation: self.context_generation.load(Ordering::SeqCst),
        })
    }
    pub fn passkey_query(
        &self,
        request: PasskeyRequest,
        sink: &mut dyn FnMut(PasskeyMatches) -> LocalResult<()>,
    ) -> LocalResult<()> {
        let rp = request.validate().map_err(policy)?;
        let _context = self.context_gate.read().expect("context");
        let key = self.account_key()?;
        let scope = self.passkey_scope()?;
        let pool = self.pool();
        let services = LocalServices::new(&pool, key.as_ref());
        let items = self.runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                let mut batch = services
                    .begin_item_batch(self.storage_id()?, self.vault_id()?)
                    .await
                    .map_err(policy)?;
                let result = async {
                    admit(&batch)?;
                    let rows = batch
                        .read_passkeys(rp.as_str(), pk::exchange::MAX_EXCHANGE_ENTRIES)
                        .await
                        .map_err(policy)?;
                    let mut items = Vec::new();
                    for (item, payload) in rows {
                        let credential = pk::Credential::from_payload(&payload).map_err(policy)?;
                        if credential.rp_id() != &rp {
                            return Err(policy("passkey index mismatch"));
                        }
                        match &request.operation {
                            PasskeyOperation::Create {
                                exclude_credentials,
                                ..
                            } => {
                                if contains(exclude_credentials, credential.credential_id())? {
                                    return Err(policy(pk::PasskeyError::Excluded));
                                }
                            }
                            PasskeyOperation::Get { allow_credentials } => {
                                if allow_credentials.is_empty()
                                    || contains(allow_credentials, credential.credential_id())?
                                {
                                    items.push(PasskeyCandidate {
                                        item_id: item.id.to_string(),
                                        title: item.name,
                                        user_name: payload.fields["user_name"].value.clone(),
                                        user_display_name: payload.fields["user_display_name"]
                                            .value
                                            .clone(),
                                    });
                                }
                            }
                        }
                    }
                    Ok(items)
                }
                .await;
                match result {
                    Ok(items) => {
                        batch.commit().await.map_err(policy)?;
                        Ok(items)
                    }
                    Err(error) => Err(batch.rollback_for_error(error).await.map_err(policy)?),
                }
            })
            .await
            .map_err(|_| LocalError::DeadlineExceeded)?
        })?;
        sink(PasskeyMatches { scope, items })
    }
}

fn contains(ids: &[String], id: &[u8]) -> LocalResult<bool> {
    Ok(decode_ids(ids)?.iter().any(|v| v == id))
}
fn decode_ids(ids: &[String]) -> LocalResult<Vec<Vec<u8>>> {
    ids.iter()
        .map(|id| decode(id, 1023).map_err(policy))
        .collect()
}
fn admit(batch: &PreparedItemBatch) -> LocalResult<()> {
    // Eligibility is checked before any candidate is decrypted.
    zann_core::item_policy::admit_item_type(
        "passkey",
        batch.vault().kind,
        if batch.vault().key_wrap_type == zann_db::local::KeyWrapType::RemoteServer {
            zann_core::VaultEncryptionType::Server
        } else {
            zann_core::VaultEncryptionType::Client
        },
    )
    .map_err(policy)
}

#[cfg(test)]
mod tests;
