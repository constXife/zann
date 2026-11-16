//! One confirmed operation: prepare, commit, then deliver under the context lease.
use super::*;

impl LocalVault {
    pub fn passkey_ceremony(
        &self,
        request: PasskeyRequest,
        scope: BrowserScope,
        selected: Option<String>,
        sink: &mut dyn FnMut(PasskeyResponse) -> LocalResult<()>,
    ) -> LocalResult<()> {
        let rp = request.validate().map_err(policy)?;
        let (top, frame) = request.context.credential_context().map_err(policy)?;
        let hash = request.client_data_hash().map_err(policy)?;
        let client_data_json = B64.encode(request.client_data().map_err(policy)?);
        let _context = self.context_gate.read().expect("context");
        let key = self.account_key()?;
        if self.passkey_scope()? != scope {
            return Err(policy("passkey selection changed"));
        }
        let pool = self.pool();
        let services = LocalServices::new(&pool, key.as_ref());
        let response = self.runtime.block_on(async {
            // Preparation is cancellable; once commit begins it is awaited under
            // the context lease. A lost response is ambiguous and never replayed.
            let preparation = tokio::time::timeout(std::time::Duration::from_secs(2), async {
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
                    let mut credentials = Vec::new();
                    let mut selected_index = None;
                    for (item, payload) in rows {
                        if selected.as_deref() == Some(&item.id.to_string()) {
                            selected_index = Some(credentials.len());
                        }
                        let credential = pk::Credential::from_payload(&payload).map_err(policy)?;
                        if credential.rp_id() != &rp {
                            return Err(policy("passkey index mismatch"));
                        }
                        credentials.push(credential);
                    }
                    let context = pk::CeremonyContext {
                        top_level: &top,
                        frame: &frame,
                        cross_origin_permission: pk::CrossOriginPermission::Denied,
                        presence: pk::UserPresence::Confirmed,
                        verification: pk::UserVerification::NotPerformed,
                    };
                    let mut response = PasskeyResponse {
                        credential_id: String::new(),
                        client_data_json: client_data_json.clone(),
                        authenticator_data: String::new(),
                        attestation_object: None,
                        public_key_spki: None,
                        signature: None,
                        user_handle: None,
                    };
                    match &request.operation {
                        PasskeyOperation::Create {
                            rp_name,
                            user_id,
                            user_name,
                            user_display_name,
                            algorithms,
                            exclude_credentials,
                        } => {
                            if selected.is_some() {
                                return Err(policy("unexpected passkey selection"));
                            }
                            let excluded = decode_ids(exclude_credentials)?;
                            let refs: Vec<_> = excluded.iter().map(Vec::as_slice).collect();
                            let registration = pk::make_credential(
                                pk::MakeCredentialRequest {
                                    context,
                                    client_data_hash: hash,
                                    rp_id: &rp,
                                    rp_name,
                                    user: pk::UserEntity {
                                        id: decode(user_id, 64).map_err(policy)?,
                                        name: user_name.clone(),
                                        display_name: user_display_name.clone(),
                                    },
                                    algorithms,
                                    exclude_credentials: &refs,
                                    require_verification: request.require_verification,
                                    vault_kind: batch.vault().kind,
                                    encryption_type: zann_core::VaultEncryptionType::Client,
                                    created_at: chrono::Utc::now(),
                                },
                                &credentials,
                            )
                            .map_err(policy)?;
                            let path = format!("Passkeys/{}", Uuid::now_v7());
                            batch
                                .add(
                                    path,
                                    "passkey".into(),
                                    registration.credential.to_payload().map_err(policy)?,
                                    zann_core::ItemMetadata::default(),
                                )
                                .await
                                .map_err(policy)?;
                            response.public_key_spki =
                                Some(B64.encode(registration.response.public_key_spki));
                            response.credential_id =
                                B64.encode(registration.response.credential_id);
                            response.authenticator_data =
                                B64.encode(registration.response.authenticator_data);
                            response.attestation_object =
                                Some(B64.encode(registration.response.attestation_object));
                        }
                        PasskeyOperation::Get { allow_credentials } => {
                            let index = selected_index
                                .ok_or_else(|| policy(pk::PasskeyError::NoCredential))?;
                            let allowed = decode_ids(allow_credentials)?;
                            let refs: Vec<_> = allowed.iter().map(Vec::as_slice).collect();
                            let assertion = pk::get_assertion(
                                &pk::GetAssertionRequest {
                                    context,
                                    rp_id: &rp,
                                    client_data_hash: hash,
                                    allow_credentials: &refs,
                                    require_verification: request.require_verification,
                                },
                                &credentials[index],
                            )
                            .map_err(policy)?;
                            response.credential_id = B64.encode(assertion.credential_id);
                            response.authenticator_data = B64.encode(assertion.authenticator_data);
                            response.signature = Some(B64.encode(assertion.signature));
                            response.user_handle = Some(B64.encode(assertion.user_handle));
                        }
                    }
                    Ok(response)
                }
                .await;
                match result {
                    Ok(response) => Ok((batch, response)),
                    Err(error) => Err(batch.rollback_for_error(error).await.map_err(policy)?),
                }
            })
            .await
            .map_err(|_| LocalError::DeadlineExceeded)??;
            let (batch, response) = preparation;
            batch.commit().await.map_err(policy)?;
            Ok::<_, LocalError>(response)
        })?;
        sink(response)
    }
}
