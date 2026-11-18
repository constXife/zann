//! Private adapter over the selected verifier; extension origins require its core API.
use super::{AccessError, Result};
use std::time::Duration;
use uuid::Uuid;
use webauthn_rs_core::{proto::*, WebauthnCore};
use zann_core::api::account_access::{
    CeremonyOptions, CeremonyPhase, CeremonyResponse, CHALLENGE_SECONDS,
};
use zann_crypto::account_access::{decode, encode, prf_input};

pub(super) struct RelyingParty {
    core: WebauthnCore,
    server_id: String,
    rp_id: String,
    rp_name: String,
}

impl RelyingParty {
    pub fn new(config: &crate::config::PasskeyConfig, server_id: String) -> Result<Self> {
        let origins = config.validate().map_err(AccessError::Configuration)?;
        Ok(Self {
            core: WebauthnCore::new_unsafe_experts_only(
                &config.rp_name,
                &config.rp_id,
                origins,
                Duration::from_secs(CHALLENGE_SECONDS as u64),
                Some(false),
                Some(false),
            ),
            server_id,
            rp_id: config.rp_id.clone(),
            rp_name: config.rp_name.clone(),
        })
    }
    pub fn registration(
        &self,
        id: Uuid,
        user: Uuid,
        name: &str,
        exclude: Vec<Credential>,
    ) -> Result<(CeremonyOptions, RegistrationState)> {
        let builder = self
            .core
            .new_challenge_register_builder(user.as_bytes(), name, name)?
            .attestation(AttestationConveyancePreference::None)
            .user_verification_policy(UserVerificationPolicy::Required)
            .require_resident_key(true)
            .credential_algorithms(vec![COSEAlgorithm::ES256])
            .exclude_credentials(Some(exclude.into_iter().map(|c| c.cred_id).collect()));
        let (response, state) = self.core.generate_challenge_register(builder)?;
        let options = CeremonyOptions {
            operation_id: id,
            phase: CeremonyPhase::Register,
            challenge: encode(response.public_key.challenge.as_ref()),
            rp_id: self.rp_id.clone(),
            rp_name: self.rp_name.clone(),
            user_id: Some(user),
            user_name: Some(name.into()),
            credential_ids: response
                .public_key
                .exclude_credentials
                .unwrap_or_default()
                .into_iter()
                .map(|c| encode(c.id.as_ref()))
                .collect(),
            prf_input: encode(&prf_input(&self.server_id, &self.rp_id)?),
        };
        Ok((options, state))
    }
    pub fn assertion(
        &self,
        id: Uuid,
        phase: CeremonyPhase,
        credentials: Vec<Credential>,
    ) -> Result<(CeremonyOptions, AuthenticationState)> {
        let builder = self.core.new_challenge_authenticate_builder(
            credentials,
            Some(UserVerificationPolicy::Required),
        )?;
        let (response, state) = self.core.generate_challenge_authenticate(builder)?;
        // Candidate testing is discoverable too: an allow-list test cannot establish
        // that a newly enrolled resident credential is usable in ordinary login.
        let ids = if phase == CeremonyPhase::Test || phase == CeremonyPhase::Login {
            Vec::new()
        } else {
            response
                .public_key
                .allow_credentials
                .into_iter()
                .map(|c| encode(c.id.as_ref()))
                .collect()
        };
        Ok((
            CeremonyOptions {
                operation_id: id,
                phase,
                challenge: encode(response.public_key.challenge.as_ref()),
                rp_id: self.rp_id.clone(),
                rp_name: self.rp_name.clone(),
                user_id: None,
                user_name: None,
                credential_ids: ids,
                prf_input: encode(&prf_input(&self.server_id, &self.rp_id)?),
            },
            state,
        ))
    }
    pub fn finish_registration(
        &self,
        response: &CeremonyResponse,
        state: &RegistrationState,
    ) -> Result<Credential> {
        let CeremonyResponse::Register {
            credential_id,
            client_data_json,
            attestation_object,
        } = response
        else {
            return Err(AccessError::Rejected);
        };
        let id = decode(credential_id, 1024)?;
        if id.is_empty() {
            return Err(AccessError::Rejected);
        }
        let input = RegisterPublicKeyCredential {
            id: credential_id.clone(),
            raw_id: id.clone(),
            type_: "public-key".into(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: decode(attestation_object, 32768)?,
                client_data_json: decode(client_data_json, 8192)?,
                transports: None,
            },
            extensions: Default::default(),
        };
        let credential = self.core.register_credential(&input, state, None)?;
        if credential.cred_id.as_slice() != id.as_slice()
            || !credential.user_verified
            || credential.cred.type_ != COSEAlgorithm::ES256
            || credential.attestation_format != AttestationFormat::None
        {
            return Err(AccessError::Rejected);
        }
        Ok(credential)
    }
    pub fn finish_assertion(
        &self,
        response: &CeremonyResponse,
        mut state: AuthenticationState,
        mut credential: Credential,
        user: Uuid,
        discoverable: bool,
    ) -> Result<Credential> {
        let CeremonyResponse::Assertion {
            credential_id,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
        } = response
        else {
            return Err(AccessError::Rejected);
        };
        let raw_id = decode(credential_id, 1024)?;
        if raw_id.is_empty() || raw_id.as_slice() != credential.cred_id.as_slice() {
            return Err(AccessError::Rejected);
        }
        let handle = user_handle.as_deref().map(|v| decode(v, 16)).transpose()?;
        if (discoverable && handle.is_none())
            || handle
                .as_deref()
                .is_some_and(|value| value != user.as_bytes())
        {
            return Err(AccessError::Rejected);
        }
        state.set_allowed_credentials(vec![credential.clone()]);
        let input = PublicKeyCredential {
            id: credential_id.clone(),
            raw_id,
            type_: "public-key".into(),
            extensions: Default::default(),
            response: AuthenticatorAssertionResponseRaw {
                client_data_json: decode(client_data_json, 8192)?,
                authenticator_data: decode(authenticator_data, 8192)?,
                signature: decode(signature, 1024)?,
                user_handle: handle,
            },
        };
        let result = self.core.authenticate_credential(&input, &state)?;
        if !result.user_verified() {
            return Err(AccessError::Rejected);
        }
        credential.counter = result.counter();
        credential.backup_eligible = result.backup_eligible();
        credential.backup_state = result.backup_state();
        Ok(credential)
    }
}
