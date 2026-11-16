use chrono::{DateTime, Utc};
use zann_core::{item_policy::admit_item_type, VaultEncryptionType, VaultKind};
use zann_crypto::es256::{sha256, Es256Key};

use crate::{
    credential, encoding, Credential, CrossOriginPermission, PasskeyError, RpId, SiteUrl,
    UserEntity, PASSKEY_ALGORITHM, PASSKEY_TYPE_ID,
};

pub const MAX_CANDIDATES: usize = 200;
pub const MAX_CREDENTIAL_LIST: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserPresence {
    Absent,
    Confirmed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserVerification {
    NotPerformed,
    Verified,
}

/// Trusted adapter evidence for THIS request, not the vault's unlocked state.
/// Providers must bind this to one operation and consume their presence proof.
pub struct CeremonyContext<'a> {
    pub top_level: &'a SiteUrl,
    pub frame: &'a SiteUrl,
    pub cross_origin_permission: CrossOriginPermission,
    pub presence: UserPresence,
    pub verification: UserVerification,
}

pub struct MakeCredentialRequest<'a> {
    pub context: CeremonyContext<'a>,
    /// Required CTAP clientDataHash. With `none` attestation it is not signed;
    /// the provider binds the browser challenge to this request/confirmation.
    pub client_data_hash: [u8; 32],
    pub rp_id: &'a RpId,
    pub rp_name: &'a str,
    pub user: UserEntity,
    pub algorithms: &'a [i32],
    pub exclude_credentials: &'a [&'a [u8]],
    pub require_verification: bool,
    pub vault_kind: VaultKind,
    pub encryption_type: VaultEncryptionType,
    pub created_at: DateTime<Utc>,
}

pub struct GetAssertionRequest<'a> {
    pub context: CeremonyContext<'a>,
    pub rp_id: &'a RpId,
    /// Computed by the trusted browser/OS from its clientDataJSON.
    pub client_data_hash: [u8; 32],
    pub allow_credentials: &'a [&'a [u8]],
    pub require_verification: bool,
}

/// Safe for a provider response; deliberately excludes the local private key.
pub struct RegistrationResponse {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

pub struct Registration {
    pub credential: Credential,
    pub response: RegistrationResponse,
}

pub struct AssertionResponse {
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
}

/// `existing` must contain every local credential matching the RP/exclusion
/// lookup. Never pass a silently truncated page: storage admission must reject
/// an incomplete lookup before requesting confirmation or generating a key.
pub fn make_credential(
    request: MakeCredentialRequest<'_>,
    existing: &[Credential],
) -> Result<Registration, PasskeyError> {
    admit_item_type(PASSKEY_TYPE_ID, request.vault_kind, request.encryption_type)
        .map_err(PasskeyError::Vault)?;
    authorize(
        &request.context,
        request.rp_id,
        request.require_verification,
    )?;
    bounded_candidates(existing)?;
    validate_list(request.exclude_credentials)?;
    if request.algorithms.is_empty() || request.algorithms.len() > MAX_CREDENTIAL_LIST {
        return Err(PasskeyError::Input);
    }
    if !request.algorithms.contains(&PASSKEY_ALGORITHM) {
        return Err(PasskeyError::Algorithm);
    }
    credential::validate_user(&request.user)?;
    credential::validate_label(request.rp_name)?;
    if existing.iter().any(|credential| {
        credential.rp_id == *request.rp_id
            && request
                .exclude_credentials
                .contains(&credential.id.as_slice())
    }) {
        return Err(PasskeyError::Excluded);
    }
    let key = Es256Key::generate().map_err(PasskeyError::Crypto)?;
    // Credential identifiers are independent of the signing scalar.
    let id = zann_crypto::es256::credential_id().map_err(PasskeyError::Crypto)?;
    let credential = Credential {
        exchange_metadata: None,
        rp_id: request.rp_id.clone(),
        rp_name: request.rp_name.into(),
        id: id.to_vec(),
        user: request.user,
        key,
        created_at: Some(request.created_at),
    };
    let mut auth_data = authenticator_data(request.rp_id, &request.context, true);
    auth_data.extend_from_slice(&[0; 16]); // none attestation: anonymous AAGUID
    auth_data.extend_from_slice(&(credential.id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(&credential.id);
    auth_data.extend(encoding::cose_public_key(&credential.public_key())?);
    let attestation_object = encoding::none_attestation(&auth_data)?;
    Ok(Registration {
        response: RegistrationResponse {
            credential_id: credential.id.clone(),
            authenticator_data: auth_data,
            attestation_object,
        },
        credential,
    })
}

/// Returns indices only; candidates remain local. The caller supplies one
/// bounded, vault-scoped page and owns pagination/selection before signing.
pub fn select_credentials(
    request: &GetAssertionRequest<'_>,
    candidates: &[Credential],
) -> Result<Vec<usize>, PasskeyError> {
    authorize(
        &request.context,
        request.rp_id,
        request.require_verification,
    )?;
    validate_list(request.allow_credentials)?;
    bounded_candidates(candidates)?;
    Ok(candidates
        .iter()
        .enumerate()
        .filter_map(|(index, credential)| matches(request, credential).then_some(index))
        .collect())
}

/// Strictly read-only: no timestamps, counters, payload mutation or persistence.
pub fn get_assertion(
    request: &GetAssertionRequest<'_>,
    credential: &Credential,
) -> Result<AssertionResponse, PasskeyError> {
    authorize(
        &request.context,
        request.rp_id,
        request.require_verification,
    )?;
    validate_list(request.allow_credentials)?;
    if !matches(request, credential) {
        return Err(PasskeyError::NoCredential);
    }
    let auth_data = authenticator_data(request.rp_id, &request.context, false);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&request.client_data_hash);
    let signature = credential.key.sign(&signed).map_err(PasskeyError::Crypto)?;
    Ok(AssertionResponse {
        credential_id: credential.id.clone(),
        user_handle: credential.user.id.clone(),
        authenticator_data: auth_data,
        signature,
    })
}

fn matches(request: &GetAssertionRequest<'_>, credential: &Credential) -> bool {
    credential.rp_id == *request.rp_id
        && (request.allow_credentials.is_empty()
            || request
                .allow_credentials
                .contains(&credential.id.as_slice()))
}

fn authorize(
    context: &CeremonyContext<'_>,
    rp_id: &RpId,
    require_verification: bool,
) -> Result<(), PasskeyError> {
    rp_id
        .authorize(
            context.top_level,
            context.frame,
            context.cross_origin_permission,
        )
        .map_err(PasskeyError::Origin)?;
    if context.presence != UserPresence::Confirmed {
        return Err(PasskeyError::Presence);
    }
    if require_verification && context.verification != UserVerification::Verified {
        return Err(PasskeyError::Verification);
    }
    Ok(())
}

fn authenticator_data(rp_id: &RpId, context: &CeremonyContext<'_>, attested: bool) -> Vec<u8> {
    let mut bytes = sha256(rp_id.as_str().as_bytes()).to_vec();
    let mut flags = 0x01 | 0x08 | 0x10; // UP, BE, BS: synced multi-device credential
    if context.verification == UserVerification::Verified {
        flags |= 0x04;
    }
    if attested {
        flags |= 0x40;
    }
    bytes.push(flags);
    bytes.extend_from_slice(&0u32.to_be_bytes()); // permanent zero signCount
    bytes
}

fn validate_list(ids: &[&[u8]]) -> Result<(), PasskeyError> {
    if ids.len() > MAX_CREDENTIAL_LIST {
        return Err(PasskeyError::Input);
    }
    ids.iter().try_for_each(|id| credential::validate_id(id))
}
fn bounded_candidates(candidates: &[Credential]) -> Result<(), PasskeyError> {
    if candidates.len() > MAX_CANDIDATES {
        return Err(PasskeyError::Input);
    }
    Ok(())
}
