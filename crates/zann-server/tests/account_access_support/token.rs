//! In-memory, synthetic UV token using the existing provider ceremony owner.
//! This exercises RP verification; it is not hardware/PRF qualification evidence.
use zann_core::{
    api::account_access::{CeremonyOptions, CeremonyResponse},
    VaultEncryptionType, VaultKind,
};
use zann_crypto::account_access::encode;
use zann_passkey::*;
pub struct Token {
    credential: Credential,
}
fn client_data(kind: &str, options: &CeremonyOptions, origin: &str, cross_origin: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"type":kind,"challenge":options.challenge,"origin":origin,"crossOrigin":cross_origin})).expect("synthetic client data")
}
fn context(site: &SiteUrl, uv: bool) -> CeremonyContext<'_> {
    CeremonyContext {
        top_level: site,
        frame: site,
        cross_origin_permission: CrossOriginPermission::Denied,
        presence: UserPresence::Confirmed,
        verification: if uv {
            UserVerification::Verified
        } else {
            UserVerification::NotPerformed
        },
    }
}
impl Token {
    pub fn register(options: &CeremonyOptions, origin: &str, uv: bool) -> (Self, CeremonyResponse) {
        let site = SiteUrl::parse(&format!("https://{}/", options.rp_id)).expect("synthetic site");
        let rp = RpId::parse(&options.rp_id).expect("RP");
        let data = client_data("webauthn.create", options, origin, false);
        let name = options.user_name.as_deref().expect("user name");
        let registration = make_credential(
            MakeCredentialRequest {
                context: context(&site, uv),
                client_data_hash: zann_crypto::es256::sha256(&data),
                rp_id: &rp,
                rp_name: &options.rp_name,
                user: UserEntity {
                    id: options.user_id.expect("user ID").as_bytes().to_vec(),
                    name: name.into(),
                    display_name: name.into(),
                },
                algorithms: &[-7],
                exclude_credentials: &[],
                require_verification: false,
                vault_kind: VaultKind::Personal,
                encryption_type: VaultEncryptionType::Client,
                created_at: chrono::Utc::now(),
            },
            &[],
        )
        .expect("synthetic registration");
        let response = CeremonyResponse::Register {
            credential_id: encode(&registration.response.credential_id),
            client_data_json: encode(&data),
            attestation_object: encode(&registration.response.attestation_object),
        };
        (
            Self {
                credential: registration.credential,
            },
            response,
        )
    }
    pub fn assert(
        &self,
        options: &CeremonyOptions,
        origin: &str,
        uv: bool,
        cross_origin: bool,
    ) -> CeremonyResponse {
        let site = SiteUrl::parse(&format!("https://{}/", options.rp_id)).expect("synthetic site");
        let rp = RpId::parse(&options.rp_id).expect("RP");
        let data = client_data("webauthn.get", options, origin, cross_origin);
        let request = GetAssertionRequest {
            context: context(&site, uv),
            rp_id: &rp,
            client_data_hash: zann_crypto::es256::sha256(&data),
            allow_credentials: &[],
            require_verification: false,
        };
        let response = get_assertion(&request, &self.credential).expect("synthetic assertion");
        CeremonyResponse::Assertion {
            credential_id: encode(&response.credential_id),
            client_data_json: encode(&data),
            authenticator_data: encode(&response.authenticator_data),
            signature: encode(&response.signature),
            user_handle: Some(encode(&response.user_handle)),
        }
    }
}
