use chrono::{TimeZone, Utc};
use zann_core::{VaultEncryptionType, VaultKind};
use zann_passkey::*;

pub fn context(site: &SiteUrl, verification: UserVerification) -> CeremonyContext<'_> {
    CeremonyContext {
        top_level: site,
        frame: site,
        cross_origin_permission: CrossOriginPermission::Denied,
        presence: UserPresence::Confirmed,
        verification,
    }
}

pub fn registration<'a>(site: &'a SiteUrl, rp: &'a RpId) -> MakeCredentialRequest<'a> {
    MakeCredentialRequest {
        client_data_hash: [42; 32],
        context: context(site, UserVerification::Verified),
        rp_id: rp,
        rp_name: "Example",
        user: UserEntity {
            id: b"synthetic-user-handle".to_vec(),
            name: "test@example.com".into(),
            display_name: "Test".into(),
        },
        algorithms: &[-7],
        exclude_credentials: &[],
        require_verification: true,
        vault_kind: VaultKind::Personal,
        encryption_type: VaultEncryptionType::Client,
        created_at: Utc.timestamp_opt(1794700800, 0).unwrap(),
    }
}

pub fn assertion<'a>(site: &'a SiteUrl, rp: &'a RpId) -> GetAssertionRequest<'a> {
    GetAssertionRequest {
        context: context(site, UserVerification::Verified),
        rp_id: rp,
        client_data_hash: [42; 32],
        allow_credentials: &[],
        require_verification: true,
    }
}
