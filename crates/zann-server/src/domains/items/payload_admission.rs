//! Shared payloads are server-readable; personal ciphertext stays opaque.
use crate::domains::errors::ServiceError;
use uuid::Uuid;
use zann_core::{Vault, VaultEncryptionType};
use zann_crypto::{decrypt_payload, decrypt_vault_key, SecretKey, VaultCryptoError};

pub(crate) fn ensure_supported(
    vault: &Vault,
    server_master_key: Option<&SecretKey>,
    item_id: Uuid,
    ciphertext: &[u8],
) -> Result<(), ServiceError> {
    if vault.encryption_type == VaultEncryptionType::Client {
        return Ok(());
    }
    let smk = server_master_key.ok_or(ServiceError::Internal("smk_missing"))?;
    let key = decrypt_vault_key(smk, vault.id, &vault.vault_key_enc)
        .map_err(|error| ServiceError::Internal(error.as_code()))?;
    admit(&key, vault.id, item_id, ciphertext)
}

pub(crate) fn admit(
    key: &SecretKey,
    vault_id: Uuid,
    item_id: Uuid,
    ciphertext: &[u8],
) -> Result<(), ServiceError> {
    let payload =
        decrypt_payload(key, vault_id, item_id, ciphertext).map_err(|error| match error {
            VaultCryptoError::UnsupportedPayloadVersion(_) => {
                ServiceError::Conflict("unsupported_payload_version")
            }
            _ => ServiceError::Internal(error.as_code()),
        })?;
    zann_core::item_policy::admit_item_type(
        &payload.type_id,
        zann_core::VaultKind::Shared,
        VaultEncryptionType::Server,
    )
    .map_err(|_| ServiceError::Conflict("passkey_personal_only"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn personal_payload_is_opaque_even_without_a_server_master_key() {
        let vault = Vault {
            id: Uuid::now_v7(),
            slug: "personal".into(),
            name: "Personal".into(),
            kind: zann_core::VaultKind::Personal,
            encryption_type: VaultEncryptionType::Client,
            vault_key_enc: vec![0xff],
            cache_policy: zann_core::CachePolicy::Full,
            tags: None,
            deleted_at: None,
            deleted_by_user_id: None,
            deleted_by_device_id: None,
            row_version: 1,
            created_at: chrono::Utc::now(),
        };
        assert!(ensure_supported(&vault, None, Uuid::now_v7(), b"opaque bytes").is_ok());
    }

    #[test]
    fn future_shared_payload_is_refused_before_a_mutation_can_commit() {
        let key = SecretKey::generate();
        let vault = Uuid::now_v7();
        let item = Uuid::now_v7();
        let ciphertext = zann_crypto::encrypt_payload_bytes(
            &key,
            vault,
            item,
            br#"{"fields":{"value":{"kind":"future-kind"}},"v":2}"#,
        )
        .expect("future fixture");
        assert!(matches!(
            admit(&key, vault, item, &ciphertext),
            Err(ServiceError::Conflict("unsupported_payload_version"))
        ));
        let current = zann_crypto::encrypt_payload(
            &key,
            vault,
            item,
            &zann_crypto::EncryptedPayload::new("login"),
        )
        .expect("current fixture");
        assert!(admit(&key, vault, item, &current).is_ok());
    }

    #[test]
    fn shared_passkey_payloads_are_refused_including_history_admission() {
        let key = SecretKey::generate();
        let vault = Uuid::now_v7();
        let item = Uuid::now_v7();
        let payload = zann_crypto::EncryptedPayload::new("passkey");
        let ciphertext = zann_crypto::encrypt_payload(&key, vault, item, &payload)
            .expect("encrypt shared fixture");
        assert!(matches!(
            admit(&key, vault, item, &ciphertext),
            Err(ServiceError::Conflict("passkey_personal_only"))
        ));
        assert_eq!(
            super::super::contract::validate_server_typed_payload(&payload, "passkey")
                .expect_err("shared passkey must be refused")
                .code(),
            "passkey_personal_only"
        );
    }
}
