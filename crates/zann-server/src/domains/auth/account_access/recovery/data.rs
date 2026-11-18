//! Recovery needs only the canonical personal key envelope for local custody
//! proof. Ordinary item synchronization starts after fresh passkey login.
use super::*;
use zann_core::{VaultEncryptionType, VaultKind, VaultMemberRole};
use zann_db::repo::{VaultMemberRepo, VaultRepo};
pub(super) async fn keys(
    state: &AppState,
    authority: &ResumeAuthority,
) -> Result<RecoveryKeyMaterial> {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        let account = AccountAccessRepo::lock_account_in(&mut tx, authority.user).await?;
        let record = RecoveryRepo::get_in(&mut tx, authority.id)
            .await?
            .ok_or(AccessError::Rejected)?;
        if !record.status.is_active_at(Utc::now()) {
            return Err(AccessError::Recovery(
                zann_db::repo::RecoveryStoreError::Ended,
            ));
        }
        if !account.active
            || account.active_recovery_id != Some(authority.id)
            || account.auth_epoch != record.status.auth_epoch
        {
            return Err(AccessError::Rejected);
        }
        if !state.config.server.personal_vaults_enabled {
            return Ok(RecoveryKeyMaterial { personal: None });
        }
        let vault = VaultRepo::get_personal_by_user_in(&mut *tx, authority.user).await?;
        let personal = if let Some(vault) = vault {
            let member = VaultMemberRepo::get_in(&mut *tx, vault.id, authority.user)
                .await?
                .ok_or(AccessError::Rejected)?;
            if member.role != VaultMemberRole::Admin {
                return Err(AccessError::Rejected);
            }
            if vault.kind != VaultKind::Personal
                || vault.encryption_type != VaultEncryptionType::Client
                || vault.vault_key_enc.len() > 65536
            {
                return Err(AccessError::Rejected);
            }
            // Personal vault membership is established only by the canonical
            // account initializer. The query never traverses shared history/items.
            if vault.vault_key_enc.is_empty() {
                None
            } else {
                Some(RecoveryKeyEnvelope {
                    vault_id: vault.id,
                    vault_key_enc: encode(&vault.vault_key_enc),
                })
            }
        } else {
            None
        };
        tx.commit().await?;
        Ok(RecoveryKeyMaterial { personal })
    })
    .await
    .map_err(|_| AccessError::Timeout)?
}
