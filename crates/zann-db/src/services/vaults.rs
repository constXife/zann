use async_trait::async_trait;
use uuid::Uuid;

use zann_core::crypto::SecretKey;
use zann_core::vault_crypto as core_crypto;
use zann_core::{ServiceError, ServiceResult, VaultKind, VaultSummary, VaultsService};

use crate::local::{LocalVault, LocalVaultRepo};

use super::LocalServices;

#[async_trait]
impl<'a> VaultsService for LocalServices<'a> {
    async fn list_vaults(&self, storage_id: Uuid) -> ServiceResult<Vec<VaultSummary>> {
        let repo = LocalVaultRepo::new(self.pool);
        let vaults = repo
            .list_by_storage(storage_id)
            .await
            .map_err(|err| ServiceError::new("vault_list_failed", err.to_string()))?;
        Ok(vaults
            .into_iter()
            .map(|vault| VaultSummary {
                id: vault.id,
                storage_id: vault.storage_id,
                name: vault.name,
                kind: vault.kind,
                is_default: vault.is_default,
            })
            .collect())
    }

    async fn get_vault_by_name(
        &self,
        storage_id: Uuid,
        name: &str,
    ) -> ServiceResult<Option<VaultSummary>> {
        let repo = LocalVaultRepo::new(self.pool);
        let vault = repo
            .get_by_name(storage_id, name)
            .await
            .map_err(|err| ServiceError::new("vault_lookup_failed", err.to_string()))?;
        Ok(vault.map(|vault| VaultSummary {
            id: vault.id,
            storage_id: vault.storage_id,
            name: vault.name,
            kind: vault.kind,
            is_default: vault.is_default,
        }))
    }

    async fn create_vault(
        &self,
        storage_id: Uuid,
        name: &str,
        kind: VaultKind,
        is_default: bool,
    ) -> ServiceResult<VaultSummary> {
        let repo = LocalVaultRepo::new(self.pool);
        let vault_key = SecretKey::generate();
        let vault_id = Uuid::now_v7();
        let payload = core_crypto::encrypt_vault_key(self.master_key, vault_id, &vault_key)
            .map_err(|err| ServiceError::new("vault_key_encrypt_failed", err.to_string()))?;
        let vault = LocalVault {
            id: vault_id,
            storage_id,
            name: name.to_string(),
            kind,
            is_default,
            vault_key_enc: payload,
            key_wrap_type: crate::local::KeyWrapType::Master,
            last_synced_at: None,
        };
        repo.create(&vault)
            .await
            .map_err(|err| ServiceError::new("vault_create_failed", err.to_string()))?;
        Ok(VaultSummary {
            id: vault.id,
            storage_id: vault.storage_id,
            name: vault.name,
            kind: vault.kind,
            is_default: vault.is_default,
        })
    }

    async fn ensure_default_local_personal(&self) -> ServiceResult<VaultSummary> {
        let repo = LocalVaultRepo::new(self.pool);
        let storage_id = Uuid::nil();
        if let Some(existing) = repo
            .get_by_name(storage_id, "Personal (Local)")
            .await
            .map_err(|err| ServiceError::new("vault_lookup_failed", err.to_string()))?
        {
            return Ok(VaultSummary {
                id: existing.id,
                storage_id: existing.storage_id,
                name: existing.name,
                kind: existing.kind,
                is_default: existing.is_default,
            });
        }
        self.create_vault(storage_id, "Personal (Local)", VaultKind::Personal, true)
            .await
    }
}
