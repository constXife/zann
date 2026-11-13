use async_trait::async_trait;
use uuid::Uuid;

use zann_core::{ServiceError, ServiceResult, VaultSummary, VaultsService};

use crate::local::LocalVaultRepo;

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
}
