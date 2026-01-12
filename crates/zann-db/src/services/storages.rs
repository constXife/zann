use async_trait::async_trait;
use uuid::Uuid;

use zann_core::{ServiceError, ServiceResult, StorageSummary, StoragesService};

use crate::local::LocalStorageRepo;

use super::LocalServices;

#[async_trait]
impl<'a> StoragesService for LocalServices<'a> {
    async fn list_storages(&self) -> ServiceResult<Vec<StorageSummary>> {
        let repo = LocalStorageRepo::new(self.pool);
        let rows = repo
            .list()
            .await
            .map_err(|err| ServiceError::new("storage_list_failed", err.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|storage| StorageSummary {
                id: storage.id,
                name: storage.name,
                kind: storage.kind,
                server_url: storage.server_url,
                server_name: storage.server_name,
                account_subject: storage.account_subject,
                personal_vaults_enabled: storage.personal_vaults_enabled,
                auth_method: storage.auth_method,
            })
            .collect())
    }

    async fn get_storage(&self, storage_id: Uuid) -> ServiceResult<StorageSummary> {
        let repo = LocalStorageRepo::new(self.pool);
        let storage = repo
            .get(storage_id)
            .await
            .map_err(|err| ServiceError::new("storage_lookup_failed", err.to_string()))?
            .ok_or_else(|| ServiceError::new("storage_not_found", "storage not found"))?;
        Ok(StorageSummary {
            id: storage.id,
            name: storage.name,
            kind: storage.kind,
            server_url: storage.server_url,
            server_name: storage.server_name,
            account_subject: storage.account_subject,
            personal_vaults_enabled: storage.personal_vaults_enabled,
            auth_method: storage.auth_method,
        })
    }

    fn default_storage_id(&self) -> Uuid {
        Uuid::nil()
    }
}
