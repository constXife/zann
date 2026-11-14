//! Coarse native context reads and explicit selection through the local port.
use super::*;

#[derive(Debug, Clone)]
pub struct VaultContext {
    pub storages: Vec<StorageSummary>,
    pub current_storage_id: Option<String>,
    pub vaults: Vec<VaultSummary>,
    pub current_vault_id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ContextTarget {
    Storage(String),
    Vault(String),
}

#[derive(Debug, Clone)]
pub struct ContextChange {
    // These getters remain available even if selection or a subsequent read
    // fails. The shell must display the actual core selection, not guess it.
    pub storage_id: Option<String>,
    pub vault_id: Option<String>,
    pub result: Result<(VaultContext, Result<ItemsPage, String>), String>,
}

pub fn vault_context(facade: &Facade) -> Result<VaultContext, String> {
    Ok(VaultContext {
        storages: storages(facade)?,
        current_storage_id: facade.current_storage_id(),
        vaults: facade.list_vaults().map_err(|err| err.to_string())?,
        current_vault_id: facade.current_vault_id(),
    })
}

pub fn switch_context(facade: &Facade, target: ContextTarget) -> ContextChange {
    let result = match target {
        ContextTarget::Storage(id) => facade.set_current_storage(id),
        ContextTarget::Vault(id) => facade.set_current_vault(id).map(|_| ()),
    }
    .map_err(|err| err.to_string())
    .and_then(|()| {
        let context = vault_context(facade)?;
        Ok((context, items(facade, None, None)))
    });
    ContextChange {
        storage_id: facade.current_storage_id(),
        vault_id: facade.current_vault_id(),
        result,
    }
}
