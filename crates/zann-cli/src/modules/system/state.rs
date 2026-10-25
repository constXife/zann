//! CLI selection state projected from the canonical configuration repository.

use std::collections::BTreeMap;
use std::sync::Arc;
use zann_client::config::{
    ClientId, ClientNamespace, ConfigRepository, ConnectionId, CredentialStore,
};
use zann_client::credentials::{OsCredentialStore, OsLegacyCredentialSource};

pub struct ContextView {
    pub id: ConnectionId,
    pub addr: String,
    pub server_fingerprint: Option<String>,
    pub current_token: Option<String>,
    pub tokens: Vec<String>,
    pub vault: Option<String>,
}
pub struct CliState {
    pub repository: ConfigRepository,
    pub credentials: Arc<dyn CredentialStore>,
    pub client_id: ClientId,
    pub current_context: Option<String>,
    pub contexts: BTreeMap<String, ContextView>,
}
impl CliState {
    pub fn open(root: std::path::PathBuf) -> anyhow::Result<Self> {
        let repository = ConfigRepository::new(zann_client::config::ClientPaths::new(root));
        let credentials = Arc::new(OsCredentialStore::system_default());
        let client_id = ClientId::new("cli")?;
        repository.initialize(
            &client_id,
            credentials.as_ref(),
            &OsLegacyCredentialSource::system_default(),
        )?;
        Self::from_repository(repository, credentials, client_id)
    }
    pub fn from_repository(
        repository: ConfigRepository,
        credentials: Arc<dyn CredentialStore>,
        client_id: ClientId,
    ) -> anyhow::Result<Self> {
        let mut state = Self {
            repository,
            credentials,
            client_id,
            current_context: None,
            contexts: BTreeMap::new(),
        };
        state.reload()?;
        Ok(state)
    }
    pub fn reload(&mut self) -> anyhow::Result<()> {
        let snapshot = self.repository.snapshot()?;
        let config = snapshot.config();
        let client = config.clients.get(&self.client_id);
        let active = client.and_then(|client| client.active_connection());
        let vaults = client.and_then(|client| match client.namespace() {
            ClientNamespace::CliV1(namespace) => Some(&namespace.default_vault_by_connection),
            _ => None,
        });
        let mut contexts = BTreeMap::new();
        let mut current = None;
        for (id, connection) in &config.connections {
            let metadata = connection.metadata();
            if active == Some(id) {
                current = Some(metadata.name.clone());
            }
            if contexts
                .insert(
                    metadata.name.clone(),
                    ContextView {
                        id: id.clone(),
                        addr: metadata.address.clone(),
                        server_fingerprint: metadata.server_fingerprint.clone(),
                        current_token: connection.active_credential().map(str::to_string),
                        tokens: connection.credential_profiles().keys().cloned().collect(),
                        vault: vaults.and_then(|vaults| vaults.get(id)).cloned(),
                    },
                )
                .is_some()
            {
                anyhow::bail!("ambiguous connection name: {}", metadata.name);
            }
        }
        self.contexts = contexts;
        self.current_context = current;
        Ok(())
    }
    pub fn selected_name(&self, name: Option<String>) -> anyhow::Result<String> {
        name.or_else(|| self.current_context.clone())
            .ok_or_else(|| anyhow::anyhow!("context not set"))
    }
    pub fn context(&self, name: &str) -> anyhow::Result<&ContextView> {
        self.contexts
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("context not found: {name}"))
    }
}
