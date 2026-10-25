use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigIdentity {
    pub kdf_salt: String,
    pub kdf_params: ConfigKdfParams,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigKdfParams {
    pub algorithm: String,
    pub iterations: u32,
    pub memory_kb: u32,
    pub parallelism: u32,
}

impl From<KdfParams> for ConfigKdfParams {
    fn from(params: KdfParams) -> Self {
        Self {
            algorithm: params.algorithm,
            iterations: params.iterations,
            memory_kb: params.memory_kb,
            parallelism: params.parallelism,
        }
    }
}

impl From<ConfigKdfParams> for KdfParams {
    fn from(params: ConfigKdfParams) -> Self {
        Self {
            algorithm: params.algorithm,
            iterations: params.iterations,
            memory_kb: params.memory_kb,
            parallelism: params.parallelism,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) active_connection: Option<ConnectionId>,
    #[serde(default)]
    pub(super) namespace: ClientNamespace,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            active_connection: None,
            namespace: ClientNamespace::Empty,
        }
    }
}

impl ClientConfig {
    pub fn active_connection(&self) -> Option<&ConnectionId> {
        self.active_connection.as_ref()
    }

    pub fn namespace(&self) -> &ClientNamespace {
        &self.namespace
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "settings",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ClientNamespace {
    #[default]
    Empty,
    CliV1(CliNamespace),
    DesktopV1(DesktopNamespace),
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CliNamespace {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub default_vault_by_connection: BTreeMap<ConnectionId, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopNamespace {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<DesktopBackupSettings>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopBackupSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_retention_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_max_count: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionConfig {
    pub(super) metadata: ConnectionMetadata,
    #[serde(default)]
    pub(super) credential_profiles: BTreeMap<String, CredentialProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) active_credential: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionMetadata {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub needs_salt_update: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_master_key_fp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_id: Option<String>,
}

impl ConnectionMetadata {
    pub fn new(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            address: address.into(),
            needs_salt_update: false,
            server_id: None,
            server_fingerprint: None,
            expected_master_key_fp: None,
            storage_id: None,
        }
    }
}
