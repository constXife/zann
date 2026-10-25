use super::*;

#[derive(Default, Deserialize)]
pub(super) struct LegacyConfig {
    #[serde(default)]
    pub(super) current_context: Option<String>,
    #[serde(default)]
    pub(super) contexts: BTreeMap<String, LegacyConnection>,
    #[serde(default)]
    pub(super) identity: Option<LegacyIdentity>,
    #[serde(default)]
    pub(super) storage: Option<LegacyStorage>,
}

#[derive(Deserialize)]
pub(super) struct LegacyClientClaim {
    #[serde(default)]
    pub(super) current_context: Option<String>,
    #[serde(default)]
    pub(super) contexts: BTreeMap<String, LegacyConnectionClaim>,
}

#[derive(Deserialize)]
pub(super) struct LegacyConnectionClaim {
    pub(super) addr: String,
}

#[derive(Deserialize)]
pub(super) struct LegacyStorage {
    #[serde(default)]
    pub(super) backup_dir: Option<String>,
    #[serde(default)]
    pub(super) backup_retention_days: Option<u32>,
    #[serde(default)]
    pub(super) backup_max_count: Option<u32>,
}

#[derive(Deserialize)]
pub(super) struct LegacyIdentity {
    pub(super) kdf_salt: String,
    pub(super) kdf_params: ConfigKdfParams,
    #[serde(default)]
    pub(super) salt_fingerprint: Option<String>,
    #[serde(default)]
    pub(super) first_seen_at: Option<String>,
    #[serde(default)]
    pub(super) email: Option<String>,
}

impl From<LegacyIdentity> for ConfigIdentity {
    fn from(identity: LegacyIdentity) -> Self {
        Self {
            kdf_salt: identity.kdf_salt,
            kdf_params: identity.kdf_params,
            salt_fingerprint: identity.salt_fingerprint,
            first_seen_at: identity.first_seen_at,
            email: identity.email,
        }
    }
}

#[derive(Deserialize)]
pub(super) struct LegacyConnection {
    pub(super) addr: String,
    #[serde(default)]
    pub(super) needs_salt_update: bool,
    #[serde(default)]
    pub(super) server_id: Option<String>,
    #[serde(default)]
    pub(super) server_fingerprint: Option<String>,
    #[serde(default)]
    pub(super) expected_master_key_fp: Option<String>,
    #[serde(default)]
    pub(super) tokens: BTreeMap<String, LegacyCredentialProfile>,
    #[serde(default)]
    pub(super) current_token: Option<String>,
    #[serde(default)]
    pub(super) storage_id: Option<String>,
    #[serde(default)]
    pub(super) vault: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct LegacyCredentialProfile {
    #[serde(default)]
    pub(super) access_token: Option<LegacySecret>,
    #[serde(default)]
    pub(super) refresh_token: Option<LegacySecret>,
    #[serde(default)]
    pub(super) service_account_token: Option<LegacySecret>,
    #[serde(default)]
    pub(super) access_expires_at: Option<String>,
}

pub(super) struct LegacySecret(pub(super) Zeroizing<String>);

impl LegacySecret {
    pub(super) fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for LegacySecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}
