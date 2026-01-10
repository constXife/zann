use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerConfig {
    #[serde(default)]
    pub server: ServerRuntimeConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub rotation: RotationConfig,
    #[serde(default)]
    pub sentry: SentryConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub tracing: TracingConfig,
}

pub const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_CLOCK_SKEW_SECONDS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerRuntimeConfig {
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_max_clock_skew_seconds")]
    pub max_clock_skew_seconds: i64,
    #[serde(default = "default_true")]
    pub personal_vaults_enabled: bool,
    #[serde(default = "default_attachments_gc_grace_days")]
    pub attachments_gc_grace_days: i64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub master_key: Option<String>,
    #[serde(default)]
    pub master_key_file: Option<String>,
    #[serde(default)]
    pub master_key_mode: MasterKeyMode,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

impl Default for ServerRuntimeConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: default_max_body_bytes(),
            max_clock_skew_seconds: default_max_clock_skew_seconds(),
            personal_vaults_enabled: default_true(),
            attachments_gc_grace_days: default_attachments_gc_grace_days(),
            name: None,
            fingerprint: None,
            master_key: None,
            master_key_file: None,
            master_key_mode: MasterKeyMode::default(),
            trusted_proxies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MasterKeyMode {
    #[default]
    AutoGenerate,
    External,
    ManualUnseal,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretsConfig {
    #[serde(default)]
    pub policies_file: Option<String>,
    #[serde(default)]
    pub default_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub mode: AuthMode,
    #[serde(default)]
    pub kdf: KdfConfig,
    #[serde(default)]
    pub internal: InternalAuthConfig,
    #[serde(default)]
    pub oidc: OidcConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Internal,
            kdf: KdfConfig::default(),
            internal: InternalAuthConfig::default(),
            oidc: OidcConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfConfig {
    #[serde(default = "default_kdf_algorithm")]
    pub algorithm: String,
    #[serde(default = "default_kdf_iterations")]
    pub iterations: u32,
    #[serde(default = "default_kdf_memory_kb")]
    pub memory_kb: u32,
    #[serde(default = "default_kdf_parallelism")]
    pub parallelism: u32,
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self {
            algorithm: default_kdf_algorithm(),
            iterations: default_kdf_iterations(),
            memory_kb: default_kdf_memory_kb(),
            parallelism: default_kdf_parallelism(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    #[default]
    Internal,
    Oidc,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub registration: InternalRegistration,
}

impl Default for InternalAuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            registration: InternalRegistration::Open,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InternalRegistration {
    Open,
    #[default]
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OidcConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub jwks_cache_ttl: Option<String>,
    #[serde(default)]
    pub jwks_file: Option<String>,
    #[serde(default)]
    pub jwks_url: Option<String>,
    #[serde(default)]
    pub groups_claim: Option<String>,
    #[serde(default)]
    pub admin_group: Option<String>,
    #[serde(default)]
    pub group_mappings: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConfig {
    #[serde(default)]
    pub file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    #[serde(default = "default_rotation_lock_ttl_seconds")]
    pub lock_ttl_seconds: i64,
    #[serde(default = "default_rotation_stale_retention_seconds")]
    pub stale_retention_seconds: i64,
    #[serde(default = "default_rotation_cleanup_interval_seconds")]
    pub cleanup_interval_seconds: u64,
    #[serde(default = "default_rotation_max_versions")]
    pub max_versions: i64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            lock_ttl_seconds: default_rotation_lock_ttl_seconds(),
            stale_retention_seconds: default_rotation_stale_retention_seconds(),
            cleanup_interval_seconds: default_rotation_cleanup_interval_seconds(),
            max_versions: default_rotation_max_versions(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SentryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub dsn: String,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub release: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_endpoint")]
    pub endpoint: String,
    #[serde(default)]
    pub profile: Option<MetricsProfile>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_metrics_endpoint(),
            profile: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MetricsProfile {
    #[default]
    Prod,
    Staging,
    Debug,
}

impl MetricsConfig {
    #[must_use]
    pub fn effective_profile(&self) -> MetricsProfile {
        self.profile.clone().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracingConfig {
    #[serde(default)]
    pub otel: OtelConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OtelConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub service_name: Option<String>,
    #[serde(default)]
    pub sampling_ratio: Option<f64>,
    #[serde(default)]
    pub ca_file: Option<String>,
    #[serde(default)]
    pub insecure: Option<bool>,
}

const fn default_true() -> bool {
    true
}

fn default_kdf_algorithm() -> String {
    "argon2id".to_string()
}

const fn default_rotation_lock_ttl_seconds() -> i64 {
    10 * 60
}

const fn default_rotation_stale_retention_seconds() -> i64 {
    24 * 60 * 60
}

const fn default_rotation_cleanup_interval_seconds() -> u64 {
    10 * 60
}

const fn default_rotation_max_versions() -> i64 {
    5
}

const fn default_kdf_iterations() -> u32 {
    3
}

const fn default_kdf_memory_kb() -> u32 {
    65536
}

const fn default_kdf_parallelism() -> u32 {
    4
}

fn default_metrics_endpoint() -> String {
    "/metrics".to_string()
}

const fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

const fn default_max_clock_skew_seconds() -> i64 {
    DEFAULT_MAX_CLOCK_SKEW_SECONDS
}

const fn default_attachments_gc_grace_days() -> i64 {
    30
}
