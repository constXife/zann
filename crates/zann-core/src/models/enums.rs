use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum VaultKind {
    Personal,
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum VaultMemberRole {
    Admin,
    Operator,
    Member,
    Readonly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum VaultEncryptionType {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CachePolicy {
    Full,
    MetadataOnly,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ChangeOp {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum UserStatus {
    Active,
    Disabled,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SyncStatus {
    Active,
    Tombstone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ChangeType {
    Create,
    Update,
    Delete,
    Restore,
}

#[derive(Debug)]
pub struct EnumParseError {
    enum_name: &'static str,
    value: String,
}

impl EnumParseError {
    fn new(enum_name: &'static str, value: impl Into<String>) -> Self {
        Self {
            enum_name,
            value: value.into(),
        }
    }
}

impl std::fmt::Display for EnumParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid {} value: {}", self.enum_name, self.value)
    }
}

impl std::error::Error for EnumParseError {}

impl VaultKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Shared => "shared",
        }
    }
}

impl VaultEncryptionType {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

impl std::str::FromStr for VaultEncryptionType {
    type Err = EnumParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "client" => Ok(Self::Client),
            "server" => Ok(Self::Server),
            _ => Err(EnumParseError::new("vault_encryption_type", value)),
        }
    }
}

impl std::str::FromStr for VaultKind {
    type Err = EnumParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "personal" => Ok(Self::Personal),
            "shared" => Ok(Self::Shared),
            _ => Err(EnumParseError::new("vault_kind", value)),
        }
    }
}

impl VaultMemberRole {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Member => "member",
            Self::Readonly => "readonly",
        }
    }
}

impl std::str::FromStr for VaultMemberRole {
    type Err = EnumParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "admin" => Ok(Self::Admin),
            "operator" => Ok(Self::Operator),
            "member" => Ok(Self::Member),
            "readonly" => Ok(Self::Readonly),
            _ => Err(EnumParseError::new("vault_member_role", value)),
        }
    }
}

impl CachePolicy {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::MetadataOnly => "metadata_only",
            Self::None => "none",
        }
    }
}

impl std::str::FromStr for CachePolicy {
    type Err = EnumParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "full" => Ok(Self::Full),
            "metadata_only" => Ok(Self::MetadataOnly),
            "none" => Ok(Self::None),
            _ => Err(EnumParseError::new("cache_policy", value)),
        }
    }
}

impl ChangeOp {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

impl std::str::FromStr for ChangeOp {
    type Err = EnumParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "create" => Ok(Self::Create),
            "update" => Ok(Self::Update),
            "delete" => Ok(Self::Delete),
            _ => Err(EnumParseError::new("change_op", value)),
        }
    }
}

impl UserStatus {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::System => "system",
        }
    }
}

impl std::str::FromStr for UserStatus {
    type Err = EnumParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            "system" => Ok(Self::System),
            _ => Err(EnumParseError::new("user_status", value)),
        }
    }
}

impl SyncStatus {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Tombstone => "tombstone",
        }
    }
}

impl std::str::FromStr for SyncStatus {
    type Err = EnumParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "tombstone" => Ok(Self::Tombstone),
            _ => Err(EnumParseError::new("sync_status", value)),
        }
    }
}

impl ChangeType {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Restore => "restore",
        }
    }
}

impl std::str::FromStr for ChangeType {
    type Err = EnumParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "create" => Ok(Self::Create),
            "update" => Ok(Self::Update),
            "delete" => Ok(Self::Delete),
            "restore" => Ok(Self::Restore),
            _ => Err(EnumParseError::new("change_type", value)),
        }
    }
}
