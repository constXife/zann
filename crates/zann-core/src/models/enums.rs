use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "i32", into = "i32")]
pub enum VaultKind {
    Personal = 1,
    Shared = 2,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "i32", into = "i32")]
pub enum VaultMemberRole {
    Admin = 1,
    Operator = 2,
    Member = 3,
    Readonly = 4,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "i32", into = "i32")]
pub enum VaultEncryptionType {
    Client = 1,
    Server = 2,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "i32", into = "i32")]
pub enum CachePolicy {
    Full = 1,
    MetadataOnly = 2,
    None = 3,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "i32", into = "i32")]
pub enum ChangeOp {
    Create = 1,
    Update = 2,
    Delete = 3,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "i32", into = "i32")]
pub enum UserStatus {
    Active = 1,
    Disabled = 2,
    System = 3,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "i32", into = "i32")]
pub enum SyncStatus {
    Active = 1,
    Tombstone = 2,
    Modified = 3,
    LocalDeleted = 4,
    Conflict = 5,
    Synced = 6,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "i32", into = "i32")]
pub enum ChangeType {
    Create = 1,
    Update = 2,
    Delete = 3,
    Restore = 4,
}

#[derive(Debug)]
pub struct EnumParseError {
    enum_name: &'static str,
    value: String,
}

impl EnumParseError {
    pub fn new(enum_name: &'static str, value: impl Into<String>) -> Self {
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
    pub const PERSONAL: i32 = Self::Personal as i32;
    pub const SHARED: i32 = Self::Shared as i32;

    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl VaultEncryptionType {
    pub const CLIENT: i32 = Self::Client as i32;
    pub const SERVER: i32 = Self::Server as i32;

    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
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
    pub const ADMIN: i32 = Self::Admin as i32;
    pub const OPERATOR: i32 = Self::Operator as i32;
    pub const MEMBER: i32 = Self::Member as i32;
    pub const READONLY: i32 = Self::Readonly as i32;

    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
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
    pub const FULL: i32 = Self::Full as i32;
    pub const METADATA_ONLY: i32 = Self::MetadataOnly as i32;
    pub const NONE: i32 = Self::None as i32;

    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
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
    pub const CREATE: i32 = Self::Create as i32;
    pub const UPDATE: i32 = Self::Update as i32;
    pub const DELETE: i32 = Self::Delete as i32;

    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
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
    pub const ACTIVE: i32 = Self::Active as i32;
    pub const DISABLED: i32 = Self::Disabled as i32;
    pub const SYSTEM: i32 = Self::System as i32;

    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
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
    pub const ACTIVE: i32 = Self::Active as i32;
    pub const TOMBSTONE: i32 = Self::Tombstone as i32;
    pub const MODIFIED: i32 = Self::Modified as i32;
    pub const LOCAL_DELETED: i32 = Self::LocalDeleted as i32;
    pub const CONFLICT: i32 = Self::Conflict as i32;
    pub const SYNCED: i32 = Self::Synced as i32;

    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
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
    pub const CREATE: i32 = Self::Create as i32;
    pub const UPDATE: i32 = Self::Update as i32;
    pub const DELETE: i32 = Self::Delete as i32;
    pub const RESTORE: i32 = Self::Restore as i32;

    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl From<VaultKind> for i32 {
    fn from(value: VaultKind) -> Self {
        value as i32
    }
}

impl From<VaultMemberRole> for i32 {
    fn from(value: VaultMemberRole) -> Self {
        value as i32
    }
}

impl From<VaultEncryptionType> for i32 {
    fn from(value: VaultEncryptionType) -> Self {
        value as i32
    }
}

impl From<CachePolicy> for i32 {
    fn from(value: CachePolicy) -> Self {
        value as i32
    }
}

impl From<ChangeOp> for i32 {
    fn from(value: ChangeOp) -> Self {
        value as i32
    }
}

impl From<UserStatus> for i32 {
    fn from(value: UserStatus) -> Self {
        value as i32
    }
}

impl From<SyncStatus> for i32 {
    fn from(value: SyncStatus) -> Self {
        value as i32
    }
}

impl From<ChangeType> for i32 {
    fn from(value: ChangeType) -> Self {
        value as i32
    }
}

impl TryFrom<i32> for VaultKind {
    type Error = EnumParseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Personal),
            2 => Ok(Self::Shared),
            _ => Err(EnumParseError::new("vault_kind", value.to_string())),
        }
    }
}

impl TryFrom<i32> for VaultMemberRole {
    type Error = EnumParseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Admin),
            2 => Ok(Self::Operator),
            3 => Ok(Self::Member),
            4 => Ok(Self::Readonly),
            _ => Err(EnumParseError::new("vault_member_role", value.to_string())),
        }
    }
}

impl TryFrom<i32> for VaultEncryptionType {
    type Error = EnumParseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Client),
            2 => Ok(Self::Server),
            _ => Err(EnumParseError::new(
                "vault_encryption_type",
                value.to_string(),
            )),
        }
    }
}

impl TryFrom<i32> for CachePolicy {
    type Error = EnumParseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Full),
            2 => Ok(Self::MetadataOnly),
            3 => Ok(Self::None),
            _ => Err(EnumParseError::new("cache_policy", value.to_string())),
        }
    }
}

impl TryFrom<i32> for ChangeOp {
    type Error = EnumParseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Create),
            2 => Ok(Self::Update),
            3 => Ok(Self::Delete),
            _ => Err(EnumParseError::new("change_op", value.to_string())),
        }
    }
}

impl TryFrom<i32> for UserStatus {
    type Error = EnumParseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Disabled),
            3 => Ok(Self::System),
            _ => Err(EnumParseError::new("user_status", value.to_string())),
        }
    }
}

impl TryFrom<i32> for SyncStatus {
    type Error = EnumParseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Tombstone),
            3 => Ok(Self::Modified),
            4 => Ok(Self::LocalDeleted),
            5 => Ok(Self::Conflict),
            6 => Ok(Self::Synced),
            _ => Err(EnumParseError::new("sync_status", value.to_string())),
        }
    }
}

impl TryFrom<i32> for ChangeType {
    type Error = EnumParseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Create),
            2 => Ok(Self::Update),
            3 => Ok(Self::Delete),
            4 => Ok(Self::Restore),
            _ => Err(EnumParseError::new("change_type", value.to_string())),
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
