use std::cell::Cell;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use data_encoding::HEXLOWER;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

use zann_core::api::auth::KdfParams;
use zann_core::AuthMethod;

#[cfg(feature = "session")]
use super::locking::lock_order_allows;
use super::locking::{
    ensure_config_root, validate_regular_file_if_exists, ConfigFileLockGuard, FileLockGuard,
    LockKind,
};

pub use super::locking::{
    CONFIG_LOCK_FILENAME, CREDENTIAL_OPERATION_LOCK_FILENAME, SYNC_COMMIT_LOCK_FILENAME,
};

pub const CONFIG_SCHEMA_VERSION: u32 = 2;
pub const CONFIG_V2_FILENAME: &str = "client-config.json";
pub const CONFIG_BACKUP_FILENAME: &str = "client-config.backup.json";
pub const CONFIG_RESTORE_JOURNAL_FILENAME: &str = "client-config.restore.json";
pub const CREDENTIAL_TRANSACTION_JOURNAL_FILENAME: &str = "client-config.credential-intent.json";
pub(crate) const AUTH_OPERATION_INTENT_FILENAME: &str = "client-auth.intent.json";
pub const LEGACY_CONFIG_FILENAME: &str = "config.json";
pub const LEGACY_KNOWN_HOSTS_FILENAME: &str = "known_hosts.json";
pub const LOCAL_DB_FILENAME: &str = "local.sqlite";
pub const DESKTOP_SETTINGS_FILENAME: &str = "desktop.json";
pub const REMEMBERED_UNLOCK_FILENAME: &str = "unlock.json";

const CONNECTION_ID_PREFIX: &str = "conn_";
const CREDENTIAL_ID_PREFIX: &str = "cred_";
const LIFECYCLE_CREDENTIAL_ID_PREFIX: &str = "credl_";
const LIFECYCLE_NONCE_HEX_LEN: usize = 32;
const LIFECYCLE_TAG_HEX_LEN: usize = 64;
const RESTORE_JOURNAL_VERSION: u32 = 1;
const CREDENTIAL_TRANSACTION_JOURNAL_VERSION: u32 = 2;
const CREDENTIAL_TRANSACTION_JOURNAL_V1: u32 = 1;
const AUTH_OPERATION_INTENT_V1: u32 = 1;
const AUTH_OPERATION_INTENT_VERSION: u32 = 2;
const LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const CONFIG_MAX_BYTES: u64 = 4 * 1024 * 1024;
const RESTORE_JOURNAL_MAX_BYTES: u64 = 12 * 1024 * 1024;
const CREDENTIAL_TRANSACTION_JOURNAL_MAX_BYTES: u64 = 16 * 1024 * 1024;
const AUTH_OPERATION_INTENT_MAX_BYTES: u64 = 64 * 1024;
const JSON_NODE_LIMIT: usize = 50_000;
const RESTORE_JOURNAL_NODE_LIMIT: usize = 100_000;
const CREDENTIAL_TRANSACTION_JOURNAL_NODE_LIMIT: usize = 175_000;
const AUTH_OPERATION_INTENT_NODE_LIMIT: usize = 256;
const MAX_CONNECTIONS: usize = 256;
const MAX_CLIENTS: usize = 32;
const MAX_PROFILES_TOTAL: usize = 128;
const MAX_CREDENTIAL_SLOTS: usize = 384;
const MAX_KNOWN_HOSTS: usize = 1_024;
const MAX_DEFERRED_FIELDS: usize = 1_024;
const MAX_LEGACY_NAME_LEN: usize = 128;
const MAX_ADDRESS_LEN: usize = 2_048;
const MAX_METADATA_VALUE_LEN: usize = 2_048;
const MAX_CREDENTIAL_SECRET_LEN: usize = 64 * 1024;
const MAX_DEFERRED_PATH_LEN: usize = 4_096;

// Dormant until the authenticated transport/session owner calls this crate-private foundation.

mod anchor;
mod auth_validation;
mod authenticated_target;
mod credential_model;
mod credential_plan;
mod generation_model;
mod identity;
mod journal_io;
mod journal_model;
mod journal_validation;
mod json_io;
mod legacy_credentials;
mod legacy_input;
mod legacy_model;
mod legacy_scan;
mod metadata;
mod migration;
mod profile;
mod schema;
mod session_model;
mod transaction_model;
mod validation;

mod repository;

#[cfg(test)]
#[path = "v2/tests.rs"]
mod authenticated_session_tests;
use anchor::*;
use auth_validation::*;
use authenticated_target::*;
pub use credential_model::*;
use credential_plan::*;
pub use generation_model::*;
pub use identity::*;
use journal_io::*;
pub use journal_model::*;
use journal_validation::*;
use json_io::*;
use legacy_credentials::*;
use legacy_input::*;
use legacy_model::*;
use legacy_scan::*;
use metadata::*;
use migration::*;
pub use profile::*;
pub use schema::*;
pub use session_model::*;
pub use transaction_model::*;
use validation::*;
