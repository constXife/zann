//! Headless syncable ES256 ceremonies. No storage, transport, UI or clock IO.
//!
//! Adapters authenticate observed origins and fresh, request-bound presence /
//! verification evidence before calling this API. Registration returns a local
//! credential separately from the public attestation response. Assertions borrow
//! the credential immutably: they cannot bump Item versions or synced recency.
mod ceremony;
mod credential;
mod encoding;
mod error;
pub mod exchange;

pub use ceremony::*;
pub use credential::{Credential, UserEntity, MAX_CREDENTIAL_ID_BYTES, MAX_USER_HANDLE_BYTES};
pub use error::PasskeyError;
pub use zann_autofill::{CrossOriginPermission, RpId, SiteUrl};
pub use zann_core::item_policy::{PASSKEY_ALGORITHM, PASSKEY_TYPE_ID};
