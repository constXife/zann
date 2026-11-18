//! Server RP, account custody and restricted recovery authority.
mod candidate;
mod codes;
mod common;
mod enrollment;
pub(crate) mod http;
mod limiter;
mod login;
mod management;
mod model;
mod recovery;
mod rp;
mod runtime;
mod security;
pub use runtime::AccountAccessRuntime;

#[derive(Debug, thiserror::Error)]
pub(crate) enum AccessError {
    #[error("account security management is forbidden")]
    Forbidden,
    #[error("invalid account access request: {0}")]
    BadRequest(&'static str),
    #[error("invalid account access JSON")]
    InvalidJson(#[source] serde_json::Error),
    #[error("passkey account access was rejected")]
    Rejected,
    #[error("passkey account access conflicts with current state")]
    Conflict,
    #[error("passkey account access is disabled")]
    Disabled,
    #[error("passkey account access capacity exhausted")]
    Capacity,
    #[error("account access request rate exceeded")]
    RateLimited,
    #[error("account access transaction timed out")]
    Timeout,
    #[error("account access KDF failed: {0}")]
    Kdf(&'static str),
    #[error("account access KDF worker failed")]
    Worker(#[from] tokio::task::JoinError),
    #[error("account access storage failed")]
    Store(#[from] zann_db::repo::AccountAccessStoreError),
    #[error("account access session changed")]
    Session(#[from] zann_db::repo::SessionWriteError),
    #[error("account access session issuance failed")]
    Issuance(#[from] crate::domains::auth::service::issuance::SessionIssueError),
    #[error("invalid passkey configuration: {0}")]
    Configuration(&'static str),
    #[error("account access cryptography failed")]
    Crypto(#[from] zann_crypto::account_access::AccountAccessError),
    #[error("WebAuthn verification failed")]
    Webauthn(#[from] webauthn_rs_core::error::WebauthnError),
    #[error("recovery storage failed")]
    Recovery(#[from] zann_db::repo::RecoveryStoreError),
    #[error("recovery credential encoding failed")]
    RecoverySecret(#[from] zann_crypto::recovery::RecoverySecretError),
    #[error("account access database failed")]
    Database(#[from] sqlx_core::Error),
    #[error("account access state encoding failed")]
    Encoding(#[from] serde_json::Error),
}
pub(crate) type Result<T> = std::result::Result<T, AccessError>;
