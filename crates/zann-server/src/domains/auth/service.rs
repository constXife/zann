use base64::Engine;
use chrono::Utc;
use sqlx_core::query::query;
use sqlx_postgres::Postgres;
use uuid::Uuid;
use zann_core::api::auth::{
    LoginRequest, LoginResponse, LogoutRequest, OidcLoginRequest, PreloginResponse, RefreshRequest,
    RegisterRequest, ServiceAccountLoginRequest, ServiceAccountLoginResponse,
    ServiceAccountVaultKey,
};
use zann_core::{Session, User, UserStatus};
use zann_crypto::vault_crypto as core_crypto;
use zann_db::repo::{
    DeviceRepo, ServiceAccountRepo, ServiceAccountSessionRepo, SessionRepo, UserRepo, VaultRepo,
};

use crate::app::AppState;
use crate::config::{AuthMode, InternalRegistration};
use crate::domains::auth::core::identity::identity_from_oidc;
use crate::domains::auth::core::oidc::validate_oidc_jwt;
use crate::domains::auth::core::passwords::{
    derive_auth_hash, hash_password, hash_service_token, kdf_fingerprint, kdf_params_from_user,
    random_kdf_salt, verify_password, KdfParams,
};
use crate::domains::auth::core::tokens::hash_token;
use crate::domains::auth::helpers::{
    build_device, build_login_response, create_session_for_user, ensure_personal_vault_tx,
    ttl_seconds_u64,
};
use crate::domains::errors::ServiceError;
use crate::infra::db::apply_tx_isolation;
use crate::infra::metrics;

const SERVICE_ACCOUNT_PREFIX: &str = "zann_sa_";
const SERVICE_ACCOUNT_PREFIX_LEN: usize = 12;
const MAX_SERVICE_ACCOUNT_VAULT_KEYS: usize = 64;
const SERVICE_ACCOUNT_VAULT_KEY_LOOKAHEAD: i64 = 65;

pub struct AuthRequestContext {
    pub client_ip: Option<String>,
    pub request_id: Option<String>,
    pub user_agent: Option<String>,
}

pub type AuthError = ServiceError;

mod issuance;
mod machine;
mod oidc;
mod password;
mod registration;
mod sessions;

pub(crate) use machine::login_service_account;
pub use oidc::login_oidc;
pub use password::{login_internal, prelogin};
pub use registration::register;
pub use sessions::{logout, refresh};
