mod actions;
pub(crate) mod args;
mod http;
pub(crate) mod types;

pub(crate) use actions::{handle_login_command, handle_logout};
pub(crate) use http::{
    auth_headers, check_kdf_fingerprint, delete_access_token, delete_refresh_token,
    delete_service_token, ensure_access_token, exchange_service_account_token,
    fetch_auth_system_info, fetch_me_email, fetch_oidc_config, fetch_oidc_discovery,
    fetch_prelogin, load_access_token, load_refresh_token, load_service_token, poll_device_token,
    refresh_token_for_context, refresh_token_missing_error, request_device_code,
    store_access_token, store_prelogin, store_refresh_token, store_service_token,
    verify_server_fingerprint,
};
#[cfg(test)]
pub(crate) use http::{clear_keyring_mock, lock_keyring_tests_async, lock_keyring_tests_sync};
pub(crate) use types::{
    AuthResponse, DeviceAuthResponse, LoginRequest, LogoutRequest, OidcConfigResponse,
    OidcDiscovery, RefreshRequest, ServiceAccountAuthRequest, ServiceAccountAuthResponse,
    TokenErrorResponse, TokenResponse,
};
