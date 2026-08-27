use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use zann_client::app::{
    AppClient, ClientId, ClientPaths, CredentialSecret, LegacySessionImport, SessionClient,
    SessionError, SessionErrorKind, SessionOperation, SyncError, SyncErrorKind,
};
use zann_client::credentials::{OsCredentialStore, OsLegacyCredentialSource};
use zann_client_sqlite::SqliteSyncStoreFactory;

use crate::state::{local_db_path, CliContext};
use crate::util::parse_rfc3339;

pub fn app_client(root: &Path) -> Result<AppClient, String> {
    let factory = Arc::new(
        SqliteSyncStoreFactory::new(&local_db_path(root)).map_err(|error| error.to_string())?,
    );
    let client_id = ClientId::new("desktop").map_err(|error| error.to_string())?;
    let client = AppClient::new(
        ClientPaths::new(root),
        Arc::new(OsCredentialStore::system_default()),
        SessionClient::new(client_id),
        factory,
    );
    client
        .initialize(&OsLegacyCredentialSource::system_default())
        .map_err(|error| error.to_string())?;
    Ok(client)
}

#[allow(clippy::too_many_arguments)]
pub async fn import_legacy_tokens(
    client: &AppClient,
    endpoint: &str,
    connection_name: &str,
    profile_name: &str,
    storage_id: Option<String>,
    access_token: &str,
    refresh_token: &str,
    access_expires_at: Option<&str>,
) -> Result<(), String> {
    let access = CredentialSecret::new(access_token.to_string())
        .map_err(|_| "invalid access token".to_string())?;
    let refresh = CredentialSecret::new(refresh_token.to_string())
        .map_err(|_| "invalid refresh token".to_string())?;
    let request = LegacySessionImport::new(
        endpoint,
        connection_name,
        profile_name,
        storage_id,
        access,
        refresh,
        access_expires_at.and_then(parse_rfc3339),
    );
    let operation = SessionOperation::new(Instant::now() + Duration::from_secs(2 * 60)).0;
    client
        .import_legacy_session(request, operation)
        .await
        .map(|_| ())
        .map_err(map_session_error)
}

pub async fn import_from_context(
    client: &AppClient,
    context_name: &str,
    context: &CliContext,
) -> Result<(), String> {
    let Some(profile_name) = context.current_token.as_deref() else {
        return Ok(());
    };
    let Some(entry) = context.tokens.get(profile_name) else {
        return Ok(());
    };
    let Some(refresh_token) = entry.refresh_token.as_deref() else {
        return Ok(());
    };
    if entry.access_token.is_empty() {
        return Ok(());
    }
    import_legacy_tokens(
        client,
        &context.addr,
        context_name,
        profile_name,
        context.storage_id.clone(),
        &entry.access_token,
        refresh_token,
        entry.access_expires_at.as_deref(),
    )
    .await
}

pub fn map_session_error(error: SessionError) -> String {
    format!("{}: {error}", session_error_kind(error.kind()))
}

pub fn session_error_kind(kind: SessionErrorKind) -> &'static str {
    match kind {
        SessionErrorKind::SessionExpired | SessionErrorKind::ReauthenticationRequired => {
            "session_expired"
        }
        SessionErrorKind::TransportUnavailable => "server_unreachable",
        SessionErrorKind::TrustRequired
        | SessionErrorKind::TrustMismatch
        | SessionErrorKind::TrustInvalid => "server_fingerprint_changed",
        SessionErrorKind::Configuration | SessionErrorKind::SessionNotFound => "context_missing",
        SessionErrorKind::DeadlineExceeded => "network_timeout",
        _ => "sync_session",
    }
}

pub fn sync_error_kind(error: &SyncError) -> &'static str {
    match error.kind() {
        SyncErrorKind::Cancelled => "sync_cancelled",
        SyncErrorKind::DeadlineExceeded | SyncErrorKind::Timeout => "network_timeout",
        SyncErrorKind::Session | SyncErrorKind::SessionExpired => "session_expired",
        SyncErrorKind::NoLocalTarget => "context_missing",
        SyncErrorKind::TransportUnavailable => "server_unreachable",
        SyncErrorKind::Local | SyncErrorKind::Crypto => "db_error",
        SyncErrorKind::ConcurrentRemoteChange => "sync_conflict",
        SyncErrorKind::PushUnavailable => "sync_push_failed",
        _ => "sync_internal",
    }
}
