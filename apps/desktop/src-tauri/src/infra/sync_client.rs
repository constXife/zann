use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use zann_client::app::{
    AppClient, ClientId, ClientPaths, CredentialSecret, LegacySessionImport, SessionClient,
    SessionError, SessionErrorKind, SessionOperation, SyncError, SyncErrorKind,
};
use zann_client::credentials::{OsCredentialStore, OsLegacyCredentialSource};
use zann_client_sqlite::SqliteSyncStoreFactory;
use zann_core::crypto::SecretKey;

use crate::state::{local_db_path, CliContext};
use crate::util::parse_rfc3339;

pub struct MappedError {
    pub kind: String,
    pub message: String,
}

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

pub async fn run_sync(
    root: &Path,
    context_name: &str,
    context: &CliContext,
    storage_id: Option<&str>,
    master_key: &SecretKey,
) -> Result<usize, MappedError> {
    let client = app_client(root).map_err(configuration_error)?;
    import_from_context(&client, context_name, context).await?;
    let target = client
        .configured_target(storage_id)
        .map_err(session_mapped)?;
    let operation = SessionOperation::new(Instant::now() + Duration::from_secs(10 * 60)).0;
    let outcome = client
        .sync(
            target,
            SecretKey::from_bytes(*master_key.as_bytes()),
            operation,
        )
        .await
        .map_err(sync_mapped)?;
    Ok(outcome.changes_committed())
}

pub async fn run_reset(
    root: &Path,
    storage_id: &str,
    master_key: &SecretKey,
) -> Result<(), MappedError> {
    let client = app_client(root).map_err(configuration_error)?;
    let target = client
        .configured_target(Some(storage_id))
        .map_err(session_mapped)?;
    client
        .reset_sync(target, SecretKey::from_bytes(*master_key.as_bytes()))
        .await
        .map_err(sync_mapped)
}

async fn import_from_context(
    client: &AppClient,
    context_name: &str,
    context: &CliContext,
) -> Result<(), MappedError> {
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
    .map_err(import_error)
}

fn configuration_error(message: String) -> MappedError {
    MappedError {
        kind: "configuration".to_string(),
        message,
    }
}

fn import_error(error: String) -> MappedError {
    let (kind, message) = error
        .split_once(':')
        .map(|(kind, rest)| (kind.to_string(), rest.trim_start().to_string()))
        .unwrap_or_else(|| ("sync_session".to_string(), error));
    MappedError { kind, message }
}

fn map_session_error(error: SessionError) -> String {
    format!("{}: {error}", session_error_kind(error.kind()))
}

fn session_mapped(error: SessionError) -> MappedError {
    MappedError {
        kind: session_error_kind(error.kind()).to_string(),
        message: error.to_string(),
    }
}

fn sync_mapped(error: SyncError) -> MappedError {
    MappedError {
        kind: sync_error_kind(&error).to_string(),
        message: error.to_string(),
    }
}

fn session_error_kind(kind: SessionErrorKind) -> &'static str {
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

fn sync_error_kind(error: &SyncError) -> &'static str {
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
