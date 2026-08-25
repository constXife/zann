//! Private transport boundary for sync.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use reqwest::{StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::Zeroizing;

use super::model::{CatalogSnapshot, SyncCursor, VaultPlane, PULL_PAGE_LIMIT};
use super::wire::{
    personal_push_request, shared_push_request, validate_catalog_detail, validate_catalog_list,
    PersonalPullPageWire, PullPageWire, PullRequestWire, PushResponseWire, SharedPullPageWire,
    VaultDetailWire, VaultListWire,
};
use crate::session::SessionAccess;

const CATALOG_PATH: &str = "v1/vaults?limit=200&offset=0&sort=asc";
const PERSONAL_PULL_PATH: &str = "v1/sync/pull";
const SHARED_PULL_PATH: &str = "v1/sync/shared/pull";
const PERSONAL_PUSH_PATH: &str = "v1/sync/push";
const SHARED_PUSH_PATH: &str = "v1/sync/shared/push";
// 1024 summaries may legally carry 64 128-byte tags each. Keep the semantic
// catalog maximum reachable while retaining a hard transport ceiling.
const MAX_CATALOG_BODY_BYTES: usize = 16 * 1_024 * 1_024;
const MAX_DETAIL_BODY_BYTES: usize = 512 * 1_024;
const MAX_RETAINED_CATALOG_BYTES: usize = 16 * 1_024 * 1_024;
const MAX_PULL_BODY_BYTES: usize = 32 * 1_024 * 1_024;
const MAX_PUSH_BODY_BYTES: usize = 2 * 1_024 * 1_024;

pub(crate) type RemoteFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, RemoteError>> + Send + 'a>>;

pub(crate) trait SyncRemote: Send + Sync {
    fn fetch_catalog<'a>(
        &'a self,
        access: &'a SessionAccess,
        timeout: Duration,
    ) -> RemoteFuture<'a, CatalogSnapshot>;

    fn pull_page<'a>(
        &'a self,
        access: &'a SessionAccess,
        vault_id: uuid::Uuid,
        plane: VaultPlane,
        cursor: Option<&'a SyncCursor>,
        timeout: Duration,
    ) -> RemoteFuture<'a, PullPageWire>;

    fn push<'a>(
        &'a self,
        access: &'a SessionAccess,
        vault: &'a super::model::ResolvedSyncVault,
        pending: &'a [super::model::PendingProof],
        timeout: Duration,
    ) -> RemoteFuture<'a, PushResponseWire>;

    fn publish_personal_vault_key<'a>(
        &'a self,
        _access: &'a SessionAccess,
        _vault_id: uuid::Uuid,
        _envelope: &'a [u8],
        _timeout: Duration,
    ) -> RemoteFuture<'a, ()> {
        Box::pin(async { Err(RemoteError::new(RemoteErrorKind::Unavailable)) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteErrorKind {
    InvalidEndpoint,
    Timeout,
    Unavailable,
    Rejected,
    SessionExpired,
    Server,
    BodyTooLarge,
    Protocol,
    Conflict,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RemoteError {
    kind: RemoteErrorKind,
    status: Option<u16>,
}

impl RemoteError {
    pub(crate) const fn new(kind: RemoteErrorKind) -> Self {
        Self { kind, status: None }
    }

    const fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status.as_u16());
        self
    }

    pub(crate) const fn kind(self) -> RemoteErrorKind {
        self.kind
    }

    pub(crate) const fn status(self) -> Option<u16> {
        self.status
    }
}

impl fmt::Debug for RemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteError")
            .field("kind", &self.kind)
            .field("status", &self.status)
            .finish()
    }
}

impl fmt::Display for RemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sync_remote:{:?}", self.kind)?;
        if let Some(status) = self.status {
            write!(formatter, ":status_{status}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RemoteError {}

pub(crate) struct HttpSyncRemote {
    proxied: reqwest::Client,
    direct: reqwest::Client,
}

impl HttpSyncRemote {
    pub(crate) fn new() -> Result<Self, RemoteError> {
        Ok(Self {
            proxied: client_builder(false)?,
            direct: client_builder(true)?,
        })
    }

    fn client_for(&self, endpoint: &Url) -> &reqwest::Client {
        if endpoint.scheme() == "http" && endpoint.host_str().is_some_and(is_loopback_host) {
            &self.direct
        } else {
            &self.proxied
        }
    }

    fn endpoint(access: &SessionAccess) -> Result<Url, RemoteError> {
        let endpoint = Url::parse(access.endpoint())
            .map_err(|_| RemoteError::new(RemoteErrorKind::InvalidEndpoint))?;
        let transport_allowed = endpoint.scheme() == "https"
            || (endpoint.scheme() == "http" && endpoint.host_str().is_some_and(is_loopback_host));
        let canonical = endpoint
            .as_str()
            .trim_end_matches('/')
            .eq(access.endpoint());
        if !transport_allowed
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || endpoint_authority(access.endpoint())
                .is_some_and(|authority| authority.contains('@'))
            || !canonical
        {
            return Err(RemoteError::new(RemoteErrorKind::InvalidEndpoint));
        }
        Ok(endpoint)
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        access: &SessionAccess,
        path: &str,
        timeout: Duration,
        max_body_bytes: usize,
    ) -> Result<T, RemoteError> {
        let endpoint = Self::endpoint(access)?;
        let url = endpoint
            .join(path)
            .map_err(|_| RemoteError::new(RemoteErrorKind::InvalidEndpoint))?;
        let response = self
            .client_for(&endpoint)
            .get(url)
            .bearer_auth(access.bearer())
            .timeout(timeout)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        decode_response(response, max_body_bytes).await
    }

    async fn post_json<B: serde::Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        access: &SessionAccess,
        path: &str,
        body: &B,
        timeout: Duration,
        max_body_bytes: usize,
    ) -> Result<T, RemoteError> {
        let endpoint = Self::endpoint(access)?;
        let url = endpoint
            .join(path)
            .map_err(|_| RemoteError::new(RemoteErrorKind::InvalidEndpoint))?;
        let response = self
            .client_for(&endpoint)
            .post(url)
            .bearer_auth(access.bearer())
            .json(body)
            .timeout(timeout)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        decode_response(response, max_body_bytes).await
    }

    async fn put_json_empty<B: Serialize + ?Sized>(
        &self,
        access: &SessionAccess,
        path: &str,
        body: &B,
        timeout: Duration,
    ) -> Result<(), RemoteError> {
        let endpoint = Self::endpoint(access)?;
        let url = endpoint
            .join(path)
            .map_err(|_| RemoteError::new(RemoteErrorKind::InvalidEndpoint))?;
        let response = self
            .client_for(&endpoint)
            .put(url)
            .bearer_auth(access.bearer())
            .json(body)
            .timeout(timeout)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        decode_empty_response(response).await
    }
}

impl SyncRemote for HttpSyncRemote {
    fn fetch_catalog<'a>(
        &'a self,
        access: &'a SessionAccess,
        timeout: Duration,
    ) -> RemoteFuture<'a, CatalogSnapshot> {
        Box::pin(async move {
            let list: VaultListWire = self
                .get_json(access, CATALOG_PATH, timeout, MAX_CATALOG_BODY_BYTES)
                .await?;
            let ids = validate_catalog_list(&list)
                .map_err(|_| RemoteError::new(RemoteErrorKind::Protocol))?;
            let mut vaults = Vec::with_capacity(ids.len());
            let mut retained_bytes = 0_usize;
            for (summary, vault_id) in list.vaults.iter().zip(ids) {
                // The path segment comes only from a parsed canonical UUID,
                // never from reflected server text.
                let path = format!("v1/vaults/{vault_id}");
                let detail = self
                    .get_json::<VaultDetailWire>(access, &path, timeout, MAX_DETAIL_BODY_BYTES)
                    .await?;
                let vault = validate_catalog_detail(summary, detail)
                    .map_err(|_| RemoteError::new(RemoteErrorKind::Protocol))?;
                let vault_bytes = vault
                    .slug()
                    .len()
                    .checked_add(vault.name().len())
                    .and_then(|total| total.checked_add(vault.vault_key_envelope().len()))
                    .and_then(|total| {
                        vault
                            .tags()
                            .iter()
                            .try_fold(total, |sum, tag| sum.checked_add(tag.len()))
                    })
                    .ok_or_else(|| RemoteError::new(RemoteErrorKind::BodyTooLarge))?;
                retained_bytes = retained_bytes
                    .checked_add(vault_bytes)
                    .filter(|total| *total <= MAX_RETAINED_CATALOG_BYTES)
                    .ok_or_else(|| RemoteError::new(RemoteErrorKind::BodyTooLarge))?;
                vaults.push(vault);
            }
            Ok(CatalogSnapshot::validated(vaults))
        })
    }

    fn pull_page<'a>(
        &'a self,
        access: &'a SessionAccess,
        vault_id: uuid::Uuid,
        plane: VaultPlane,
        cursor: Option<&'a SyncCursor>,
        timeout: Duration,
    ) -> RemoteFuture<'a, PullPageWire> {
        Box::pin(async move {
            let request = PullRequestWire {
                vault_id,
                cursor: cursor.map(SyncCursor::as_str),
                limit: PULL_PAGE_LIMIT,
            };
            match plane {
                VaultPlane::PersonalClient => self
                    .post_json::<_, PersonalPullPageWire>(
                        access,
                        PERSONAL_PULL_PATH,
                        &request,
                        timeout,
                        MAX_PULL_BODY_BYTES,
                    )
                    .await
                    .map(PullPageWire::Personal),
                VaultPlane::SharedServer => self
                    .post_json::<_, SharedPullPageWire>(
                        access,
                        SHARED_PULL_PATH,
                        &request,
                        timeout,
                        MAX_PULL_BODY_BYTES,
                    )
                    .await
                    .map(PullPageWire::Shared),
            }
        })
    }

    fn push<'a>(
        &'a self,
        access: &'a SessionAccess,
        vault: &'a super::model::ResolvedSyncVault,
        pending: &'a [super::model::PendingProof],
        timeout: Duration,
    ) -> RemoteFuture<'a, PushResponseWire> {
        Box::pin(async move {
            match vault.plane() {
                VaultPlane::PersonalClient => {
                    let request = personal_push_request(vault.scope(), pending)
                        .map_err(|_| RemoteError::new(RemoteErrorKind::Protocol))?;
                    self.post_json(
                        access,
                        PERSONAL_PUSH_PATH,
                        &request,
                        timeout,
                        MAX_PUSH_BODY_BYTES,
                    )
                    .await
                }
                VaultPlane::SharedServer => {
                    let request = shared_push_request(vault.scope(), vault.payload_key(), pending)
                        .map_err(|error| match error.kind() {
                            super::wire::WireErrorKind::Crypto => {
                                RemoteError::new(RemoteErrorKind::Protocol)
                            }
                            _ => RemoteError::new(RemoteErrorKind::Protocol),
                        })?;
                    self.post_json(
                        access,
                        SHARED_PUSH_PATH,
                        &request,
                        timeout,
                        MAX_PUSH_BODY_BYTES,
                    )
                    .await
                }
            }
        })
    }

    fn publish_personal_vault_key<'a>(
        &'a self,
        access: &'a SessionAccess,
        vault_id: uuid::Uuid,
        envelope: &'a [u8],
        timeout: Duration,
    ) -> RemoteFuture<'a, ()> {
        #[derive(Serialize)]
        struct Request<'a> {
            vault_key_enc: &'a [u8],
        }
        Box::pin(async move {
            if envelope.is_empty() || envelope.len() > 64 * 1_024 {
                return Err(RemoteError::new(RemoteErrorKind::Protocol));
            }
            self.put_json_empty(
                access,
                &format!("v1/vaults/{vault_id}/key"),
                &Request {
                    vault_key_enc: envelope,
                },
                timeout,
            )
            .await
        })
    }
}

fn client_builder(no_proxy: bool) -> Result<reqwest::Client, RemoteError> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false);
    if no_proxy {
        builder = builder.no_proxy();
    }
    builder
        .build()
        .map_err(|_| RemoteError::new(RemoteErrorKind::InvalidEndpoint))
}

async fn decode_response<T: DeserializeOwned>(
    mut response: reqwest::Response,
    max_body_bytes: usize,
) -> Result<T, RemoteError> {
    let status = response.status();
    if !status.is_success() {
        return Err(status_error(status));
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_body_bytes as u64)
    {
        return Err(RemoteError::new(RemoteErrorKind::BodyTooLarge));
    }

    // This wipes the application-owned response buffer on drop. reqwest may
    // retain transient transport buffers internally, which is outside this
    // crate's control; no plaintext body is formatted or logged here.
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| RemoteError::new(RemoteErrorKind::BodyTooLarge))?;
        if next_len > max_body_bytes {
            return Err(RemoteError::new(RemoteErrorKind::BodyTooLarge));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| RemoteError::new(RemoteErrorKind::Protocol))
}

async fn decode_empty_response(mut response: reqwest::Response) -> Result<(), RemoteError> {
    let status = response.status();
    if !status.is_success() {
        return Err(status_error(status));
    }
    let mut bytes = 0_usize;
    while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
        bytes = bytes
            .checked_add(chunk.len())
            .ok_or_else(|| RemoteError::new(RemoteErrorKind::BodyTooLarge))?;
        if bytes > 1_024 || chunk.iter().any(|byte| !byte.is_ascii_whitespace()) {
            return Err(RemoteError::new(RemoteErrorKind::Protocol));
        }
    }
    Ok(())
}

fn status_error(status: StatusCode) -> RemoteError {
    let kind = if status == StatusCode::UNAUTHORIZED {
        RemoteErrorKind::SessionExpired
    } else if status == StatusCode::CONFLICT {
        RemoteErrorKind::Conflict
    } else if status.is_client_error() {
        RemoteErrorKind::Rejected
    } else if status.is_server_error() {
        RemoteErrorKind::Server
    } else {
        RemoteErrorKind::Protocol
    };
    RemoteError::new(kind).with_status(status)
}

fn map_reqwest_error(error: reqwest::Error) -> RemoteError {
    if error.is_timeout() {
        RemoteError::new(RemoteErrorKind::Timeout)
    } else if error.is_decode() || error.is_body() {
        RemoteError::new(RemoteErrorKind::Protocol)
    } else {
        RemoteError::new(RemoteErrorKind::Unavailable)
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn endpoint_authority(endpoint: &str) -> Option<&str> {
    endpoint
        .split_once("://")
        .map(|(_, remainder)| remainder.split(['/', '?', '#']).next().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use zann_core::ChangeType;

    use super::*;
    use crate::sync::model::{MAX_CIPHERTEXT_BYTES, MAX_HISTORY_PER_ITEM};
    use crate::sync::wire::{PersonalHistoryWire, PersonalPullChangeWire};

    fn cursor(sequence: i64) -> String {
        base64::engine::general_purpose::STANDARD.encode(
            serde_json::to_vec(&serde_json::json!({ "seq": sequence }))
                .expect("serialize test cursor"),
        )
    }

    #[test]
    fn maximum_legal_personal_page_fits_fixed_transport_cap() {
        let mut changes = Vec::with_capacity(PULL_PAGE_LIMIT);
        for index in 0..PULL_PAGE_LIMIT {
            let item_id = uuid::Uuid::now_v7();
            let history = (0..MAX_HISTORY_PER_ITEM)
                .map(|history_index| PersonalHistoryWire {
                    version: i64::try_from(MAX_HISTORY_PER_ITEM - history_index)
                        .expect("history version fits i64"),
                    checksum: "ff".repeat(32),
                    change_type: ChangeType::Update.as_i32(),
                    changed_by_name: Some("n".repeat(200)),
                    changed_by_email: format!("{}@example.test", "a".repeat(307)),
                    created_at: "2025-01-02T03:04:05Z".to_string(),
                    payload_enc: vec![u8::MAX; MAX_CIPHERTEXT_BYTES],
                })
                .collect();
            changes.push(PersonalPullChangeWire {
                item_id: item_id.to_string(),
                operation: ChangeType::Update.as_i32(),
                seq: i64::try_from(index).expect("page index fits i64") + 1,
                updated_at: "2025-01-02T03:04:05Z".to_string(),
                checksum: "ff".repeat(32),
                payload_enc: Some(vec![u8::MAX; MAX_CIPHERTEXT_BYTES]),
                path: format!("items/{item_id}"),
                name: item_id.to_string(),
                type_id: "login".to_string(),
                history,
            });
        }
        let page = PersonalPullPageWire {
            changes,
            next_cursor: cursor(i64::try_from(PULL_PAGE_LIMIT).expect("page limit fits i64")),
            has_more: false,
            push_available: false,
        };
        let encoded = serde_json::to_vec(&page).expect("serialize maximum legal page");
        assert!(
            encoded.len() <= MAX_PULL_BODY_BYTES,
            "legal page is {} bytes but transport cap is {MAX_PULL_BODY_BYTES}",
            encoded.len()
        );
    }

    #[test]
    fn catalog_request_uses_explicit_bounded_first_page() {
        assert_eq!(CATALOG_PATH, "v1/vaults?limit=200&offset=0&sort=asc");
    }
}
