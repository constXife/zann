//! Strict adapters from server JSON into persistence-independent sync models.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zann_core::{CachePolicy, ChangeType, VaultEncryptionType, VaultKind};
use zann_crypto::EncryptedPayload;
use zeroize::Zeroizing;

use super::model::{
    validate_path, validate_required, CatalogVault, ContentChecksum, HistoryProjection,
    ItemProjection, ItemState, PendingProof, PushCommitChange, SyncCursor, SyncModelError,
    SyncScope, SyncSeq, VaultPayloadKey, VaultPlane, MAX_CATALOG_VAULTS, MAX_CIPHERTEXT_BYTES,
    MAX_DISPLAY_NAME_BYTES, MAX_EMAIL_BYTES, MAX_HISTORY_PER_ITEM, MAX_ITEM_NAME_BYTES,
    MAX_PAYLOAD_BYTES, MAX_TYPE_ID_BYTES, PULL_PAGE_LIMIT,
};

#[cfg(test)]
use super::model::CatalogSnapshot;

const MAX_SLUG_BYTES: usize = 128;
const MAX_TAGS: usize = 64;
const MAX_TAG_BYTES: usize = 128;
const MAX_KEY_ENVELOPE_BYTES: usize = 64 * 1_024;

#[derive(Deserialize)]
pub(crate) struct VaultListWire {
    pub(crate) vaults: Vec<VaultSummaryWire>,
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
pub(crate) struct VaultSummaryWire {
    pub(crate) id: String,
    pub(crate) slug: String,
    pub(crate) name: String,
    pub(crate) kind: i32,
    pub(crate) cache_policy: i32,
    pub(crate) tags: Option<Vec<String>>,
}

#[derive(Clone, Deserialize)]
pub(crate) struct VaultDetailWire {
    pub(crate) id: String,
    pub(crate) slug: String,
    pub(crate) name: String,
    pub(crate) kind: i32,
    pub(crate) cache_policy: i32,
    pub(crate) vault_key_enc: Vec<u8>,
    pub(crate) encryption_type: i32,
    pub(crate) tags: Option<Vec<String>>,
    pub(crate) created_at: String,
}

#[derive(Serialize)]
pub(crate) struct PullRequestWire<'a> {
    pub(crate) vault_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cursor: Option<&'a str>,
    pub(crate) limit: usize,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub(crate) struct PersonalPullPageWire {
    pub(crate) changes: Vec<PersonalPullChangeWire>,
    pub(crate) next_cursor: String,
    pub(crate) has_more: bool,
    pub(crate) push_available: bool,
}

#[derive(Deserialize)]
pub(crate) struct SharedPullPageWire {
    pub(crate) changes: Vec<SharedPullChangeWire>,
    pub(crate) next_cursor: String,
    pub(crate) has_more: bool,
    pub(crate) push_available: bool,
}

pub(crate) enum PullPageWire {
    Personal(PersonalPullPageWire),
    Shared(SharedPullPageWire),
}

#[derive(Serialize)]
pub(crate) struct PersonalPushRequestWire<'a> {
    pub(crate) vault_id: Uuid,
    pub(crate) changes: Vec<PersonalPushChangeWire<'a>>,
}

#[derive(Serialize)]
pub(crate) struct PersonalPushChangeWire<'a> {
    pub(crate) item_id: Uuid,
    pub(crate) operation: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) payload_enc: Option<&'a [u8]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) checksum: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) type_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) base_seq: Option<i64>,
}

#[derive(Serialize)]
pub(crate) struct SharedPushRequestWire {
    pub(crate) vault_id: Uuid,
    pub(crate) changes: Vec<SharedPushChangeWire>,
}

#[derive(Serialize)]
pub(crate) struct SharedPushChangeWire {
    pub(crate) item_id: Uuid,
    pub(crate) operation: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) payload: Option<EncryptedPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) type_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) base_seq: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct PushResponseWire {
    pub(crate) applied: Vec<String>,
    #[serde(default)]
    pub(crate) applied_changes: Vec<AppliedPushChangeWire>,
    #[serde(default)]
    pub(crate) conflicts: Vec<PushConflictWire>,
    pub(crate) new_cursor: String,
}

#[derive(Deserialize)]
pub(crate) struct AppliedPushChangeWire {
    pub(crate) item_id: String,
    pub(crate) seq: i64,
    pub(crate) updated_at: String,
    pub(crate) deleted_at: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct PushConflictWire {
    pub(crate) item_id: String,
    pub(crate) reason: String,
    pub(crate) server_seq: i64,
    pub(crate) server_updated_at: String,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub(crate) struct PersonalPullChangeWire {
    pub(crate) item_id: String,
    pub(crate) operation: i32,
    pub(crate) seq: i64,
    pub(crate) updated_at: String,
    pub(crate) checksum: String,
    pub(crate) payload_enc: Option<Vec<u8>>,
    pub(crate) path: String,
    pub(crate) name: String,
    pub(crate) type_id: String,
    #[serde(default)]
    pub(crate) history: Vec<PersonalHistoryWire>,
}

#[derive(Deserialize)]
pub(crate) struct SharedPullChangeWire {
    pub(crate) item_id: String,
    pub(crate) operation: i32,
    pub(crate) seq: i64,
    pub(crate) updated_at: String,
    pub(crate) checksum: String,
    pub(crate) payload: Option<EncryptedPayload>,
    pub(crate) path: String,
    pub(crate) name: String,
    pub(crate) type_id: String,
    #[serde(default)]
    pub(crate) history: Vec<SharedHistoryWire>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub(crate) struct PersonalHistoryWire {
    pub(crate) version: i64,
    pub(crate) checksum: String,
    pub(crate) change_type: i32,
    pub(crate) changed_by_name: Option<String>,
    pub(crate) changed_by_email: String,
    pub(crate) created_at: String,
    pub(crate) payload_enc: Vec<u8>,
}

#[derive(Deserialize)]
pub(crate) struct SharedHistoryWire {
    pub(crate) version: i64,
    pub(crate) checksum: String,
    pub(crate) change_type: i32,
    pub(crate) changed_by_name: Option<String>,
    pub(crate) changed_by_email: String,
    pub(crate) created_at: String,
    pub(crate) payload: EncryptedPayload,
}

pub(crate) struct ValidatedPullPage {
    pub(crate) changes: Vec<ValidatedPullChange>,
    pub(crate) wire_change_count: usize,
    pub(crate) next_cursor: SyncCursor,
    pub(crate) has_more: bool,
    pub(crate) push_available: bool,
    pub(crate) last_seq: Option<SyncSeq>,
}

pub(crate) struct ValidatedPullChange {
    pub(crate) item: ItemProjection,
    pub(crate) history: Vec<HistoryProjection>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireErrorKind {
    Catalog,
    Page,
    Cursor,
    Sequence,
    Timestamp,
    Enum,
    Checksum,
    Payload,
    Crypto,
    Conflict,
    Limit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WireError {
    kind: WireErrorKind,
}

impl WireError {
    const fn new(kind: WireErrorKind) -> Self {
        Self { kind }
    }

    pub(crate) const fn kind(self) -> WireErrorKind {
        self.kind
    }
}

impl std::fmt::Display for WireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid sync wire response: {:?}", self.kind)
    }
}

impl std::error::Error for WireError {}

impl From<SyncModelError> for WireError {
    fn from(error: SyncModelError) -> Self {
        let kind = match error {
            SyncModelError::InvalidCursor => WireErrorKind::Cursor,
            SyncModelError::InvalidSequence => WireErrorKind::Sequence,
            SyncModelError::InvalidChecksum => WireErrorKind::Checksum,
            SyncModelError::PayloadTooLarge => WireErrorKind::Limit,
            SyncModelError::CatalogTooLarge => WireErrorKind::Catalog,
            SyncModelError::PageTooLarge => WireErrorKind::Page,
            _ => WireErrorKind::Page,
        };
        Self::new(kind)
    }
}

#[cfg(test)]
pub(crate) fn validate_catalog(
    list: VaultListWire,
    details: Vec<VaultDetailWire>,
) -> Result<CatalogSnapshot, WireError> {
    let ordered_ids = validate_catalog_list(&list)?;
    if details.len() != list.vaults.len() {
        return Err(WireError::new(WireErrorKind::Catalog));
    }
    let summaries = list
        .vaults
        .iter()
        .map(|summary| Ok((parse_uuid(&summary.id)?, summary)))
        .collect::<Result<HashMap<_, _>, WireError>>()?;
    let mut validated = Vec::with_capacity(details.len());
    let mut detail_ids = HashSet::with_capacity(details.len());
    for detail in details {
        let id = parse_uuid(&detail.id)?;
        if !detail_ids.insert(id) {
            return Err(WireError::new(WireErrorKind::Catalog));
        }
        let summary = summaries
            .get(&id)
            .ok_or_else(|| WireError::new(WireErrorKind::Catalog))?;
        validated.push(validate_catalog_detail(summary, detail)?);
    }

    // Preserve the server's list order rather than detail-fetch completion order.
    let mut by_id = validated
        .into_iter()
        .map(|vault| (vault.id(), vault))
        .collect::<HashMap<_, _>>();
    let mut ordered = Vec::with_capacity(summaries.len());
    for id in ordered_ids {
        let vault = by_id
            .remove(&id)
            .ok_or_else(|| WireError::new(WireErrorKind::Catalog))?;
        ordered.push(vault);
    }
    Ok(CatalogSnapshot::validated(ordered))
}

/// Validates every summary before any authenticated detail request is built.
pub(crate) fn validate_catalog_list(list: &VaultListWire) -> Result<Vec<Uuid>, WireError> {
    if list.vaults.len() > MAX_CATALOG_VAULTS {
        return Err(WireError::new(WireErrorKind::Catalog));
    }
    let mut ids = Vec::with_capacity(list.vaults.len());
    let mut unique = HashSet::with_capacity(list.vaults.len());
    for summary in &list.vaults {
        validate_catalog_text(&summary.slug, &summary.name, summary.tags.as_deref())?;
        let id = parse_uuid(&summary.id)?;
        validate_full_plane(summary.kind, summary.cache_policy, None)?;
        if !unique.insert(id) {
            return Err(WireError::new(WireErrorKind::Catalog));
        }
        ids.push(id);
    }
    Ok(ids)
}

/// Validates and consumes one detail immediately, keeping at most one raw
/// detail response resident in memory during transport catalog expansion.
pub(crate) fn validate_catalog_detail(
    summary: &VaultSummaryWire,
    detail: VaultDetailWire,
) -> Result<CatalogVault, WireError> {
    validate_catalog_text(&detail.slug, &detail.name, detail.tags.as_deref())?;
    let id = parse_uuid(&detail.id)?;
    if summary.id != detail.id
        || summary.slug != detail.slug
        || summary.name != detail.name
        || summary.kind != detail.kind
        || summary.cache_policy != detail.cache_policy
        || summary.tags != detail.tags
    {
        return Err(WireError::new(WireErrorKind::Catalog));
    }
    let plane = validate_full_plane(
        detail.kind,
        detail.cache_policy,
        Some(detail.encryption_type),
    )?;
    if detail.vault_key_enc.len() > MAX_KEY_ENVELOPE_BYTES
        || (detail.vault_key_enc.is_empty() && plane != VaultPlane::PersonalClient)
    {
        return Err(WireError::new(WireErrorKind::Limit));
    }
    let created_at = strict_timestamp(&detail.created_at)?;
    Ok(CatalogVault::validated(
        id,
        detail.slug,
        detail.name,
        plane,
        detail.tags.unwrap_or_default(),
        created_at,
        detail.vault_key_enc,
    ))
}

fn validate_catalog_text(slug: &str, name: &str, tags: Option<&[String]>) -> Result<(), WireError> {
    validate_required(slug, MAX_SLUG_BYTES)?;
    validate_required(name, MAX_DISPLAY_NAME_BYTES)?;
    if !slug
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(WireError::new(WireErrorKind::Catalog));
    }
    let tags = tags.unwrap_or_default();
    if tags.len() > MAX_TAGS {
        return Err(WireError::new(WireErrorKind::Limit));
    }
    let mut unique = HashSet::with_capacity(tags.len());
    for tag in tags {
        validate_required(tag, MAX_TAG_BYTES)?;
        if !unique.insert(tag) {
            return Err(WireError::new(WireErrorKind::Catalog));
        }
    }
    Ok(())
}

fn validate_full_plane(
    kind: i32,
    cache_policy: i32,
    encryption_type: Option<i32>,
) -> Result<VaultPlane, WireError> {
    let kind = VaultKind::try_from(kind).map_err(|_| WireError::new(WireErrorKind::Enum))?;
    let cache =
        CachePolicy::try_from(cache_policy).map_err(|_| WireError::new(WireErrorKind::Enum))?;
    if cache != CachePolicy::Full {
        return Err(WireError::new(WireErrorKind::Catalog));
    }
    match encryption_type {
        None => match kind {
            VaultKind::Personal => Ok(VaultPlane::PersonalClient),
            VaultKind::Shared => Ok(VaultPlane::SharedServer),
        },
        Some(value) => {
            let encryption = VaultEncryptionType::try_from(value)
                .map_err(|_| WireError::new(WireErrorKind::Enum))?;
            match (kind, encryption) {
                (VaultKind::Personal, VaultEncryptionType::Client) => {
                    Ok(VaultPlane::PersonalClient)
                }
                (VaultKind::Shared, VaultEncryptionType::Server) => Ok(VaultPlane::SharedServer),
                _ => Err(WireError::new(WireErrorKind::Catalog)),
            }
        }
    }
}

pub(crate) fn validate_personal_page(
    scope: SyncScope,
    expected_cursor: Option<&SyncCursor>,
    prior_seq: Option<SyncSeq>,
    key: &VaultPayloadKey,
    page: PersonalPullPageWire,
) -> Result<ValidatedPullPage, WireError> {
    let wire_change_count = page.changes.len();
    let next_cursor = validate_page_shape(
        page.changes.len(),
        &page.next_cursor,
        page.has_more,
        expected_cursor,
    )?;
    let mut last_seq = prior_seq;
    let mut validated = Vec::with_capacity(page.changes.len());
    for change in page.changes {
        let seq = validate_next_seq(change.seq, last_seq)?;
        last_seq = Some(seq);
        validated.push(validate_personal_change(scope, key, change, seq)?);
    }
    validate_cursor_sequence(&next_cursor, last_seq)?;
    Ok(ValidatedPullPage {
        changes: coalesce_after_validation(validated),
        wire_change_count,
        next_cursor,
        has_more: page.has_more,
        push_available: page.push_available,
        last_seq,
    })
}

pub(crate) fn validate_shared_page(
    scope: SyncScope,
    expected_cursor: Option<&SyncCursor>,
    prior_seq: Option<SyncSeq>,
    key: &VaultPayloadKey,
    page: SharedPullPageWire,
) -> Result<ValidatedPullPage, WireError> {
    let wire_change_count = page.changes.len();
    let next_cursor = validate_page_shape(
        page.changes.len(),
        &page.next_cursor,
        page.has_more,
        expected_cursor,
    )?;
    let mut last_seq = prior_seq;
    let mut validated = Vec::with_capacity(page.changes.len());
    for change in page.changes {
        let seq = validate_next_seq(change.seq, last_seq)?;
        last_seq = Some(seq);
        validated.push(validate_shared_change(scope, key, change, seq)?);
    }
    validate_cursor_sequence(&next_cursor, last_seq)?;
    Ok(ValidatedPullPage {
        changes: coalesce_after_validation(validated),
        wire_change_count,
        next_cursor,
        has_more: page.has_more,
        push_available: page.push_available,
        last_seq,
    })
}

fn validate_page_shape(
    change_count: usize,
    next_cursor: &str,
    has_more: bool,
    expected_cursor: Option<&SyncCursor>,
) -> Result<SyncCursor, WireError> {
    if change_count > PULL_PAGE_LIMIT || (has_more && change_count == 0) {
        return Err(WireError::new(WireErrorKind::Limit));
    }
    let next = SyncCursor::new(next_cursor)?;
    if change_count > 0 && expected_cursor.is_some_and(|cursor| cursor == &next) {
        return Err(WireError::new(WireErrorKind::Cursor));
    }
    Ok(next)
}

fn validate_cursor_sequence(
    cursor: &SyncCursor,
    last_seq: Option<SyncSeq>,
) -> Result<(), WireError> {
    let expected = last_seq.map(SyncSeq::get).unwrap_or(0);
    if cursor.sequence() != expected {
        return Err(WireError::new(WireErrorKind::Cursor));
    }
    Ok(())
}

fn validate_next_seq(value: i64, previous: Option<SyncSeq>) -> Result<SyncSeq, WireError> {
    let seq = SyncSeq::new(value)?;
    if previous.is_some_and(|previous| seq <= previous) {
        return Err(WireError::new(WireErrorKind::Sequence));
    }
    Ok(seq)
}

fn validate_personal_change(
    scope: SyncScope,
    key: &VaultPayloadKey,
    change: PersonalPullChangeWire,
    seq: SyncSeq,
) -> Result<ValidatedPullChange, WireError> {
    let item_id = parse_uuid(&change.item_id)?;
    let operation = pull_operation(change.operation)?;
    validate_item_metadata(&change.path, &change.name, &change.type_id)?;
    let updated_at = strict_timestamp(&change.updated_at)?;
    let server_checksum = ContentChecksum::parse(&change.checksum)?;

    let (payload_enc, checksum, deleted_at) = match operation {
        ChangeType::Create | ChangeType::Update => {
            let payload = change
                .payload_enc
                .ok_or_else(|| WireError::new(WireErrorKind::Payload))?;
            validate_ciphertext(&payload)?;
            if ContentChecksum::for_ciphertext(&payload)? != server_checksum {
                return Err(WireError::new(WireErrorKind::Checksum));
            }
            let decoded =
                zann_crypto::decrypt_payload(key.expose(), scope.vault_id(), item_id, &payload)
                    .map_err(|_| WireError::new(WireErrorKind::Crypto))?;
            validate_typed_payload(&decoded, &change.type_id)?;
            (payload, server_checksum, None)
        }
        ChangeType::Delete => {
            if change.payload_enc.is_some() {
                return Err(WireError::new(WireErrorKind::Payload));
            }
            let empty = Vec::new();
            let checksum = ContentChecksum::for_ciphertext(&empty)?;
            (empty, checksum, Some(updated_at))
        }
        ChangeType::Restore => return Err(WireError::new(WireErrorKind::Enum)),
    };

    let history = validate_personal_history(scope, item_id, &change.type_id, key, change.history)?;
    Ok(ValidatedPullChange {
        item: ItemProjection::validated(
            scope,
            item_id,
            change.path,
            change.name,
            change.type_id,
            payload_enc,
            checksum,
            key.cache_key_fingerprint().to_string(),
            seq,
            updated_at,
            deleted_at,
        ),
        history,
    })
}

fn validate_shared_change(
    scope: SyncScope,
    key: &VaultPayloadKey,
    change: SharedPullChangeWire,
    seq: SyncSeq,
) -> Result<ValidatedPullChange, WireError> {
    let item_id = parse_uuid(&change.item_id)?;
    let operation = pull_operation(change.operation)?;
    validate_item_metadata(&change.path, &change.name, &change.type_id)?;
    let updated_at = strict_timestamp(&change.updated_at)?;
    // Validate the server checksum's syntax, but never retain it for a shared
    // plaintext response. The local checksum covers the new local ciphertext.
    let _server_checksum = ContentChecksum::parse(&change.checksum)?;

    let (payload_enc, checksum, deleted_at) = match operation {
        ChangeType::Create | ChangeType::Update => {
            let payload = change
                .payload
                .ok_or_else(|| WireError::new(WireErrorKind::Payload))?;
            let decoded = decode_plaintext_payload(payload, &change.type_id)?;
            let payload_enc =
                zann_crypto::encrypt_payload(key.expose(), scope.vault_id(), item_id, &decoded)
                    .map_err(|_| WireError::new(WireErrorKind::Crypto))?;
            let checksum = ContentChecksum::for_ciphertext(&payload_enc)?;
            (payload_enc, checksum, None)
        }
        ChangeType::Delete => {
            if change.payload.is_some() {
                return Err(WireError::new(WireErrorKind::Payload));
            }
            let empty = Vec::new();
            let checksum = ContentChecksum::for_ciphertext(&empty)?;
            (empty, checksum, Some(updated_at))
        }
        ChangeType::Restore => return Err(WireError::new(WireErrorKind::Enum)),
    };

    let history = validate_shared_history(scope, item_id, &change.type_id, key, change.history)?;
    Ok(ValidatedPullChange {
        item: ItemProjection::validated(
            scope,
            item_id,
            change.path,
            change.name,
            change.type_id,
            payload_enc,
            checksum,
            key.cache_key_fingerprint().to_string(),
            seq,
            updated_at,
            deleted_at,
        ),
        history,
    })
}

pub(crate) fn personal_push_request<'a>(
    scope: SyncScope,
    pending: &'a [PendingProof],
) -> Result<PersonalPushRequestWire<'a>, WireError> {
    let changes = pending
        .iter()
        .map(|proof| {
            if proof.scope() != scope {
                return Err(WireError::new(WireErrorKind::Page));
            }
            Ok(PersonalPushChangeWire {
                item_id: proof.item_id(),
                operation: proof.operation().as_i32(),
                payload_enc: proof.payload_enc(),
                checksum: proof.checksum().map(ContentChecksum::to_hex),
                path: proof.path(),
                name: proof.name(),
                type_id: proof.type_id(),
                base_seq: proof.base_seq().map(SyncSeq::get),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PersonalPushRequestWire {
        vault_id: scope.vault_id(),
        changes,
    })
}

pub(crate) fn shared_push_request(
    scope: SyncScope,
    key: &VaultPayloadKey,
    pending: &[PendingProof],
) -> Result<SharedPushRequestWire, WireError> {
    let changes = pending
        .iter()
        .map(|proof| {
            if proof.scope() != scope {
                return Err(WireError::new(WireErrorKind::Page));
            }
            let payload = proof
                .payload_enc()
                .map(|payload| {
                    zann_crypto::decrypt_payload(
                        key.expose(),
                        scope.vault_id(),
                        proof.item_id(),
                        payload,
                    )
                    .map_err(|_| WireError::new(WireErrorKind::Crypto))
                })
                .transpose()?;
            if let (Some(payload), Some(type_id)) = (payload.as_ref(), proof.type_id()) {
                validate_typed_payload(payload, type_id)?;
            }
            Ok(SharedPushChangeWire {
                item_id: proof.item_id(),
                operation: proof.operation().as_i32(),
                payload,
                path: proof.path().map(str::to_string),
                name: proof.name().map(str::to_string),
                type_id: proof.type_id().map(str::to_string),
                base_seq: proof.base_seq().map(SyncSeq::get),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SharedPushRequestWire {
        vault_id: scope.vault_id(),
        changes,
    })
}

pub(crate) fn validate_push_response(
    scope: SyncScope,
    key: &VaultPayloadKey,
    pending: Vec<PendingProof>,
    states: Vec<ItemState>,
    response: PushResponseWire,
) -> Result<(SyncCursor, Vec<PushCommitChange>), WireError> {
    let server_head = SyncCursor::new(response.new_cursor)?;
    let expected_ids = pending
        .iter()
        .map(PendingProof::item_id)
        .collect::<HashSet<_>>();
    if expected_ids.len() != pending.len() || states.len() != pending.len() {
        return Err(WireError::new(WireErrorKind::Page));
    }
    for conflict in &response.conflicts {
        let item_id = parse_uuid(&conflict.item_id)?;
        validate_required(&conflict.reason, MAX_DISPLAY_NAME_BYTES)?;
        let _ = SyncSeq::new(conflict.server_seq)?;
        let _ = strict_timestamp(&conflict.server_updated_at)?;
        if !expected_ids.contains(&item_id) {
            return Err(WireError::new(WireErrorKind::Page));
        }
    }
    if !response.conflicts.is_empty() {
        return Err(WireError::new(WireErrorKind::Conflict));
    }

    let applied_ids = response
        .applied
        .iter()
        .map(|value| parse_uuid(value))
        .collect::<Result<HashSet<_>, _>>()?;
    if applied_ids != expected_ids || response.applied_changes.len() != pending.len() {
        return Err(WireError::new(WireErrorKind::Page));
    }
    let mut applied = HashMap::with_capacity(response.applied_changes.len());
    for change in response.applied_changes {
        let item_id = parse_uuid(&change.item_id)?;
        if !expected_ids.contains(&item_id) || applied.contains_key(&item_id) {
            return Err(WireError::new(WireErrorKind::Page));
        }
        let seq = SyncSeq::new(change.seq)?;
        let updated_at = strict_timestamp(&change.updated_at)?;
        let deleted_at = change
            .deleted_at
            .as_deref()
            .map(strict_timestamp)
            .transpose()?;
        if deleted_at.is_some_and(|deleted| deleted != updated_at) {
            return Err(WireError::new(WireErrorKind::Timestamp));
        }
        applied.insert(item_id, (seq, updated_at, deleted_at));
    }

    let mut state_by_id = states
        .into_iter()
        .map(|state| (state.item_id(), state))
        .collect::<HashMap<_, _>>();
    let mut changes = Vec::with_capacity(pending.len());
    for proof in pending {
        let item_id = proof.item_id();
        let state = state_by_id
            .remove(&item_id)
            .ok_or_else(|| WireError::new(WireErrorKind::Page))?;
        let local = state
            .exact_proof()
            .ok_or_else(|| WireError::new(WireErrorKind::Page))?
            .projection();
        let (seq, updated_at, deleted_at) = applied
            .remove(&item_id)
            .ok_or_else(|| WireError::new(WireErrorKind::Page))?;
        let expected_deleted = matches!(proof.operation(), ChangeType::Delete);
        if deleted_at.is_some() != expected_deleted {
            return Err(WireError::new(WireErrorKind::Page));
        }
        let item = ItemProjection::validated(
            scope,
            item_id,
            local.path().to_string(),
            local.name().to_string(),
            local.type_id().to_string(),
            local.payload_enc().to_vec(),
            local.checksum(),
            key.cache_key_fingerprint().to_string(),
            seq,
            updated_at,
            deleted_at,
        );
        changes.push(PushCommitChange::validated(proof, state, item)?);
    }
    if !applied.is_empty() || !state_by_id.is_empty() {
        return Err(WireError::new(WireErrorKind::Page));
    }
    Ok((server_head, changes))
}

fn validate_personal_history(
    scope: SyncScope,
    item_id: Uuid,
    type_id: &str,
    key: &VaultPayloadKey,
    history: Vec<PersonalHistoryWire>,
) -> Result<Vec<HistoryProjection>, WireError> {
    validate_history_count(&history)?;
    let mut previous = None;
    let mut output = Vec::with_capacity(history.len());
    for entry in history {
        let version = validate_descending_version(entry.version, previous)?;
        previous = Some(version);
        let change_type = history_operation(entry.change_type)?;
        validate_actor(&entry.changed_by_email, entry.changed_by_name.as_deref())?;
        let created_at = strict_timestamp(&entry.created_at)?;
        validate_ciphertext(&entry.payload_enc)?;
        let checksum = ContentChecksum::parse(&entry.checksum)?;
        if ContentChecksum::for_ciphertext(&entry.payload_enc)? != checksum {
            return Err(WireError::new(WireErrorKind::Checksum));
        }
        let decoded = zann_crypto::decrypt_payload(
            key.expose(),
            scope.vault_id(),
            item_id,
            &entry.payload_enc,
        )
        .map_err(|_| WireError::new(WireErrorKind::Crypto))?;
        validate_typed_payload(&decoded, type_id)?;
        output.push(HistoryProjection::validated(
            Uuid::now_v7(),
            scope,
            item_id,
            entry.payload_enc,
            checksum,
            version,
            change_type,
            entry.changed_by_email,
            entry.changed_by_name,
            created_at,
        ));
    }
    Ok(output)
}

fn validate_shared_history(
    scope: SyncScope,
    item_id: Uuid,
    type_id: &str,
    key: &VaultPayloadKey,
    history: Vec<SharedHistoryWire>,
) -> Result<Vec<HistoryProjection>, WireError> {
    validate_history_count(&history)?;
    let mut previous = None;
    let mut output = Vec::with_capacity(history.len());
    for entry in history {
        let version = validate_descending_version(entry.version, previous)?;
        previous = Some(version);
        let change_type = history_operation(entry.change_type)?;
        validate_actor(&entry.changed_by_email, entry.changed_by_name.as_deref())?;
        let created_at = strict_timestamp(&entry.created_at)?;
        let _server_checksum = ContentChecksum::parse(&entry.checksum)?;
        let decoded = decode_plaintext_payload(entry.payload, type_id)?;
        let payload_enc =
            zann_crypto::encrypt_payload(key.expose(), scope.vault_id(), item_id, &decoded)
                .map_err(|_| WireError::new(WireErrorKind::Crypto))?;
        let checksum = ContentChecksum::for_ciphertext(&payload_enc)?;
        output.push(HistoryProjection::validated(
            Uuid::now_v7(),
            scope,
            item_id,
            payload_enc,
            checksum,
            version,
            change_type,
            entry.changed_by_email,
            entry.changed_by_name,
            created_at,
        ));
    }
    Ok(output)
}

fn validate_history_count<T>(history: &[T]) -> Result<(), WireError> {
    if history.len() > MAX_HISTORY_PER_ITEM {
        return Err(WireError::new(WireErrorKind::Limit));
    }
    Ok(())
}

fn validate_descending_version(
    value: i64,
    previous: Option<SyncSeq>,
) -> Result<SyncSeq, WireError> {
    let version = SyncSeq::new(value)?;
    if previous.is_some_and(|previous| version >= previous) {
        return Err(WireError::new(WireErrorKind::Sequence));
    }
    Ok(version)
}

fn validate_actor(email: &str, name: Option<&str>) -> Result<(), WireError> {
    validate_required(email, MAX_EMAIL_BYTES)?;
    if let Some(name) = name {
        validate_required(name, MAX_DISPLAY_NAME_BYTES)?;
    }
    Ok(())
}

fn validate_item_metadata(path: &str, name: &str, type_id: &str) -> Result<(), WireError> {
    validate_path(path)?;
    validate_required(name, MAX_ITEM_NAME_BYTES)?;
    validate_required(type_id, MAX_TYPE_ID_BYTES)?;
    if path.rsplit('/').next() != Some(name) {
        return Err(WireError::new(WireErrorKind::Page));
    }
    Ok(())
}

fn validate_ciphertext(payload: &[u8]) -> Result<(), WireError> {
    if payload.is_empty() || payload.len() > MAX_CIPHERTEXT_BYTES {
        return Err(WireError::new(WireErrorKind::Limit));
    }
    Ok(())
}

fn decode_plaintext_payload(
    payload: EncryptedPayload,
    type_id: &str,
) -> Result<EncryptedPayload, WireError> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(&payload).map_err(|_| WireError::new(WireErrorKind::Payload))?,
    );
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(WireError::new(WireErrorKind::Limit));
    }
    validate_typed_payload(&payload, type_id)?;
    Ok(payload)
}

fn validate_typed_payload(payload: &EncryptedPayload, type_id: &str) -> Result<(), WireError> {
    if payload.v != 1 || payload.type_id != type_id {
        return Err(WireError::new(WireErrorKind::Payload));
    }
    validate_required(&payload.type_id, MAX_TYPE_ID_BYTES)?;
    Ok(())
}

fn pull_operation(value: i32) -> Result<ChangeType, WireError> {
    let operation = ChangeType::try_from(value).map_err(|_| WireError::new(WireErrorKind::Enum))?;
    match operation {
        ChangeType::Create | ChangeType::Update | ChangeType::Delete => Ok(operation),
        ChangeType::Restore => Err(WireError::new(WireErrorKind::Enum)),
    }
}

fn history_operation(value: i32) -> Result<ChangeType, WireError> {
    ChangeType::try_from(value).map_err(|_| WireError::new(WireErrorKind::Enum))
}

fn parse_uuid(value: &str) -> Result<Uuid, WireError> {
    let id = Uuid::parse_str(value).map_err(|_| WireError::new(WireErrorKind::Catalog))?;
    if id.is_nil() || id.to_string() != value {
        return Err(WireError::new(WireErrorKind::Catalog));
    }
    Ok(id)
}

fn strict_timestamp(value: &str) -> Result<DateTime<Utc>, WireError> {
    if value.is_empty()
        || value.len() > 64
        || value.trim() != value
        || !value.contains('T')
        || !(value.ends_with('Z') || value.ends_with("+00:00"))
    {
        return Err(WireError::new(WireErrorKind::Timestamp));
    }
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| WireError::new(WireErrorKind::Timestamp))?;
    if parsed.offset().local_minus_utc() != 0 {
        return Err(WireError::new(WireErrorKind::Timestamp));
    }
    Ok(parsed.with_timezone(&Utc))
}

fn coalesce_after_validation(changes: Vec<ValidatedPullChange>) -> Vec<ValidatedPullChange> {
    let mut by_item = HashMap::with_capacity(changes.len());
    for change in changes {
        by_item.insert(change.item.item_id(), change);
    }
    let mut changes = by_item.into_values().collect::<Vec<_>>();
    changes.sort_by_key(|change| change.item.seq());
    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog_list(count: usize) -> VaultListWire {
        VaultListWire {
            vaults: (0..count)
                .map(|index| VaultSummaryWire {
                    id: Uuid::now_v7().to_string(),
                    slug: format!("vault-{index}"),
                    name: format!("Vault {index}"),
                    kind: VaultKind::Personal.as_i32(),
                    cache_policy: CachePolicy::Full.as_i32(),
                    tags: Some(vec!["test".to_string()]),
                })
                .collect(),
        }
    }

    #[test]
    fn catalog_short_pages_of_50_and_199_are_complete_candidates() {
        for count in [50, 199] {
            let ids = validate_catalog_list(&catalog_list(count)).expect("short catalog page");
            assert_eq!(ids.len(), count);
        }
    }

    #[test]
    fn catalog_full_page_of_200_fails_closed_as_potentially_truncated() {
        let error = validate_catalog_list(&catalog_list(200))
            .expect_err("a full offset page is not a complete catalog snapshot");
        assert_eq!(error.kind(), WireErrorKind::Catalog);
    }
}
