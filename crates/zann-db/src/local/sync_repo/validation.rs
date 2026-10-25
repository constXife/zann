use super::*;

pub(super) fn validate_push_outcome(
    scope: LocalSyncScope,
    outcome: &PushOutcome,
) -> Result<(), LocalSyncError> {
    validate_scope(scope)?;
    match &outcome.kind {
        PushOutcomeKind::Applied {
            pending,
            expected_item,
            item,
        } => {
            validate_pending(pending, scope)?;
            validate_expectation(expected_item, scope, pending.item_id)?;
            validate_item(item, scope)?;
            if pending.item_id != item.id {
                return invalid("applied item does not match its pending provenance");
            }
            let LocalItemExpectation::Exact(proof) = expected_item else {
                return invalid("applied push outcome requires an exact existing item");
            };
            validate_applied_server_version(pending, item)?;
            validate_applied_binding(pending, proof, item)?;
            validate_remote_item_status(item)
        }
        PushOutcomeKind::Conflict => invalid("conflicted push batch is fail-closed"),
    }
}

pub(super) fn validate_pull_change(
    scope: LocalSyncScope,
    change: &PullChange,
) -> Result<(), LocalSyncError> {
    validate_scope(scope)?;
    validate_expectation(&change.expected_item, scope, change.item.id)?;
    validate_item(&change.item, scope)?;
    validate_remote_item_status(&change.item)?;
    if let LocalItemExpectation::Exact(proof) = &change.expected_item {
        if proof.sync_status != SyncStatus::Synced {
            return invalid("pull may overwrite only an exact clean synced item");
        }
        if change.item.version <= proof.version {
            return invalid("pulled item version must advance monotonically");
        }
    }
    if change.history.len() > MAX_HISTORY_PER_ITEM {
        return invalid("item history count exceeds the supported range");
    }
    let mut ids = HashSet::with_capacity(change.history.len());
    let mut versions = HashSet::with_capacity(change.history.len());
    for entry in &change.history {
        validate_history(entry, scope, change.item.id)?;
        if !ids.insert(entry.id) {
            return invalid("pull item contains a duplicate history id");
        }
        if !versions.insert(entry.version) {
            return invalid("item history contains a duplicate version");
        }
    }
    Ok(())
}

pub(super) fn validate_push(commit: &PushCommit) -> Result<(), LocalSyncError> {
    validate_scope(commit.scope)?;
    validate_cursors(commit.expected_cursor.as_deref(), &commit.server_head_hint)?;
    validate_last_seq(
        commit.expected_last_seq,
        "expected last sequence is invalid",
    )?;
    if commit.outcomes.is_empty() || commit.outcomes.len() > MAX_PUSH_BATCH_ITEMS {
        return invalid("push outcome count is outside the supported range");
    }

    let mut pending_ids = HashSet::with_capacity(commit.outcomes.len());
    let mut canonical_item_ids = HashSet::with_capacity(commit.outcomes.len());
    let mut projection_bytes = 0usize;
    for outcome in &commit.outcomes {
        validate_push_outcome(commit.scope, outcome)?;
        let pending = match &outcome.kind {
            PushOutcomeKind::Applied { pending, .. } => pending,
            PushOutcomeKind::Conflict => return invalid("conflicted push batch is fail-closed"),
        };
        validate_pending(pending, commit.scope)?;
        if !pending_ids.insert(pending.id) {
            return invalid("push contains a duplicate pending proof");
        }
        if !canonical_item_ids.insert(pending.item_id) {
            return invalid("push contains a duplicate item outcome");
        }
        if let Some(payload) = &pending.payload_enc {
            projection_bytes = add_projection_bytes(projection_bytes, payload.len())?;
        }

        let PushOutcomeKind::Applied { item, .. } = &outcome.kind else {
            return invalid("conflicted push batch is fail-closed");
        };
        projection_bytes = add_projection_bytes(projection_bytes, item.payload_enc.len())?;
    }
    Ok(())
}

pub(super) fn validate_pull(page: &PullPage) -> Result<(), LocalSyncError> {
    validate_scope(page.scope)?;
    validate_cache_key_fingerprint(
        &page.expected_vault_cache_key_fp,
        "pull page cache-key fingerprint is not canonical",
    )?;
    validate_cursors(page.expected_cursor.as_deref(), &page.next_cursor)?;
    validate_last_seq(page.expected_last_seq, "expected last sequence is invalid")?;
    validate_last_seq(page.next_last_seq, "next last sequence is invalid")?;
    if page.expected_last_seq.is_some() && page.next_last_seq.is_none() {
        return invalid("pull page cannot clear the last sequence");
    }
    if let (Some(expected), Some(next)) = (page.expected_last_seq, page.next_last_seq) {
        if next < expected {
            return invalid("pull page last sequence must not move backwards");
        }
    }
    if page.changes.len() > MAX_PULL_PAGE_ITEMS {
        return invalid("pull change count exceeds the supported range");
    }

    let mut item_ids = HashSet::with_capacity(page.changes.len());
    let mut history_ids = HashSet::new();
    let mut history_count = 0usize;
    let mut projection_bytes = 0usize;
    for change in &page.changes {
        validate_pull_change(page.scope, change)?;
        if change.item.cache_key_fp.as_deref() != Some(page.expected_vault_cache_key_fp.as_str()) {
            return invalid("pulled item cache-key fingerprint does not match its vault proof");
        }
        if !item_ids.insert(change.item.id) {
            return invalid("pull page contains a duplicate item");
        }
        if change.history.len() > MAX_HISTORY_PER_ITEM {
            return invalid("item history count exceeds the supported range");
        }
        history_count = history_count
            .checked_add(change.history.len())
            .ok_or_else(|| LocalSyncError::InvalidPlan {
                reason: "pull history count overflowed",
            })?;
        if history_count > MAX_HISTORY_PER_PAGE {
            return invalid("pull history count exceeds the supported range");
        }
        projection_bytes = add_projection_bytes(projection_bytes, change.item.payload_enc.len())?;

        let mut versions = HashSet::with_capacity(change.history.len());
        for entry in &change.history {
            validate_history(entry, page.scope, change.item.id)?;
            if !history_ids.insert(entry.id) {
                return invalid("pull page contains a duplicate history id");
            }
            if !versions.insert(entry.version) {
                return invalid("item history contains a duplicate version");
            }
            projection_bytes = add_projection_bytes(projection_bytes, entry.payload_enc.len())?;
        }
    }
    Ok(())
}

pub(super) fn validate_reset(reset: &ResetProjection) -> Result<(), LocalSyncError> {
    validate_storage_proof(&reset.expected_storage)?;
    if reset.storage_id != reset.expected_storage.id {
        return invalid("storage proof id does not match reset scope");
    }
    if let Some(storage) = &reset.replacement_storage {
        validate_storage(storage)?;
        if storage.id != reset.storage_id {
            return invalid("replacement storage id does not match reset scope");
        }
    }
    Ok(())
}

pub(crate) fn validate_storage_proof(proof: &LocalStorageProof) -> Result<(), LocalSyncError> {
    if proof.id.is_nil() || proof.kind != StorageKind::Remote {
        return invalid("storage proof must identify a non-nil remote storage");
    }
    validate_required_bounded(
        &proof.name,
        MAX_DISPLAY_NAME_BYTES,
        "storage proof name is outside the supported range",
    )?;
    validate_optional_bounded(
        proof.server_url.as_deref(),
        MAX_SERVER_URL_BYTES,
        "storage proof server URL is outside the supported range",
    )?;
    if proof.server_url.is_none() {
        return invalid("remote storage proof requires a server URL");
    }
    validate_optional_bounded(
        proof.server_name.as_deref(),
        MAX_SERVER_METADATA_BYTES,
        "storage proof server name is outside the supported range",
    )?;
    validate_optional_bounded(
        proof.server_fingerprint.as_deref(),
        MAX_SERVER_METADATA_BYTES,
        "storage proof fingerprint is outside the supported range",
    )?;
    validate_optional_bounded(
        proof.account_subject.as_deref(),
        MAX_SERVER_METADATA_BYTES,
        "storage proof account subject is outside the supported range",
    )
}

pub(super) fn validate_scope(scope: LocalSyncScope) -> Result<(), LocalSyncError> {
    if scope.storage_id.is_nil() || scope.vault_id.is_nil() {
        return invalid("sync scope ids must be non-nil");
    }
    Ok(())
}

pub(super) fn validate_cursors(expected: Option<&str>, next: &str) -> Result<(), LocalSyncError> {
    validate_optional_bounded(
        expected,
        MAX_CURSOR_BYTES,
        "expected cursor is outside the supported range",
    )?;
    validate_required_bounded(
        next,
        MAX_CURSOR_BYTES,
        "next cursor is outside the supported range",
    )
}

pub(super) fn validate_last_seq(
    value: Option<i64>,
    reason: &'static str,
) -> Result<(), LocalSyncError> {
    if value.is_some_and(|sequence| sequence < 1) {
        return invalid(reason);
    }
    Ok(())
}

pub(super) fn validate_pending(
    proof: &LocalPendingProof,
    scope: LocalSyncScope,
) -> Result<(), LocalSyncError> {
    if proof.storage_id != scope.storage_id || proof.vault_id != scope.vault_id {
        return invalid("pending proof ids do not match the sync scope");
    }
    validate_pending_fields(
        proof.id,
        proof.storage_id,
        proof.vault_id,
        proof.item_id,
        proof.operation,
        proof.payload_enc.as_deref(),
        proof.checksum.as_deref(),
        proof.path.as_deref(),
        proof.name.as_deref(),
        proof.type_id.as_deref(),
        proof.base_seq,
    )
}

pub(super) fn validate_pending_change(change: &LocalPendingChange) -> Result<(), LocalSyncError> {
    validate_scope(LocalSyncScope {
        storage_id: change.storage_id,
        vault_id: change.vault_id,
    })?;
    validate_pending_fields(
        change.id,
        change.storage_id,
        change.vault_id,
        change.item_id,
        change.operation,
        change.payload_enc.as_deref(),
        change.checksum.as_deref(),
        change.path.as_deref(),
        change.name.as_deref(),
        change.type_id.as_deref(),
        change.base_seq,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_pending_fields(
    id: Uuid,
    storage_id: Uuid,
    vault_id: Uuid,
    item_id: Uuid,
    operation: ChangeType,
    payload_enc: Option<&[u8]>,
    checksum: Option<&str>,
    path: Option<&str>,
    name: Option<&str>,
    type_id: Option<&str>,
    base_seq: Option<i64>,
) -> Result<(), LocalSyncError> {
    if id.is_nil() || storage_id.is_nil() || vault_id.is_nil() || item_id.is_nil() {
        return invalid("pending proof ids must be non-nil");
    }
    if payload_enc.is_some_and(|payload| payload.len() > MAX_ITEM_CIPHERTEXT_BYTES) {
        return invalid("pending payload exceeds the supported size");
    }
    validate_optional_bounded(
        checksum,
        MAX_CHECKSUM_BYTES,
        "pending checksum is outside the supported range",
    )?;
    if let Some(checksum) = checksum {
        validate_checksum(checksum, "pending checksum is not canonical")?;
    }
    if let Some(path) = path {
        validate_path(path)?;
    }
    validate_optional_bounded(
        name,
        MAX_ITEM_NAME_LEN,
        "pending name is outside the supported range",
    )?;
    validate_optional_bounded(
        type_id,
        MAX_TYPE_ID_BYTES,
        "pending item type is outside the supported range",
    )?;
    if let (Some(path), Some(name)) = (path, name) {
        if path.rsplit('/').next() != Some(name) {
            return invalid("pending name must match its path basename");
        }
    }
    if base_seq.is_some_and(|version| version < 1) {
        return invalid("pending base version must be positive");
    }
    match operation {
        ChangeType::Create => {
            if payload_enc.is_none()
                || checksum.is_none()
                || path.is_none()
                || name.is_none()
                || type_id.is_none()
                || base_seq.is_some()
            {
                return invalid("pending create proof has invalid provenance fields");
            }
        }
        ChangeType::Update | ChangeType::Restore => {
            if payload_enc.is_none()
                || checksum.is_none()
                || path.is_none()
                || name.is_none()
                || type_id.is_none()
                || base_seq.is_none()
            {
                return invalid("pending mutation proof has invalid provenance fields");
            }
        }
        ChangeType::Delete => {
            if payload_enc.is_some()
                || checksum.is_some()
                || path.is_none()
                || name.is_none()
                || type_id.is_none()
                || base_seq.is_none()
            {
                return invalid("pending delete proof has invalid provenance fields");
            }
        }
    }
    Ok(())
}

pub(super) fn validate_expectation(
    expectation: &LocalItemExpectation,
    scope: LocalSyncScope,
    item_id: Uuid,
) -> Result<(), LocalSyncError> {
    if let LocalItemExpectation::Exact(proof) = expectation {
        if proof.id != item_id
            || proof.storage_id != scope.storage_id
            || proof.vault_id != scope.vault_id
        {
            return invalid("item proof ids do not match the expected scope");
        }
        validate_path(&proof.path)?;
        validate_required_bounded(
            &proof.name,
            MAX_ITEM_NAME_LEN,
            "item proof name is outside the supported range",
        )?;
        validate_required_bounded(
            &proof.type_id,
            MAX_TYPE_ID_BYTES,
            "item proof type is outside the supported range",
        )?;
        if proof.payload_enc.len() > MAX_ITEM_CIPHERTEXT_BYTES {
            return invalid("item proof payload exceeds the supported size");
        }
        validate_checksum(&proof.checksum, "item proof checksum is not canonical")?;
        if let Some(fingerprint) = proof.cache_key_fp.as_deref() {
            validate_cache_key_fingerprint(
                fingerprint,
                "item proof cache-key fingerprint is not canonical",
            )?;
        }
        if proof.version < 1 {
            return invalid("item proof version must be positive");
        }
    }
    Ok(())
}

pub(super) fn validate_item(item: &LocalItem, scope: LocalSyncScope) -> Result<(), LocalSyncError> {
    if item.id.is_nil() || item.storage_id != scope.storage_id || item.vault_id != scope.vault_id {
        return invalid("item ids do not match the sync scope");
    }
    validate_path(&item.path)?;
    validate_required_bounded(
        &item.name,
        MAX_ITEM_NAME_LEN,
        "item name is outside the supported range",
    )?;
    if item.path.rsplit('/').next() != Some(item.name.as_str()) {
        return invalid("item name must match its path basename");
    }
    validate_required_bounded(
        &item.type_id,
        MAX_TYPE_ID_BYTES,
        "item type is outside the supported range",
    )?;
    if item.payload_enc.len() > MAX_ITEM_CIPHERTEXT_BYTES {
        return invalid("item payload exceeds the supported size");
    }
    validate_checksum(&item.checksum, "item checksum is not canonical")?;
    if let Some(fingerprint) = item.cache_key_fp.as_deref() {
        validate_cache_key_fingerprint(fingerprint, "cache-key fingerprint is not canonical")?;
    }
    if item.version < 1 {
        return invalid("item version must be positive");
    }
    Ok(())
}

pub(super) fn validate_remote_item_status(item: &LocalItem) -> Result<(), LocalSyncError> {
    if item.sync_status == SyncStatus::Synced {
        Ok(())
    } else {
        invalid("remote item projection must use the clean synced status")
    }
}

pub(super) fn validate_applied_binding(
    pending: &LocalPendingProof,
    proof: &LocalItemProof,
    item: &LocalItem,
) -> Result<(), LocalSyncError> {
    if pending.created_at != proof.updated_at {
        return invalid("pending creation time does not match the local item revision");
    }
    match pending.operation {
        ChangeType::Delete => {
            let (Some(path), Some(name), Some(type_id), Some(base_seq)) = (
                pending.path.as_deref(),
                pending.name.as_deref(),
                pending.type_id.as_deref(),
                pending.base_seq,
            ) else {
                return invalid("pending delete proof lacks exact item metadata");
            };
            if path != proof.path
                || name != proof.name
                || type_id != proof.type_id
                || proof.sync_status != SyncStatus::Tombstone
                || proof.deleted_at.is_none()
                || base_seq >= proof.version
            {
                return invalid("pending delete proof does not match the tombstoned item");
            }
            if item.path.as_str() != proof.path.as_str()
                || item.name.as_str() != proof.name.as_str()
                || item.type_id.as_str() != proof.type_id.as_str()
                || item.payload_enc.as_slice() != proof.payload_enc.as_slice()
                || item.checksum.as_str() != proof.checksum.as_str()
                || item.cache_key_fp.as_deref() != proof.cache_key_fp.as_deref()
                || item.sync_status != SyncStatus::Synced
                || item.deleted_at.is_none()
            {
                return invalid("applied delete projection changed canonical item content");
            }
        }
        ChangeType::Create | ChangeType::Update | ChangeType::Restore => {
            let (Some(payload), Some(checksum), Some(path), Some(name), Some(type_id)) = (
                pending.payload_enc.as_ref(),
                pending.checksum.as_ref(),
                pending.path.as_ref(),
                pending.name.as_ref(),
                pending.type_id.as_ref(),
            ) else {
                return invalid("applied pending proof lacks a complete item projection");
            };
            if proof.sync_status != SyncStatus::Modified
                || proof.deleted_at.is_some()
                || proof.path.as_str() != path.as_str()
                || proof.name.as_str() != name.as_str()
                || proof.type_id.as_str() != type_id.as_str()
                || proof.payload_enc.as_slice() != payload.as_slice()
                || proof.checksum.as_str() != checksum.as_str()
            {
                return invalid("pending mutation proof does not match the modified item");
            }
            match pending.operation {
                ChangeType::Create if pending.base_seq.is_none() && proof.version >= 1 => {}
                ChangeType::Update | ChangeType::Restore
                    if pending
                        .base_seq
                        .is_some_and(|base_seq| base_seq < proof.version) => {}
                _ => return invalid("pending base sequence does not match the item revision"),
            }
            if item.path.as_str() != proof.path.as_str()
                || item.name.as_str() != name.as_str()
                || item.type_id.as_str() != type_id.as_str()
                || item.payload_enc.as_slice() != payload.as_slice()
                || item.checksum.as_str() != checksum.as_str()
                || item.cache_key_fp.as_deref() != proof.cache_key_fp.as_deref()
                || item.sync_status != SyncStatus::Synced
                || item.deleted_at.is_some()
            {
                return invalid("applied item projection does not match pending provenance");
            }
        }
    }
    Ok(())
}

pub(super) fn validate_applied_server_version(
    pending: &LocalPendingProof,
    item: &LocalItem,
) -> Result<(), LocalSyncError> {
    match pending.operation {
        ChangeType::Create if item.version >= 1 => Ok(()),
        ChangeType::Create => invalid("applied create version must be positive"),
        ChangeType::Update | ChangeType::Restore | ChangeType::Delete => {
            let Some(base_seq) = pending.base_seq else {
                return invalid("applied mutation lacks a pending base sequence");
            };
            if item.version <= base_seq {
                return invalid("applied version must advance beyond the pending base sequence");
            }
            Ok(())
        }
    }
}

pub(super) fn validate_history(
    entry: &LocalItemHistory,
    scope: LocalSyncScope,
    item_id: Uuid,
) -> Result<(), LocalSyncError> {
    if entry.id.is_nil()
        || entry.storage_id != scope.storage_id
        || entry.vault_id != scope.vault_id
        || entry.item_id != item_id
    {
        return invalid("history ids do not match the pull item scope");
    }
    if entry.payload_enc.len() > MAX_ITEM_CIPHERTEXT_BYTES {
        return invalid("history payload exceeds the supported size");
    }
    validate_checksum(&entry.checksum, "history checksum is not canonical")?;
    if entry.version < 1 {
        return invalid("history version must be positive");
    }
    validate_required_bounded(
        &entry.changed_by_email,
        MAX_EMAIL_BYTES,
        "history actor email is outside the supported range",
    )?;
    validate_optional_bounded(
        entry.changed_by_name.as_deref(),
        MAX_DISPLAY_NAME_BYTES,
        "history actor name is outside the supported range",
    )?;
    validate_optional_bounded(
        entry.changed_by_device_name.as_deref(),
        MAX_DISPLAY_NAME_BYTES,
        "history device name is outside the supported range",
    )?;
    if entry.changed_by_device_id.is_some_and(|id| id.is_nil()) {
        return invalid("history device id must be non-nil when present");
    }
    if entry.source != HistorySource::Server || entry.sync_status != HistorySyncStatus::Confirmed {
        return invalid("pull history must be a confirmed server projection");
    }
    Ok(())
}

pub(super) fn validate_storage(storage: &LocalStorage) -> Result<(), LocalSyncError> {
    if storage.id.is_nil() || storage.kind != StorageKind::Remote {
        return invalid("replacement storage must be a non-nil remote storage");
    }
    validate_required_bounded(
        &storage.name,
        MAX_DISPLAY_NAME_BYTES,
        "storage name is outside the supported range",
    )?;
    validate_optional_bounded(
        storage.server_url.as_deref(),
        MAX_SERVER_URL_BYTES,
        "server URL is outside the supported range",
    )?;
    if storage.server_url.is_none() {
        return invalid("remote replacement storage requires a server URL");
    }
    validate_optional_bounded(
        storage.server_name.as_deref(),
        MAX_SERVER_METADATA_BYTES,
        "server name is outside the supported range",
    )?;
    validate_optional_bounded(
        storage.server_fingerprint.as_deref(),
        MAX_SERVER_METADATA_BYTES,
        "server fingerprint is outside the supported range",
    )?;
    validate_optional_bounded(
        storage.account_subject.as_deref(),
        MAX_SERVER_METADATA_BYTES,
        "account subject is outside the supported range",
    )
}

pub(super) fn validate_path(path: &str) -> Result<(), LocalSyncError> {
    validate_required_bounded(
        path,
        MAX_ITEM_PATH_LEN,
        "item path is outside the supported range",
    )?;
    let mut segments = 0usize;
    for segment in path.split('/') {
        segments += 1;
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.starts_with('.')
            || segment.len() > MAX_ITEM_NAME_LEN
        {
            return invalid("item path contains an invalid segment");
        }
    }
    if segments > MAX_ITEM_PATH_SEGMENTS {
        return invalid("item path has too many segments");
    }
    Ok(())
}

pub(super) fn validate_required_bounded(
    value: &str,
    max: usize,
    reason: &'static str,
) -> Result<(), LocalSyncError> {
    if value.is_empty() || value.len() > max {
        return invalid(reason);
    }
    Ok(())
}

pub(super) fn validate_checksum(
    checksum: &str,
    reason: &'static str,
) -> Result<(), LocalSyncError> {
    if checksum.len() != 64
        || !checksum
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(reason);
    }
    Ok(())
}

pub(super) fn validate_cache_key_fingerprint(
    fingerprint: &str,
    reason: &'static str,
) -> Result<(), LocalSyncError> {
    if fingerprint.len() != CACHE_KEY_FINGERPRINT_BYTES
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(reason);
    }
    Ok(())
}

pub(super) fn validate_optional_bounded(
    value: Option<&str>,
    max: usize,
    reason: &'static str,
) -> Result<(), LocalSyncError> {
    if value.is_some_and(|value| value.is_empty() || value.len() > max) {
        return invalid(reason);
    }
    Ok(())
}

pub(super) fn add_projection_bytes(current: usize, bytes: usize) -> Result<usize, LocalSyncError> {
    let total = current
        .checked_add(bytes)
        .ok_or(LocalSyncError::InvalidPlan {
            reason: "projection byte count overflowed",
        })?;
    if total > MAX_PROJECTION_BYTES {
        return invalid("projection payloads exceed the supported total size");
    }
    Ok(total)
}

pub(super) fn invalid<T>(reason: &'static str) -> Result<T, LocalSyncError> {
    Err(LocalSyncError::InvalidPlan { reason })
}
