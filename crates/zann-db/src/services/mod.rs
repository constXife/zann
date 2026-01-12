use chrono::{Duration as ChronoDuration, Utc};
use uuid::Uuid;

use zann_core::crypto::SecretKey;
use zann_core::vault_crypto as core_crypto;
use zann_core::{
    ChangeType, EncryptedPayload, ServiceError, ServiceResult, StorageKind, SyncStatus, VaultKind,
};

use crate::local::{
    KeyWrapType, LocalItemHistory, LocalItemHistoryRepo, LocalItemRepo, LocalPendingChange,
    LocalStorageRepo, LocalVault, LocalVaultRepo, PendingChangeRepo,
};
use crate::SqlitePool;

pub struct LocalServices<'a> {
    pool: &'a SqlitePool,
    master_key: &'a SecretKey,
}

pub const MAX_ITEM_NAME_LEN: usize = 200;
pub const MAX_ITEM_PATH_LEN: usize = 500;
pub const MAX_ITEM_PATH_SEGMENTS: usize = 32;
pub const MAX_ITEM_PAYLOAD_BYTES: usize = 262_144;

const ITEM_HISTORY_LIMIT: i64 = 5;

impl<'a> LocalServices<'a> {
    fn key_fingerprint(key: &SecretKey) -> String {
        let hex = blake3::hash(key.as_bytes()).to_hex().to_string();
        hex.get(0..12).unwrap_or(&hex).to_string()
    }

    fn item_debug(_args: std::fmt::Arguments<'_>) {}

    pub fn new(pool: &'a SqlitePool, master_key: &'a SecretKey) -> Self {
        Self { pool, master_key }
    }

    fn name_from_path(path: &str) -> String {
        path.split('/')
            .rfind(|part| !part.is_empty())
            .unwrap_or(path)
            .to_string()
    }

    fn normalize_path(path: &str) -> ServiceResult<String> {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err(ServiceError::new("path_required", "path is required"));
        }
        let mut segments: Vec<String> = Vec::new();
        for raw in trimmed.split('/') {
            let part = raw.trim();
            if part.is_empty() {
                continue;
            }
            if part == "." {
                continue;
            }
            if part == ".." {
                return Err(ServiceError::new("path_invalid", "path cannot include .."));
            }
            if part.starts_with('.') {
                return Err(ServiceError::new(
                    "path_segment_invalid",
                    "path segment is reserved",
                ));
            }
            if part.len() > MAX_ITEM_NAME_LEN {
                return Err(ServiceError::new("name_too_long", "name is too long"));
            }
            segments.push(part.to_string());
        }
        if segments.is_empty() {
            return Err(ServiceError::new("path_required", "path is required"));
        }
        if segments.len() > MAX_ITEM_PATH_SEGMENTS {
            return Err(ServiceError::new(
                "path_segments_limit",
                "path has too many segments",
            ));
        }
        let normalized = segments.join("/");
        if normalized.len() > MAX_ITEM_PATH_LEN {
            return Err(ServiceError::new("path_too_long", "path is too long"));
        }
        Ok(normalized)
    }

    fn validate_payload_size(payload: &EncryptedPayload) -> ServiceResult<()> {
        let bytes = serde_json::to_vec(payload)
            .map_err(|err| ServiceError::new("payload_encode_failed", err.to_string()))?;
        if bytes.len() > MAX_ITEM_PAYLOAD_BYTES {
            return Err(ServiceError::new(
                "payload_too_large",
                "payload exceeds size limit",
            ));
        }
        Ok(())
    }

    fn split_path(path: &str) -> (String, String) {
        match path.rsplit_once('/') {
            Some((folder, name)) => (folder.to_string(), name.to_string()),
            None => ("".to_string(), path.to_string()),
        }
    }

    fn join_path(folder: &str, name: &str) -> String {
        if folder.is_empty() {
            name.to_string()
        } else {
            format!("{}/{}", folder, name)
        }
    }

    async fn unique_restored_path(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        item_id: Uuid,
        base_path: &str,
    ) -> ServiceResult<String> {
        let repo = LocalItemRepo::new(self.pool);
        let (folder, name) = Self::split_path(base_path);
        for idx in 0..50 {
            let suffix = if idx == 0 {
                " (restored)".to_string()
            } else {
                format!(" (restored {})", idx + 1)
            };
            let max_name_len = MAX_ITEM_NAME_LEN.saturating_sub(suffix.len());
            if max_name_len == 0 {
                return Err(ServiceError::new("name_too_long", "name is too long"));
            }
            let base_name = if name.chars().count() > max_name_len {
                name.chars().take(max_name_len).collect::<String>()
            } else {
                name.clone()
            };
            let candidate_name = format!("{base_name}{suffix}");
            let candidate_path = Self::join_path(&folder, &candidate_name);
            if candidate_path.len() > MAX_ITEM_PATH_LEN {
                continue;
            }
            let existing = repo
                .get_active_by_vault_path(storage_id, vault_id, &candidate_path)
                .await
                .map_err(|err| ServiceError::new("item_lookup_failed", err.to_string()))?;
            if existing.is_none_or(|item| item.id == item_id) {
                return Ok(candidate_path);
            }
        }
        Err(ServiceError::new(
            "item_conflict",
            "could not generate unique restore path",
        ))
    }

    async fn track_pending(
        &self,
        storage_id: Uuid,
        change: LocalPendingChange,
    ) -> ServiceResult<()> {
        // Only sync remote storages; skip local-only (nil UUID)
        if storage_id.is_nil() {
            return Ok(());
        }
        let repo = PendingChangeRepo::new(self.pool);
        let mut merged = change;
        let existing = repo
            .list_by_item(storage_id, merged.item_id)
            .await
            .map_err(|err| ServiceError::new("pending_change_failed", err.to_string()))?;
        if let Some(first) = existing.first() {
            if first.operation == ChangeType::Create {
                merged.operation = ChangeType::Create;
                merged.base_seq = None;
            } else if first.base_seq.is_some() {
                merged.base_seq = first.base_seq;
            }
            let _ = repo.delete_by_item(storage_id, merged.item_id).await;
        }
        repo.create(&merged)
            .await
            .map_err(|err| ServiceError::new("pending_change_failed", err.to_string()))
    }

    fn decrypt_vault_key(&self, vault: &LocalVault) -> ServiceResult<SecretKey> {
        if vault.key_wrap_type == KeyWrapType::RemoteServer {
            return Ok(SecretKey::from_bytes(*self.master_key.as_bytes()));
        }
        match core_crypto::decrypt_vault_key(self.master_key, vault.id, &vault.vault_key_enc) {
            Ok(key) => Ok(key),
            Err(core_crypto::VaultCryptoError::InvalidBlob)
            | Err(core_crypto::VaultCryptoError::InvalidKeyLength) => {
                Err(ServiceError::new("vault_key_invalid", "invalid vault key"))
            }
            Err(err) => Err(ServiceError::new(
                "vault_key_decrypt_failed",
                err.to_string(),
            )),
        }
    }

    async fn encrypt_payload(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        item_id: Uuid,
        payload: &EncryptedPayload,
    ) -> ServiceResult<(Vec<u8>, String)> {
        let bytes = payload
            .to_bytes()
            .map_err(|err| ServiceError::new("payload_encode_failed", err.to_string()))?;
        let key = self.payload_key_for_id(storage_id, vault_id).await?;
        let key_fp = Self::key_fingerprint(&key);
        let payload_enc = core_crypto::encrypt_payload_bytes(&key, vault_id, item_id, &bytes)
            .map_err(|err| ServiceError::new("payload_encrypt_failed", err.to_string()))?;
        Ok((payload_enc, key_fp))
    }

    async fn decrypt_payload(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        item_id: Uuid,
        payload_enc: &[u8],
    ) -> ServiceResult<EncryptedPayload> {
        let repo = LocalVaultRepo::new(self.pool);
        let vault = repo
            .get_by_id(storage_id, vault_id)
            .await
            .map_err(|err| ServiceError::new("vault_lookup_failed", err.to_string()))?
            .ok_or_else(|| ServiceError::new("vault_not_found", "vault not found"))?;
        let checksum = core_crypto::payload_checksum(payload_enc);
        Self::item_debug(format_args!(
            "[item_debug] decrypt_start item_id={} vault_id={} kind={} key_wrap_type={} vault_key_len={} checksum={}",
            item_id,
            vault_id,
            vault.kind.as_i32(),
            vault.key_wrap_type.as_i32(),
            vault.vault_key_enc.len(),
            checksum
        ));
        let (primary_key, primary_source) = if vault.kind == VaultKind::Shared {
            (SecretKey::from_bytes(*self.master_key.as_bytes()), "master")
        } else {
            (self.decrypt_vault_key(&vault)?, "vault")
        };
        let primary_fp = Self::key_fingerprint(&primary_key);
        Self::item_debug(format_args!(
            "[item_debug] decrypt_key item_id={} vault_id={} source={} key_fp={}",
            item_id, vault_id, primary_source, primary_fp
        ));
        let mut used_source = primary_source.to_string();
        let mut used_fp = primary_fp.clone();
        let bytes = match core_crypto::decrypt_payload_bytes(
            &primary_key,
            vault_id,
            item_id,
            payload_enc,
        ) {
            Ok(value) => value,
            Err(err) => {
                if vault.kind == VaultKind::Shared && !vault.vault_key_enc.is_empty() {
                    Self::item_debug(format_args!(
                        "[item_debug] shared_decrypt_fallback item_id={} vault_id={} checksum={}",
                        item_id, vault_id, checksum
                    ));
                    let fallback_key = self.decrypt_vault_key(&vault)?;
                    let fallback_fp = Self::key_fingerprint(&fallback_key);
                    match core_crypto::decrypt_payload_bytes(
                        &fallback_key,
                        vault_id,
                        item_id,
                        payload_enc,
                    ) {
                        Ok(value) => {
                            used_source = "vault_fallback".to_string();
                            used_fp = fallback_fp.clone();
                            Self::item_debug(format_args!(
                                "[item_debug] shared_decrypt_fallback_ok item_id={} vault_id={} key_fp={}",
                                item_id, vault_id, fallback_fp
                            ));
                            value
                        }
                        Err(err) => {
                            let cache_key_fp = LocalItemRepo::new(self.pool)
                                .get_by_id(storage_id, item_id)
                                .await
                                .ok()
                                .flatten()
                                .and_then(|item| item.cache_key_fp);
                            if let Some(cache_key_fp) = cache_key_fp {
                                Self::item_debug(format_args!(
                                    "[item_debug] cache_key_fp item_id={} vault_id={} cache_key_fp={}",
                                    item_id, vault_id, cache_key_fp
                                ));
                            }
                            Self::item_debug(format_args!(
                                "[item_debug] shared_decrypt_fallback_failed item_id={} vault_id={} key_fp={} error={}",
                                item_id, vault_id, fallback_fp, err
                            ));
                            return Err(ServiceError::new(
                                "payload_decrypt_failed",
                                err.to_string(),
                            ));
                        }
                    }
                } else {
                    let cache_key_fp = LocalItemRepo::new(self.pool)
                        .get_by_id(storage_id, item_id)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|item| item.cache_key_fp);
                    if let Some(cache_key_fp) = cache_key_fp {
                        Self::item_debug(format_args!(
                            "[item_debug] cache_key_fp item_id={} vault_id={} cache_key_fp={}",
                            item_id, vault_id, cache_key_fp
                        ));
                    }
                    Self::item_debug(format_args!(
                        "[item_debug] decrypt_failed item_id={} vault_id={} source={} key_fp={} checksum={} error={}",
                        item_id, vault_id, primary_source, primary_fp, checksum, err
                    ));
                    return Err(ServiceError::new("payload_decrypt_failed", err.to_string()));
                }
            }
        };
        let cache_key_fp = LocalItemRepo::new(self.pool)
            .get_by_id(storage_id, item_id)
            .await
            .ok()
            .flatten()
            .and_then(|item| item.cache_key_fp);
        if let Some(cache_key_fp) = cache_key_fp {
            if cache_key_fp == used_fp {
                Self::item_debug(format_args!(
                    "[item_debug] cache_key_fp_match item_id={} vault_id={} source={} key_fp={}",
                    item_id, vault_id, used_source, cache_key_fp
                ));
            } else {
                Self::item_debug(format_args!(
                    "[item_debug] cache_key_fp_mismatch item_id={} vault_id={} source={} cache_key_fp={} used_key_fp={}",
                    item_id, vault_id, used_source, cache_key_fp, used_fp
                ));
            }
        }
        EncryptedPayload::from_bytes(&bytes)
            .map_err(|err| ServiceError::new("payload_decode_failed", err.to_string()))
    }

    pub async fn decrypt_payload_for_item(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        item_id: Uuid,
        payload_enc: &[u8],
    ) -> ServiceResult<EncryptedPayload> {
        self.decrypt_payload(storage_id, vault_id, item_id, payload_enc)
            .await
    }

    async fn payload_key_for_id(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
    ) -> ServiceResult<SecretKey> {
        let repo = LocalVaultRepo::new(self.pool);
        let vault = repo
            .get_by_id(storage_id, vault_id)
            .await
            .map_err(|err| ServiceError::new("vault_lookup_failed", err.to_string()))?
            .ok_or_else(|| ServiceError::new("vault_not_found", "vault not found"))?;
        let (key, source) = if vault.kind == VaultKind::Shared {
            (SecretKey::from_bytes(*self.master_key.as_bytes()), "master")
        } else {
            (self.decrypt_vault_key(&vault)?, "vault")
        };
        let key_fp = Self::key_fingerprint(&key);
        Self::item_debug(format_args!(
            "[item_debug] payload_key vault_id={} kind={} key_wrap_type={} vault_key_len={} source={} key_fp={}",
            vault.id,
            vault.kind.as_i32(),
            vault.key_wrap_type.as_i32(),
            vault.vault_key_enc.len(),
            source,
            key_fp
        ));
        Ok(key)
    }

    fn payload_checksum(payload_enc: &[u8]) -> String {
        core_crypto::payload_checksum(payload_enc)
    }

    pub(crate) fn payloads_equal(
        prev: &EncryptedPayload,
        next: &EncryptedPayload,
    ) -> Result<bool, ServiceError> {
        let prev_value = serde_json::to_value(prev)
            .map_err(|err| ServiceError::new("payload_encode_failed", err.to_string()))?;
        let next_value = serde_json::to_value(next)
            .map_err(|err| ServiceError::new("payload_encode_failed", err.to_string()))?;
        Ok(prev_value == next_value)
    }

    pub async fn update_item_by_id(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
        path: String,
        type_id: String,
        payload: EncryptedPayload,
    ) -> ServiceResult<Uuid> {
        let normalized_path = Self::normalize_path(&path)?;
        Self::validate_payload_size(&payload)?;
        let repo = LocalItemRepo::new(self.pool);
        let Some(mut item) = repo
            .get_by_id(storage_id, item_id)
            .await
            .map_err(|err| ServiceError::new("item_lookup_failed", err.to_string()))?
        else {
            return Err(ServiceError::new("item_not_found", "item not found"));
        };
        if item.deleted_at.is_some() {
            return Err(ServiceError::new("item_deleted", "item is deleted"));
        }
        if item.path != normalized_path {
            if let Some(existing) = repo
                .get_active_by_vault_path(storage_id, item.vault_id, &normalized_path)
                .await
                .map_err(|err| ServiceError::new("item_lookup_failed", err.to_string()))?
            {
                if existing.id != item_id {
                    return Err(ServiceError::new(
                        "item_conflict",
                        "item with same path exists",
                    ));
                }
            }
        }
        let prev_version = item.version;
        let prev_payload_enc = item.payload_enc.clone();
        let prev_checksum = item.checksum.clone();
        let prev_payload = self
            .decrypt_payload(storage_id, item.vault_id, item.id, &item.payload_enc)
            .await?;
        let now = Utc::now();
        let (payload_enc, key_fp) = self
            .encrypt_payload(storage_id, item.vault_id, item.id, &payload)
            .await?;
        item.payload_enc = payload_enc;
        item.checksum = Self::payload_checksum(&item.payload_enc);
        item.cache_key_fp = Some(key_fp);
        item.version = item.version.saturating_add(1);
        item.updated_at = now;
        item.name = Self::name_from_path(&normalized_path);
        item.path = normalized_path.clone();
        item.type_id = type_id;
        item.sync_status = SyncStatus::Modified;
        repo.update(&item)
            .await
            .map_err(|err| ServiceError::new("item_update_failed", err.to_string()))?;
        if !Self::payloads_equal(&prev_payload, &payload)? {
            let storage_repo = LocalStorageRepo::new(self.pool);
            let is_local_only = match storage_repo.get(storage_id).await {
                Ok(Some(storage)) => storage.kind == StorageKind::LocalOnly,
                _ => false,
            };
            if is_local_only {
                let history_repo = LocalItemHistoryRepo::new(self.pool);
                let history = LocalItemHistory {
                    id: Uuid::now_v7(),
                    storage_id,
                    vault_id: item.vault_id,
                    item_id: item.id,
                    payload_enc: prev_payload_enc,
                    checksum: prev_checksum,
                    version: prev_version,
                    change_type: ChangeType::Update,
                    changed_by_email: "local".to_string(),
                    changed_by_name: None,
                    changed_by_device_id: None,
                    changed_by_device_name: None,
                    created_at: now,
                };
                let _ = history_repo.create(&history).await;
                let _ = history_repo
                    .prune_by_item(storage_id, item.id, ITEM_HISTORY_LIMIT)
                    .await;
            }
        }
        self.track_pending(
            storage_id,
            LocalPendingChange {
                id: Uuid::now_v7(),
                storage_id,
                vault_id: item.vault_id,
                item_id: item.id,
                operation: ChangeType::Update,
                payload_enc: Some(item.payload_enc.clone()),
                checksum: Some(item.checksum.clone()),
                path: Some(item.path.clone()),
                name: Some(item.name.clone()),
                type_id: Some(item.type_id.clone()),
                base_seq: Some(prev_version),
                created_at: now,
            },
        )
        .await?;
        Ok(item.id)
    }

    pub async fn restore_item_version(
        &self,
        storage_id: Uuid,
        item_id: Uuid,
        version: i64,
    ) -> ServiceResult<()> {
        let repo = LocalItemRepo::new(self.pool);
        let Some(mut item) = repo
            .get_by_id(storage_id, item_id)
            .await
            .map_err(|err| ServiceError::new("item_lookup_failed", err.to_string()))?
        else {
            return Err(ServiceError::new("item_not_found", "item not found"));
        };

        let history_repo = LocalItemHistoryRepo::new(self.pool);
        let history = history_repo
            .get_by_item_version(storage_id, item_id, version)
            .await
            .map_err(|err| ServiceError::new("history_get_failed", err.to_string()))?
            .ok_or_else(|| ServiceError::new("history_not_found", "history not found"))?;

        if history.checksum == item.checksum {
            return Err(ServiceError::new("history_no_changes", "no changes"));
        }

        let prev_version = item.version;
        let now = Utc::now();
        let history_snapshot = LocalItemHistory {
            id: Uuid::now_v7(),
            storage_id,
            vault_id: item.vault_id,
            item_id: item.id,
            payload_enc: item.payload_enc.clone(),
            checksum: item.checksum.clone(),
            version: prev_version,
            change_type: ChangeType::Restore,
            changed_by_email: "local".to_string(),
            changed_by_name: None,
            changed_by_device_id: None,
            changed_by_device_name: None,
            created_at: now,
        };
        let _ = history_repo.create(&history_snapshot).await;
        let _ = history_repo
            .prune_by_item(storage_id, item.id, ITEM_HISTORY_LIMIT)
            .await;

        let key = self.payload_key_for_id(storage_id, item.vault_id).await?;
        let key_fp = Self::key_fingerprint(&key);
        item.payload_enc = history.payload_enc;
        item.checksum = history.checksum;
        item.cache_key_fp = Some(key_fp);
        item.version = item.version.saturating_add(1);
        item.updated_at = now;
        item.deleted_at = None;
        item.sync_status = SyncStatus::Modified;
        repo.update(&item)
            .await
            .map_err(|err| ServiceError::new("item_update_failed", err.to_string()))?;

        self.track_pending(
            storage_id,
            LocalPendingChange {
                id: Uuid::now_v7(),
                storage_id,
                vault_id: item.vault_id,
                item_id: item.id,
                operation: ChangeType::Update,
                payload_enc: Some(item.payload_enc.clone()),
                checksum: Some(item.checksum.clone()),
                path: Some(item.path.clone()),
                name: Some(item.name.clone()),
                type_id: Some(item.type_id.clone()),
                base_seq: Some(prev_version),
                created_at: now,
            },
        )
        .await?;

        Ok(())
    }

    pub async fn restore_item(&self, storage_id: Uuid, item_id: Uuid) -> ServiceResult<()> {
        let repo = LocalItemRepo::new(self.pool);
        let Some(mut item) = repo
            .get_by_id(storage_id, item_id)
            .await
            .map_err(|err| ServiceError::new("item_lookup_failed", err.to_string()))?
        else {
            return Err(ServiceError::new("item_not_found", "item not found"));
        };
        if item.deleted_at.is_none() {
            return Err(ServiceError::new("item_not_deleted", "item is not deleted"));
        }
        let pending_repo = PendingChangeRepo::new(self.pool);
        let pending = pending_repo
            .list_by_item(storage_id, item_id)
            .await
            .map_err(|err| ServiceError::new("pending_change_failed", err.to_string()))?;
        let has_pending_create = pending
            .iter()
            .any(|change| change.operation == ChangeType::Create && change.base_seq.is_none());
        let was_local_only_delete = item.sync_status == SyncStatus::LocalDeleted;
        if let Some(existing) = repo
            .get_active_by_vault_path(storage_id, item.vault_id, &item.path)
            .await
            .map_err(|err| ServiceError::new("item_lookup_failed", err.to_string()))?
        {
            if existing.id != item.id {
                let updated_path = self
                    .unique_restored_path(storage_id, item.vault_id, item.id, &item.path)
                    .await?;
                item.path = updated_path;
                item.name = Self::name_from_path(&item.path);
            }
        }
        let _ = pending_repo.delete_by_item(storage_id, item_id).await;
        let prev_version = item.version;
        item.deleted_at = None;
        item.sync_status = SyncStatus::Modified;
        item.updated_at = Utc::now();
        item.version = item.version.saturating_add(1);
        repo.update(&item)
            .await
            .map_err(|err| ServiceError::new("item_update_failed", err.to_string()))?;
        if has_pending_create || was_local_only_delete {
            self.track_pending(
                storage_id,
                LocalPendingChange {
                    id: Uuid::now_v7(),
                    storage_id,
                    vault_id: item.vault_id,
                    item_id: item.id,
                    operation: ChangeType::Create,
                    payload_enc: Some(item.payload_enc.clone()),
                    checksum: Some(item.checksum.clone()),
                    path: Some(item.path.clone()),
                    name: Some(item.name.clone()),
                    type_id: Some(item.type_id.clone()),
                    base_seq: None,
                    created_at: item.updated_at,
                },
            )
            .await?;
        } else {
            self.track_pending(
                storage_id,
                LocalPendingChange {
                    id: Uuid::now_v7(),
                    storage_id,
                    vault_id: item.vault_id,
                    item_id: item.id,
                    operation: ChangeType::Restore,
                    payload_enc: Some(item.payload_enc.clone()),
                    checksum: Some(item.checksum.clone()),
                    path: Some(item.path.clone()),
                    name: Some(item.name.clone()),
                    type_id: Some(item.type_id.clone()),
                    base_seq: Some(prev_version),
                    created_at: item.updated_at,
                },
            )
            .await?;
        }
        Ok(())
    }

    pub async fn purge_item(&self, storage_id: Uuid, item_id: Uuid) -> ServiceResult<()> {
        let repo = LocalItemRepo::new(self.pool);
        let Some(item) = repo
            .get_by_id(storage_id, item_id)
            .await
            .map_err(|err| ServiceError::new("item_lookup_failed", err.to_string()))?
        else {
            return Err(ServiceError::new("item_not_found", "item not found"));
        };
        if item.deleted_at.is_none() {
            return Err(ServiceError::new("item_not_deleted", "item is not deleted"));
        }
        let pending_repo = PendingChangeRepo::new(self.pool);
        let _ = pending_repo.delete_by_item(storage_id, item_id).await;
        repo.delete_by_id(item_id)
            .await
            .map_err(|err| ServiceError::new("item_delete_failed", err.to_string()))?;
        Ok(())
    }

    pub async fn purge_trash(
        &self,
        storage_id: Uuid,
        older_than_days: Option<u32>,
    ) -> ServiceResult<usize> {
        let cutoff = older_than_days.map(|days| Utc::now() - ChronoDuration::days(days as i64));
        let pending_repo = PendingChangeRepo::new(self.pool);
        let pending = pending_repo
            .list_by_storage(storage_id)
            .await
            .map_err(|err| ServiceError::new("pending_change_failed", err.to_string()))?;
        let pending_items: std::collections::HashSet<Uuid> =
            pending.into_iter().map(|p| p.item_id).collect();

        let repo = LocalItemRepo::new(self.pool);
        let items = repo
            .list_deleted_before(storage_id, cutoff)
            .await
            .map_err(|err| ServiceError::new("item_lookup_failed", err.to_string()))?;

        let mut removed = 0usize;
        for item in items {
            if pending_items.contains(&item.id) {
                continue;
            }
            if repo.delete_by_id(item.id).await.is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

mod app;
mod items;
mod storages;
mod vaults;
