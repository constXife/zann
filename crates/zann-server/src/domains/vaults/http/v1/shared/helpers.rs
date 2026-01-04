use chrono::{DateTime, Utc};
use rand::seq::SliceRandom;
use sqlx_core::row::Row;
use uuid::Uuid;
use zann_core::crypto::SecretKey;
use zann_core::vault_crypto as core_crypto;
use zann_core::{Identity, Vault, VaultEncryptionType, VaultKind};
use zann_db::repo::{DeviceRepo, ServiceAccountRepo, UserRepo};

use super::{ROTATION_STATE_ROTATING, ROTATION_STATE_STALE};
use crate::app::AppState;
use crate::domains::access_control::http::{parse_scope, ScopeRule, ScopeTarget};

pub(super) struct RotationRow {
    pub(super) state: Option<String>,
    pub(super) candidate_enc: Option<Vec<u8>>,
    pub(super) started_at: Option<DateTime<Utc>>,
    pub(super) started_by: Option<Uuid>,
    pub(super) expires_at: Option<DateTime<Utc>>,
    pub(super) recover_until: Option<DateTime<Utc>>,
    pub(super) aborted_reason: Option<String>,
}

pub(super) async fn fetch_rotation_row(
    state: &AppState,
    item_id: Uuid,
) -> Result<Option<RotationRow>, sqlx_core::Error> {
    let row = sqlx_core::query::query(
        r#"
        SELECT
            rotation_state,
            rotation_candidate_enc,
            rotation_started_at,
            rotation_started_by,
            rotation_expires_at,
            rotation_recover_until,
            rotation_aborted_reason
        FROM items
        WHERE id = $1
        "#,
    )
    .bind(item_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(RotationRow {
        state: row.try_get("rotation_state").ok(),
        candidate_enc: row.try_get("rotation_candidate_enc").ok(),
        started_at: row.try_get("rotation_started_at").ok(),
        started_by: row.try_get("rotation_started_by").ok(),
        expires_at: row.try_get("rotation_expires_at").ok(),
        recover_until: row.try_get("rotation_recover_until").ok(),
        aborted_reason: row.try_get("rotation_aborted_reason").ok(),
    }))
}

pub(super) async fn normalize_rotation_state(
    state: &AppState,
    item_id: Uuid,
    mut row: RotationRow,
) -> Result<RotationRow, sqlx_core::Error> {
    if row.state.as_deref() == Some(ROTATION_STATE_ROTATING)
        && row.expires_at.is_some_and(|value| Utc::now() > value)
    {
        sqlx_core::query::query(
            r#"
            UPDATE items
            SET rotation_state = $1
            WHERE id = $2 AND rotation_state = $3
            "#,
        )
        .bind(ROTATION_STATE_STALE)
        .bind(item_id)
        .bind(ROTATION_STATE_ROTATING)
        .execute(&state.db)
        .await?;
        row.state = Some(ROTATION_STATE_STALE.to_string());
    }
    Ok(row)
}

pub(super) fn rotation_state_label(state: &Option<String>) -> String {
    state.clone().unwrap_or_else(|| "active".to_string())
}

pub(super) struct ActorSnapshot {
    pub(super) email: String,
    pub(super) name: Option<String>,
    pub(super) device_name: Option<String>,
}

pub(super) async fn actor_snapshot(
    state: &AppState,
    identity: &Identity,
    device_id: Option<Uuid>,
) -> ActorSnapshot {
    let user_repo = UserRepo::new(&state.db);
    let name = match user_repo.get_by_id(identity.user_id).await {
        Ok(Some(user)) => user.full_name,
        _ => None,
    };
    let device_name = match device_id {
        Some(device_id) => {
            let device_repo = DeviceRepo::new(&state.db);
            match device_repo.get_by_id(device_id).await {
                Ok(Some(device)) => Some(device.name),
                _ => None,
            }
        }
        None => None,
    };
    ActorSnapshot {
        email: identity.email.clone(),
        name,
        device_name,
    }
}

pub(super) fn is_shared_server_vault(vault: &Vault) -> bool {
    vault.kind == VaultKind::Shared && vault.encryption_type == VaultEncryptionType::Server
}

pub(super) fn encrypt_rotation_candidate(
    smk: &SecretKey,
    vault: &Vault,
    item_id: Uuid,
    candidate: &str,
) -> Result<Vec<u8>, &'static str> {
    let vault_key = core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc)
        .map_err(|err| err.as_code())?;
    let payload_enc = core_crypto::encrypt_rotation_candidate(
        &vault_key,
        vault.id,
        item_id,
        candidate.as_bytes(),
    )
    .map_err(|err| err.as_code())?;
    Ok(payload_enc)
}

pub(super) fn decrypt_rotation_candidate(
    smk: &SecretKey,
    vault: &Vault,
    item_id: Uuid,
    candidate_enc: &[u8],
) -> Result<String, &'static str> {
    let vault_key = core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc)
        .map_err(|err| err.as_code())?;
    let bytes =
        core_crypto::decrypt_rotation_candidate(&vault_key, vault.id, item_id, candidate_enc)
            .map_err(|err| err.as_code())?;
    String::from_utf8(bytes).map_err(|_| "candidate_invalid")
}

pub(super) fn generate_password(policy: Option<&str>) -> Result<String, &'static str> {
    let policy = policy.unwrap_or("default");
    let mut rng = rand::thread_rng();
    match policy {
        "default" => {
            let length = 24;
            let upper = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
            let lower = b"abcdefghijkmnopqrstuvwxyz";
            let digits = b"23456789";
            let symbols = b"!@#$%^&*_-+=?";
            let mut chars = Vec::with_capacity(length);
            chars.push(*upper.choose(&mut rng).ok_or("invalid_policy")? as char);
            chars.push(*lower.choose(&mut rng).ok_or("invalid_policy")? as char);
            chars.push(*digits.choose(&mut rng).ok_or("invalid_policy")? as char);
            chars.push(*symbols.choose(&mut rng).ok_or("invalid_policy")? as char);
            let mut all =
                Vec::with_capacity(upper.len() + lower.len() + digits.len() + symbols.len());
            all.extend_from_slice(upper);
            all.extend_from_slice(lower);
            all.extend_from_slice(digits);
            all.extend_from_slice(symbols);
            for _ in chars.len()..length {
                chars.push(*all.choose(&mut rng).ok_or("invalid_policy")? as char);
            }
            chars.shuffle(&mut rng);
            Ok(chars.into_iter().collect())
        }
        "alnum" => {
            let length = 24;
            let charset = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
            let mut chars = Vec::with_capacity(length);
            for _ in 0..length {
                let ch = *charset.choose(&mut rng).ok_or("invalid_policy")? as char;
                chars.push(ch);
            }
            Ok(chars.into_iter().collect())
        }
        _ => Err("invalid_policy"),
    }
}

pub(super) fn normalize_path(value: &str) -> String {
    value.trim().trim_matches('/').to_string()
}

pub(super) fn prefix_match(prefix: Option<&str>, path: &str) -> bool {
    let Some(prefix) = prefix else {
        return true;
    };
    let path = normalize_path(path);
    path == prefix || path.starts_with(&format!("{}/", prefix))
}

pub(super) fn parse_cursor(cursor: &str) -> Option<(DateTime<Utc>, Uuid)> {
    let (ts, id) = cursor.split_once('|')?;
    let ts = DateTime::parse_from_rfc3339(ts).ok()?.with_timezone(&Utc);
    let id = Uuid::parse_str(id).ok()?;
    Some((ts, id))
}

pub(super) fn encode_cursor(item: &zann_core::Item) -> String {
    format!("{}|{}", item.updated_at.to_rfc3339(), item.id)
}

pub(super) fn cursor_allows(
    cursor: Option<&(DateTime<Utc>, Uuid)>,
    item: &zann_core::Item,
) -> bool {
    let Some((cursor_ts, cursor_id)) = cursor else {
        return true;
    };
    item.updated_at < *cursor_ts || (item.updated_at == *cursor_ts && item.id < *cursor_id)
}

pub(super) async fn service_account_scopes(
    state: &AppState,
    service_account_id: Uuid,
) -> Option<Vec<String>> {
    let repo = ServiceAccountRepo::new(&state.db);
    repo.get_by_id(service_account_id)
        .await
        .ok()
        .flatten()
        .map(|account| account.scopes.0)
}

pub(super) fn scope_allows_action(permission: &str, action: &str) -> bool {
    match action {
        "read_history" => {
            matches!(
                permission,
                "history_read" | "read_history" | "read_previous"
            )
        }
        "read_previous" => permission == "read_previous",
        _ => permission == "read",
    }
}

pub(super) fn evaluate_history_policy(
    policies: &crate::domains::access_control::policies::PolicySet,
    identity: &Identity,
    action: &str,
    resource: &str,
) -> crate::domains::access_control::policies::PolicyDecision {
    policies.evaluate(identity, action, resource)
}

pub(super) fn scope_matches_path(rule: &ScopeRule, vault: &Vault, path: &str) -> bool {
    if !vault_matches_scope(vault, &rule.target) {
        return false;
    }
    if let Some(prefix) = rule.prefix.as_deref() {
        return prefix_match(Some(prefix), path);
    }
    true
}

pub(super) fn scope_matches_prefix(rule: &ScopeRule, vault: &Vault, prefix: Option<&str>) -> bool {
    if !vault_matches_scope(vault, &rule.target) {
        return false;
    }
    if let Some(scope_prefix) = rule.prefix.as_deref() {
        return prefix.is_some_and(|value| prefix_match(Some(scope_prefix), value));
    }
    true
}

pub(super) fn vault_matches_scope(vault: &Vault, target: &ScopeTarget) -> bool {
    match target {
        ScopeTarget::Vault(scope) => vault.slug == *scope || vault.id.to_string() == *scope,
        ScopeTarget::Tag(tag) => vault
            .tags
            .as_ref()
            .is_some_and(|tags| tags.0.iter().any(|value| value == tag)),
        ScopeTarget::Pattern(pattern) => matches_pattern(pattern, &vault.slug),
    }
}

pub(super) fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == "**" {
        return true;
    }

    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');
    let parts: Vec<&str> = pattern.split('*').filter(|p| !p.is_empty()).collect();

    if parts.is_empty() {
        return true;
    }

    let mut index = 0;
    for (i, part) in parts.iter().enumerate() {
        if let Some(pos) = value[index..].find(part) {
            if i == 0 && !starts_with_wildcard && pos != 0 {
                return false;
            }
            index += pos + part.len();
        } else {
            return false;
        }
    }

    if !ends_with_wildcard {
        if let Some(last) = parts.last() {
            return value.ends_with(last);
        }
    }

    true
}

pub(super) async fn service_account_allows_path(
    state: &AppState,
    service_account_id: Uuid,
    vault: &Vault,
    action: &str,
    path: &str,
) -> bool {
    let Some(scopes) = service_account_scopes(state, service_account_id).await else {
        return false;
    };
    scopes.iter().any(|scope| {
        let Some(rule) = parse_scope(scope) else {
            return false;
        };
        scope_allows_action(&rule.permission, action) && scope_matches_path(&rule, vault, path)
    })
}

pub(super) async fn service_account_allows_prefix(
    state: &AppState,
    service_account_id: Uuid,
    vault: &Vault,
    action: &str,
    prefix: Option<&str>,
) -> bool {
    let Some(scopes) = service_account_scopes(state, service_account_id).await else {
        return false;
    };
    let mut matched_rules = Vec::new();
    for scope in &scopes {
        let Some(rule) = parse_scope(scope) else {
            continue;
        };
        if !scope_allows_action(&rule.permission, action) {
            continue;
        }
        if vault_matches_scope(vault, &rule.target) {
            matched_rules.push(rule);
        }
    }
    if matched_rules.is_empty() {
        return false;
    }
    if prefix.is_none() && matched_rules.iter().all(|rule| rule.prefix.is_some()) {
        return false;
    }
    matched_rules
        .iter()
        .any(|rule| scope_matches_prefix(rule, vault, prefix))
}
