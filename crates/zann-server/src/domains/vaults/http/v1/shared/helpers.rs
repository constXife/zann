use chrono::{DateTime, Utc};
use sqlx_core::row::Row;
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;
use zann_core::{FieldKind, Identity, Vault, VaultEncryptionType, VaultKind};
use zann_crypto::crypto::SecretKey;
use zann_crypto::vault_crypto as core_crypto;
use zann_crypto::EncryptedPayload;
use zann_db::repo::{DeviceRepo, ServiceAccountRepo, UserRepo};
use zeroize::Zeroizing;

use super::types::RotationCandidate;
use super::{ROTATION_STATE_ROTATING, ROTATION_STATE_STALE};
use crate::app::AppState;
use crate::domains::access_control::http::{
    scopes_allow_path, scopes_allow_prefix, vault_role_allows, VaultScope,
};
use crate::domains::access_control::policies::PolicyDecision;
use crate::domains::auth::helpers::build_device;
use crate::domains::secrets::policies::{generate_secret, PasswordPolicy};
use crate::infra::{audit, metrics};

const SERVICE_ACCOUNT_DEVICE_NAME: &str = "Service Account";
const SERVICE_ACCOUNT_DEVICE_FINGERPRINT: &str = "service-account";

pub(super) struct RotationTelemetry<'a> {
    identity: &'a Identity,
    operation: &'static str,
    result: &'static str,
    vault_id: String,
    path: String,
    started_at: Instant,
}

impl<'a> RotationTelemetry<'a> {
    pub(super) fn new(identity: &'a Identity, operation: &'static str, item_id: Uuid) -> Self {
        Self {
            identity,
            operation,
            result: "error",
            vault_id: String::new(),
            path: item_id.to_string(),
            started_at: Instant::now(),
        }
    }

    pub(super) fn set_target(&mut self, vault_id: Uuid, path: &str) {
        self.vault_id = vault_id.to_string();
        self.path = path.to_string();
    }

    pub(super) fn succeed(&mut self) {
        self.result = "ok";
    }
}

impl Drop for RotationTelemetry<'_> {
    fn drop(&mut self) {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        metrics::secrets_operation(self.operation, self.result, elapsed);
        let detail = (self.result != "ok").then_some(self.result);
        audit::secrets_event(
            self.identity,
            self.operation,
            self.result,
            &self.vault_id,
            &self.path,
            detail,
        );
    }
}

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
) -> Result<RotationCandidate, &'static str> {
    let vault_key = core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc)
        .map_err(|err| err.as_code())?;
    let bytes = Zeroizing::new(
        core_crypto::decrypt_rotation_candidate(&vault_key, vault.id, item_id, candidate_enc)
            .map_err(|err| err.as_code())?,
    );
    let candidate = std::str::from_utf8(bytes.as_slice())
        .map_err(|_| "candidate_invalid")?
        .to_owned();
    Ok(RotationCandidate::new(candidate))
}

pub(super) fn generate_rotation_candidate(
    policies: &HashMap<String, PasswordPolicy>,
    default_policy: &str,
    requested_policy: Option<&str>,
) -> Result<RotationCandidate, &'static str> {
    let policy_name = requested_policy.unwrap_or(default_policy);
    let policy = policies.get(policy_name).ok_or("unknown_policy")?;
    let candidate = generate_secret(policy)?;
    Ok(RotationCandidate::new(candidate))
}

pub(super) fn rotation_password_field_name(
    payload: &EncryptedPayload,
) -> Result<String, &'static str> {
    if payload
        .fields
        .get("password")
        .is_some_and(|field| field.kind == FieldKind::Password)
    {
        return Ok("password".to_string());
    }

    let mut password_fields = payload
        .fields
        .iter()
        .filter(|(_, field)| field.kind == FieldKind::Password)
        .map(|(name, _)| name);
    let Some(field_name) = password_fields.next() else {
        return Err("password_field_missing");
    };
    if password_fields.next().is_some() {
        return Err("password_field_ambiguous");
    }
    Ok(field_name.clone())
}

pub(super) fn rotation_abort_state_allowed(state: Option<&str>, force: bool) -> bool {
    match state {
        Some(ROTATION_STATE_ROTATING | ROTATION_STATE_STALE) => true,
        Some(_) => force,
        None => false,
    }
}

pub(super) fn normalize_path(value: &str) -> String {
    value.trim().trim_matches('/').to_string()
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

pub(super) async fn effective_device_id(
    state: &AppState,
    identity: &Identity,
) -> Result<Uuid, &'static str> {
    if let Some(device_id) = identity.device_id {
        return Ok(device_id);
    }

    if identity.service_account_id.is_none() {
        return Err("device_required");
    }

    ensure_service_account_device(state, identity.user_id).await
}

async fn ensure_service_account_device(
    state: &AppState,
    user_id: Uuid,
) -> Result<Uuid, &'static str> {
    let repo = DeviceRepo::new(&state.db);
    let existing = repo
        .list_by_user(user_id, 1024, 0, "desc")
        .await
        .map_err(|_| "db_error")?
        .into_iter()
        .find(|device| {
            device.revoked_at.is_none() && device.fingerprint == SERVICE_ACCOUNT_DEVICE_FINGERPRINT
        });
    if let Some(device) = existing {
        return Ok(device.id);
    }

    let now = Utc::now();
    let device = build_device(
        user_id,
        Some(SERVICE_ACCOUNT_DEVICE_NAME.to_string()),
        Some("server".to_string()),
        Some(SERVICE_ACCOUNT_DEVICE_FINGERPRINT.to_string()),
        Some("server".to_string()),
        None,
        None,
        SERVICE_ACCOUNT_DEVICE_NAME,
        "server",
        now,
    );
    repo.create(&device).await.map_err(|_| "db_error")?;
    Ok(device.id)
}

pub(super) fn evaluate_history_policy(
    policies: &crate::domains::access_control::policies::PolicySet,
    identity: &Identity,
    action: &str,
    resource: &str,
) -> crate::domains::access_control::policies::PolicyDecision {
    policies.evaluate(identity, action, resource)
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
    scopes_allow_path(&scopes, vault, action, path)
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
    scopes_allow_prefix(&scopes, vault, action, prefix)
}

pub(super) async fn rotation_action_allowed(
    state: &AppState,
    identity: &Identity,
    vault: &Vault,
    action: &str,
    resource: &str,
    path: &str,
) -> Result<bool, sqlx_core::Error> {
    let decision = state
        .policy_store
        .get()
        .evaluate(identity, action, resource);
    if let Some(service_account_id) = identity.service_account_id {
        if matches!(decision, PolicyDecision::Deny) {
            return Ok(false);
        }
        return Ok(
            service_account_allows_path(state, service_account_id, vault, action, path).await,
        );
    }
    if action == "rotate_abort_force" {
        if matches!(decision, PolicyDecision::Deny) {
            return Ok(false);
        }
        // A policy may narrow force-abort but cannot broaden it beyond the
        // vault-admin role.
        return vault_role_allows(state, identity, vault.id, action, VaultScope::Items).await;
    }
    match decision {
        PolicyDecision::Allow => Ok(true),
        PolicyDecision::Deny => Ok(false),
        PolicyDecision::NoMatch => {
            vault_role_allows(state, identity, vault.id, action, VaultScope::Items).await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use zann_crypto::{EncryptedPayload, FieldKind, FieldValue};

    use super::{
        generate_rotation_candidate, rotation_abort_state_allowed, rotation_password_field_name,
    };
    use crate::domains::secrets::policies::PasswordPolicy;

    fn password(value: &str) -> FieldValue {
        FieldValue {
            kind: FieldKind::Password,
            value: value.to_string(),
            meta: None,
        }
    }

    #[test]
    fn rotation_uses_configured_secret_policy() {
        let mut policies = HashMap::new();
        policies.insert(
            "database".to_string(),
            PasswordPolicy {
                length: 12,
                min_lowercase: 0,
                min_uppercase: 0,
                min_digits: 12,
                min_symbols: 0,
                symbols: None,
            },
        );

        let candidate =
            generate_rotation_candidate(&policies, "database", None).expect("candidate");
        assert_eq!(candidate.as_str().len(), 12);
        assert!(candidate.as_str().chars().all(|ch| ch.is_ascii_digit()));
        assert_eq!(
            generate_rotation_candidate(&policies, "database", Some("missing"))
                .expect_err("unknown policy"),
            "unknown_policy"
        );
    }

    #[test]
    fn rotation_password_field_selection_is_deterministic() {
        let mut payload = EncryptedPayload::new("login");
        payload
            .fields
            .insert("secondary".to_string(), password("two"));
        payload
            .fields
            .insert("password".to_string(), password("one"));
        assert_eq!(
            rotation_password_field_name(&payload).expect("canonical field"),
            "password"
        );

        payload.fields.remove("password");
        assert_eq!(
            rotation_password_field_name(&payload).expect("single field"),
            "secondary"
        );

        payload
            .fields
            .insert("primary".to_string(), password("three"));
        assert_eq!(
            rotation_password_field_name(&payload).expect_err("ambiguous fields"),
            "password_field_ambiguous"
        );
    }

    #[test]
    fn force_abort_only_expands_invalid_state_recovery() {
        assert!(rotation_abort_state_allowed(Some("rotating"), false));
        assert!(rotation_abort_state_allowed(Some("stale"), false));
        assert!(!rotation_abort_state_allowed(Some("corrupt"), false));
        assert!(rotation_abort_state_allowed(Some("corrupt"), true));
        assert!(!rotation_abort_state_allowed(None, true));
    }
}
