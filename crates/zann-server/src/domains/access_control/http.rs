use zann_core::{Identity, Vault, VaultEncryptionType, VaultKind, VaultMemberRole};
use zann_db::repo::{ServiceAccountRepo, VaultMemberRepo, VaultRepo};

use crate::app::AppState;

#[derive(Clone, Copy)]
pub enum VaultScope {
    Vault,
    Items,
    Members,
    Sync,
}

pub async fn vault_role_allows(
    state: &AppState,
    identity: &Identity,
    vault_id: uuid::Uuid,
    action: &str,
    scope: VaultScope,
) -> Result<bool, sqlx_core::Error> {
    if let Some(service_account_id) = identity.service_account_id {
        let vault_repo = VaultRepo::new(&state.db);
        let Some(vault) = vault_repo.get_by_id(vault_id).await? else {
            return Ok(false);
        };
        return service_account_allows(state, service_account_id, &vault, action, scope).await;
    }
    let repo = VaultMemberRepo::new(&state.db);
    let Some(member) = repo.get(vault_id, identity.user_id).await? else {
        return Ok(false);
    };
    Ok(role_permits(member.role, action, scope))
}

async fn service_account_allows(
    state: &AppState,
    service_account_id: uuid::Uuid,
    vault: &Vault,
    action: &str,
    scope: VaultScope,
) -> Result<bool, sqlx_core::Error> {
    if !matches!(action, "read" | "list") {
        return Ok(false);
    }
    if matches!(scope, VaultScope::Members) {
        return Ok(false);
    }
    if vault.kind != VaultKind::Shared || vault.encryption_type != VaultEncryptionType::Server {
        return Ok(false);
    }

    let repo = ServiceAccountRepo::new(&state.db);
    let Some(account) = repo.get_by_id(service_account_id).await? else {
        return Ok(false);
    };
    if scopes_allow_vault(&account.scopes.0, vault) {
        return Ok(true);
    }
    Ok(false)
}

pub struct ScopeRule {
    pub target: ScopeTarget,
    pub permission: String,
    pub prefix: Option<String>,
}

pub fn scopes_allow_vault(scopes: &[String], vault: &Vault) -> bool {
    for scope in scopes {
        let Some(rule) = parse_scope(scope) else {
            continue;
        };
        if rule.permission != "read" {
            continue;
        }
        if vault_matches_scope(vault, &rule.target) {
            return true;
        }
    }
    false
}

pub fn parse_scope(scope: &str) -> Option<ScopeRule> {
    let mut parts = scope.rsplitn(2, ':');
    let permission = parts.next()?.trim();
    let selector = parts.next()?.trim();
    if selector.is_empty() || permission.is_empty() {
        return None;
    }
    let (selector, prefix) = split_prefix(selector)?;
    Some(ScopeRule {
        target: parse_scope_target(selector)?,
        permission: permission.to_string(),
        prefix,
    })
}

fn split_prefix(selector: &str) -> Option<(&str, Option<String>)> {
    if let Some((target, prefix)) = selector.split_once("/prefix:") {
        let prefix = normalize_prefix(prefix)?;
        return Some((target, Some(prefix)));
    }
    Some((selector, None))
}

fn normalize_prefix(prefix: &str) -> Option<String> {
    let trimmed = prefix.trim().trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

pub enum ScopeTarget {
    Vault(String),
    Tag(String),
    Pattern(String),
}

fn parse_scope_target(value: &str) -> Option<ScopeTarget> {
    if let Some(rest) = value.strip_prefix("tag:") {
        let tag = rest.trim();
        if tag.is_empty() {
            return None;
        }
        return Some(ScopeTarget::Tag(tag.to_string()));
    }
    if let Some(rest) = value.strip_prefix("pattern:") {
        let pattern = rest.trim();
        if pattern.is_empty() {
            return None;
        }
        return Some(ScopeTarget::Pattern(pattern.to_string()));
    }
    Some(ScopeTarget::Vault(value.to_string()))
}

fn vault_matches_scope(vault: &Vault, target: &ScopeTarget) -> bool {
    match target {
        ScopeTarget::Vault(scope) => vault.slug == *scope || vault.id.to_string() == *scope,
        ScopeTarget::Tag(tag) => vault
            .tags
            .as_ref()
            .is_some_and(|tags| tags.0.iter().any(|value| value == tag)),
        ScopeTarget::Pattern(pattern) => matches_pattern(pattern, &vault.slug),
    }
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
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

pub async fn find_vault(
    repo: &VaultRepo<'_>,
    vault_id: &str,
) -> Result<Option<Vault>, sqlx_core::Error> {
    if let Ok(uuid) = uuid::Uuid::parse_str(vault_id) {
        repo.get_by_id(uuid).await
    } else {
        repo.get_by_slug(vault_id).await
    }
}

fn role_permits(role: VaultMemberRole, action: &str, scope: VaultScope) -> bool {
    match role {
        VaultMemberRole::Admin => true,
        VaultMemberRole::Operator => match scope {
            VaultScope::Vault => matches!(action, "read" | "list"),
            VaultScope::Items | VaultScope::Sync => matches!(
                action,
                "read"
                    | "list"
                    | "write"
                    | "read_history"
                    | "read_previous"
                    | "rotate_start"
                    | "rotate_commit"
                    | "rotate_abort"
                    | "read_candidate"
                    | "recover"
            ),
            VaultScope::Members => matches!(action, "read" | "list"),
        },
        VaultMemberRole::Member => match scope {
            VaultScope::Vault => matches!(action, "read" | "list"),
            VaultScope::Items | VaultScope::Sync => {
                matches!(action, "read" | "list" | "write" | "read_history")
            }
            VaultScope::Members => matches!(action, "read" | "list"),
        },
        VaultMemberRole::Readonly => matches!(action, "read" | "list" | "read_history"),
    }
}
