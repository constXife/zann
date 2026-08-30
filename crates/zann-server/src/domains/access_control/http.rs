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

#[derive(Clone, Debug, PartialEq, Eq)]
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
    // Older token issuers encoded path separators as `::`. Accept those
    // persisted scopes while emitting the documented slash form for new ones.
    Some(trimmed.replace("::", "/"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

pub fn scope_allows_action(permission: &str, action: &str) -> bool {
    match action {
        "read" | "list" => permission == "read",
        "read_history" => matches!(
            permission,
            "history_read" | "read_history" | "read_previous"
        ),
        "read_previous" => permission == "read_previous",
        "rotate_start" | "rotate_status" | "rotate_commit" | "rotate_abort" | "read_candidate"
        | "recover" => permission == "rotate",
        "rotate_abort_force" => false,
        _ => permission == action,
    }
}

pub fn scopes_allow_path(scopes: &[String], vault: &Vault, action: &str, path: &str) -> bool {
    scopes.iter().any(|scope| {
        let Some(rule) = parse_scope(scope) else {
            return false;
        };
        scope_allows_action(&rule.permission, action) && scope_matches_path(&rule, vault, path)
    })
}

pub fn scopes_allow_prefix(
    scopes: &[String],
    vault: &Vault,
    action: &str,
    prefix: Option<&str>,
) -> bool {
    let matched_rules = scopes
        .iter()
        .filter_map(|scope| parse_scope(scope))
        .filter(|rule| scope_allows_action(&rule.permission, action))
        .filter(|rule| vault_matches_scope(vault, &rule.target))
        .collect::<Vec<_>>();

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

pub fn scope_matches_path(rule: &ScopeRule, vault: &Vault, path: &str) -> bool {
    if !vault_matches_scope(vault, &rule.target) {
        return false;
    }
    rule.prefix
        .as_deref()
        .is_none_or(|prefix| prefix_matches_path(prefix, path))
}

pub fn scope_matches_prefix(rule: &ScopeRule, vault: &Vault, prefix: Option<&str>) -> bool {
    if !vault_matches_scope(vault, &rule.target) {
        return false;
    }
    rule.prefix.as_deref().is_none_or(|scope_prefix| {
        prefix.is_some_and(|value| prefix_matches_path(scope_prefix, value))
    })
}

pub fn prefix_matches_path(prefix: &str, path: &str) -> bool {
    let prefix = prefix.trim().trim_matches('/');
    let path = path.trim().trim_matches('/');
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

pub fn vault_matches_scope(vault: &Vault, target: &ScopeTarget) -> bool {
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
                    | "rotate_status"
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

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use sqlx_core::types::Json;
    use uuid::Uuid;
    use zann_core::{CachePolicy, Vault, VaultEncryptionType, VaultKind, VaultMemberRole};

    use super::{
        parse_scope, prefix_matches_path, role_permits, scope_allows_action, scopes_allow_path,
        scopes_allow_prefix, ScopeTarget, VaultScope,
    };

    fn shared_vault() -> Vault {
        Vault {
            id: Uuid::nil(),
            slug: "infra".to_string(),
            name: "Infrastructure".to_string(),
            kind: VaultKind::Shared,
            encryption_type: VaultEncryptionType::Server,
            vault_key_enc: Vec::new(),
            cache_policy: CachePolicy::Full,
            tags: Some(Json(vec!["production".to_string()])),
            deleted_at: None,
            deleted_by_user_id: None,
            deleted_by_device_id: None,
            row_version: 1,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn parse_scope_accepts_documented_nested_prefix() {
        let rule = parse_scope("infra/prefix:services/web:read").expect("scope");
        assert_eq!(rule.target, ScopeTarget::Vault("infra".to_string()));
        assert_eq!(rule.prefix.as_deref(), Some("services/web"));
        assert_eq!(rule.permission, "read");
    }

    #[test]
    fn parse_scope_decodes_legacy_nested_prefix() {
        let rule = parse_scope("infra/prefix:services::web:read").expect("scope");
        assert_eq!(rule.prefix.as_deref(), Some("services/web"));
    }

    #[test]
    fn nested_prefix_matches_only_its_path_segment_subtree() {
        assert!(prefix_matches_path("services/web", "services/web"));
        assert!(prefix_matches_path(
            "services/web",
            "/services/web/database"
        ));
        assert!(!prefix_matches_path("services/web", "services/web-old"));
        assert!(!prefix_matches_path("services/web", "services/api"));
    }

    #[test]
    fn prefixed_scopes_cannot_list_the_unprefixed_vault() {
        let vault = shared_vault();
        let scopes = vec!["infra/prefix:services/web:read".to_string()];
        assert!(!scopes_allow_prefix(&scopes, &vault, "list", None));
        assert!(scopes_allow_prefix(
            &scopes,
            &vault,
            "list",
            Some("services/web")
        ));
        assert!(!scopes_allow_prefix(
            &scopes,
            &vault,
            "list",
            Some("services")
        ));
    }

    #[test]
    fn scope_selectors_and_permissions_share_one_evaluator() {
        let vault = shared_vault();
        assert!(scopes_allow_path(
            &["tag:production/prefix:services:write".to_string()],
            &vault,
            "write",
            "services/api"
        ));
        assert!(scopes_allow_path(
            &["pattern:inf*:read_previous".to_string()],
            &vault,
            "read_previous",
            "services/api"
        ));
        assert!(!scopes_allow_path(
            &["infra:read".to_string()],
            &vault,
            "write",
            "services/api"
        ));
        assert!(scope_allows_action("read_previous", "read_history"));
    }

    #[test]
    fn rotation_status_requires_operator_or_admin_role() {
        assert!(role_permits(
            VaultMemberRole::Operator,
            "rotate_status",
            VaultScope::Items
        ));
        assert!(!role_permits(
            VaultMemberRole::Member,
            "rotate_status",
            VaultScope::Items
        ));
        assert!(!role_permits(
            VaultMemberRole::Readonly,
            "rotate_status",
            VaultScope::Items
        ));
        assert!(!role_permits(
            VaultMemberRole::Operator,
            "rotate_abort_force",
            VaultScope::Items
        ));
        assert!(role_permits(
            VaultMemberRole::Admin,
            "rotate_abort_force",
            VaultScope::Items
        ));
    }

    #[test]
    fn service_account_rotation_scope_is_explicit_and_never_grants_force_abort() {
        let vault = shared_vault();
        let rotate = vec!["infra/prefix:services/web:rotate".to_string()];
        for action in [
            "rotate_start",
            "rotate_status",
            "rotate_commit",
            "rotate_abort",
            "read_candidate",
            "recover",
        ] {
            assert!(scopes_allow_path(
                &rotate,
                &vault,
                action,
                "services/web/database"
            ));
        }
        assert!(!scopes_allow_path(
            &rotate,
            &vault,
            "rotate_abort_force",
            "services/web/database"
        ));
        assert!(!scopes_allow_path(
            &["infra/prefix:services/web:write".to_string()],
            &vault,
            "rotate_start",
            "services/web/database"
        ));
        assert!(!scopes_allow_path(
            &rotate,
            &vault,
            "rotate_start",
            "services/api/database"
        ));
    }
}
