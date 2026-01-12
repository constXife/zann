use chrono::Duration as ChronoDuration;
use serde::{Deserialize, Serialize};
use zann_db::repo::{UserRepo, VaultRepo};
use zann_db::PgPool;

pub(super) async fn resolve_owner(
    db: &PgPool,
    owner_email: Option<&str>,
    owner_id: Option<&str>,
) -> Result<uuid::Uuid, String> {
    let repo = UserRepo::new(db);
    if let Some(owner_id) = owner_id {
        return owner_id
            .parse::<uuid::Uuid>()
            .map_err(|_| "invalid owner id".to_string());
    }
    let owner_email = owner_email.ok_or_else(|| "owner email missing".to_string())?;
    let owner = repo
        .get_by_email(owner_email)
        .await
        .map_err(|err| {
            tracing::error!(event = "owner_lookup_failed", error = %err);
            "owner lookup failed".to_string()
        })?
        .ok_or_else(|| "owner not found".to_string())?;
    Ok(owner.id)
}

pub(super) async fn resolve_shared_vault(
    db: &PgPool,
    selector: &str,
) -> Result<zann_core::Vault, String> {
    let repo = VaultRepo::new(db);
    if let Ok(id) = selector.parse::<uuid::Uuid>() {
        return repo
            .get_by_id(id)
            .await
            .map_err(|err| {
                tracing::error!(event = "vault_lookup_failed", error = %err);
                "vault lookup failed".to_string()
            })?
            .ok_or_else(|| "vault not found".to_string());
    }
    repo.get_by_slug(selector)
        .await
        .map_err(|err| {
            tracing::error!(event = "vault_lookup_failed", error = %err);
            "vault lookup failed".to_string()
        })?
        .ok_or_else(|| "vault not found".to_string())
}

pub(super) fn normalize_prefix(prefix: &str) -> Result<NormalizedPrefix, String> {
    let trimmed = prefix.trim();
    if trimmed.is_empty() {
        return Err("prefix cannot be empty".to_string());
    }
    let canonical = trimmed.trim_matches('/').to_string();
    if canonical.is_empty() {
        return Err("prefix cannot be root".to_string());
    }
    Ok(NormalizedPrefix {
        canonical: format!("/{canonical}"),
        scope: canonical.replace('/', "::"),
    })
}

pub(super) fn parse_ops(value: &str) -> Result<Vec<&'static str>, String> {
    let mut ops = Vec::new();
    for token in value.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let normalized = token.to_ascii_lowercase();
        let op = match normalized.as_str() {
            "read" => "read",
            "read_history" => "read_history",
            "read_previous" => "read_previous",
            "history_read" => "read_history",
            _ => return Err(format!("invalid ops: {token}")),
        };
        if !ops.contains(&op) {
            ops.push(op);
        }
    }
    if ops.is_empty() {
        return Err("invalid ops".to_string());
    }
    Ok(ops)
}

pub(super) fn parse_ttl(value: &str) -> Result<ChronoDuration, String> {
    let trimmed = value.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err("invalid ttl".to_string());
    }
    let (amount, unit) = trimmed.split_at(trimmed.len().saturating_sub(1));
    let amount = amount
        .parse::<i64>()
        .map_err(|_| "invalid ttl".to_string())?;
    match unit {
        "s" => Ok(ChronoDuration::seconds(amount)),
        "m" => Ok(ChronoDuration::minutes(amount)),
        "h" => Ok(ChronoDuration::hours(amount)),
        "d" => Ok(ChronoDuration::days(amount)),
        _ => Err("invalid ttl".to_string()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct TokenDescription {
    pub(super) issued_by: String,
    pub(super) vault_id: String,
    pub(super) vault_slug: String,
    pub(super) prefix: Option<String>,
    pub(super) prefixes: Option<Vec<String>>,
    pub(super) ops: Vec<String>,
}

pub(super) fn parse_description(value: &str) -> Result<TokenDescription, String> {
    serde_json::from_str(value).map_err(|_| "invalid description".to_string())
}

#[derive(Debug, Clone)]
pub(super) struct ParsedScope {
    #[allow(dead_code)]
    pub(super) vault_id: String,
    pub(super) prefix: Option<String>,
    pub(super) op: String,
}

pub(super) fn parse_scope_for_list(value: &str) -> Option<ParsedScope> {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() == 2 {
        return Some(ParsedScope {
            vault_id: parts[0].to_string(),
            prefix: None,
            op: parts[1].to_string(),
        });
    }
    if parts.len() == 4 && parts[1] == "prefix" {
        return Some(ParsedScope {
            vault_id: parts[0].to_string(),
            prefix: Some(parts[2].replace("::", "/")),
            op: parts[3].to_string(),
        });
    }
    None
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct TokenListRow {
    pub(super) id: uuid::Uuid,
    pub(super) name: String,
    pub(super) owner_email: Option<String>,
    pub(super) issued_by: Option<String>,
    pub(super) created_at: String,
    pub(super) expires_at: Option<String>,
    pub(super) last_used_at: Option<String>,
    pub(super) revoked_at: Option<String>,
    pub(super) vault_id: Option<String>,
    pub(super) vault_slug: Option<String>,
    pub(super) vault_name: Option<String>,
    pub(super) vault_kind: Option<String>,
    pub(super) scopes: Vec<String>,
    pub(super) scope_summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ScopeSummary {
    pub(super) scopes: Vec<String>,
    pub(super) summary: String,
}

impl ScopeSummary {
    pub(super) fn from_scopes(scopes: &[ParsedScope]) -> Self {
        let mut scopes_display = Vec::new();
        let mut prefixes = std::collections::HashSet::new();
        let mut ops = std::collections::HashSet::new();
        for scope in scopes {
            let op = scope.op.replace('_', " ");
            let display = if let Some(prefix) = scope.prefix.as_ref() {
                prefixes.insert(prefix.clone());
                format!("{prefix} ({op})")
            } else {
                format!("/ ({op})")
            };
            ops.insert(op);
            scopes_display.push(display);
        }
        scopes_display.sort();
        let mut ops_list: Vec<_> = ops.into_iter().collect();
        ops_list.sort();
        let summary = if prefixes.is_empty() {
            format!("full vault ({})", ops_list.join(", "))
        } else if prefixes.len() == 1 {
            format!("{} prefix ({})", prefixes.len(), ops_list.join(", "))
        } else {
            format!("{} prefixes ({})", prefixes.len(), ops_list.join(", "))
        };
        Self {
            scopes: scopes_display,
            summary,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct NormalizedPrefix {
    pub(super) canonical: String,
    pub(super) scope: String,
}

pub(super) async fn resolve_vault_for_list(
    db: &PgPool,
    description: &TokenDescription,
) -> Option<zann_core::Vault> {
    let vault_id = description.vault_id.parse::<uuid::Uuid>().ok()?;
    let vault_repo = VaultRepo::new(db);
    vault_repo.get_by_id(vault_id).await.ok().flatten()
}
