pub(crate) fn parse_selector(selector: &str) -> anyhow::Result<SecretSelector> {
    let mut parts = selector.splitn(2, ':');
    let vault = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("selector must be vault:path"))?;
    let path = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("selector must be vault:path"))?;
    Ok(SecretSelector {
        vault: vault.to_string(),
        path: path.to_string(),
    })
}

pub(crate) fn parse_selector_if_present(selector: &str) -> anyhow::Result<Option<SecretSelector>> {
    if selector.contains(':') {
        return Ok(Some(parse_selector(selector)?));
    }
    Ok(None)
}

pub(crate) fn parse_template_placeholder(expr: &str) -> anyhow::Result<(String, String)> {
    let mut parts = expr.splitn(2, '#');
    let selector = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("template placeholder missing selector"))?;
    let field = match parts.next() {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                anyhow::bail!("template placeholder missing field: {expr}");
            }
            trimmed
        }
        None => "password",
    };
    Ok((selector.to_string(), field.to_string()))
}

pub(crate) fn parse_template(template: &str) -> anyhow::Result<Vec<TemplateToken>> {
    let mut tokens = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        if start > 0 {
            tokens.push(TemplateToken::Text(rest[..start].to_string()));
        }
        rest = &rest[start + 2..];
        let end = rest
            .find("}}")
            .ok_or_else(|| anyhow::anyhow!("template placeholder missing closing '}}'"))?;
        let expr = rest[..end].trim();
        if expr.is_empty() {
            anyhow::bail!("template placeholder is empty");
        }
        tokens.push(TemplateToken::Placeholder(expr.to_string()));
        rest = &rest[end + 2..];
    }
    if !rest.is_empty() {
        tokens.push(TemplateToken::Text(rest.to_string()));
    }
    Ok(tokens)
}

pub(crate) enum TemplateToken {
    Text(String),
    Placeholder(String),
}

#[derive(Debug)]
pub(crate) struct SecretSelector {
    pub vault: String,
    pub path: String,
}

pub(crate) fn secret_not_found_error(path: &str) -> anyhow::Error {
    anyhow::anyhow!("secret not found: {}", path)
}

pub(crate) fn payload_or_error<'a>(
    item: &'a crate::modules::shared::SharedItemResponse,
) -> anyhow::Result<&'a zann_core::EncryptedPayload> {
    item.payload.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "payload unavailable for {} (encrypted payloads are not supported here)",
            item.path
        )
    })
}

pub(crate) fn normalize_prefix(prefix: Option<&str>) -> Option<String> {
    let trimmed = prefix?.trim().trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

pub(crate) fn prefix_match(prefix: Option<&str>, path: &str) -> bool {
    let Some(prefix) = prefix else {
        return true;
    };
    let path = path.trim().trim_matches('/').to_string();
    path == prefix || path.starts_with(&format!("{}/", prefix))
}

pub(crate) fn parse_cursor(cursor: &str) -> Option<(chrono::DateTime<chrono::Utc>, uuid::Uuid)> {
    let (ts, id) = cursor.split_once('|')?;
    let ts = chrono::DateTime::parse_from_rfc3339(ts)
        .ok()?
        .with_timezone(&chrono::Utc);
    let id = uuid::Uuid::parse_str(id).ok()?;
    Some((ts, id))
}

pub(crate) fn encode_cursor(
    timestamp: &chrono::DateTime<chrono::Utc>,
    item_id: uuid::Uuid,
) -> String {
    format!("{}|{}", timestamp.to_rfc3339(), item_id)
}

pub(crate) fn cursor_allows(
    cursor: Option<&(chrono::DateTime<chrono::Utc>, uuid::Uuid)>,
    updated_at: chrono::DateTime<chrono::Utc>,
    item_id: uuid::Uuid,
) -> bool {
    let Some((cursor_ts, cursor_id)) = cursor else {
        return true;
    };
    updated_at < *cursor_ts || (updated_at == *cursor_ts && item_id < *cursor_id)
}

pub(crate) fn parse_item_timestamp(value: &str) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|ts| ts.with_timezone(&chrono::Utc))
        .map_err(|err| anyhow::anyhow!("invalid timestamp '{value}': {err}"))
}
