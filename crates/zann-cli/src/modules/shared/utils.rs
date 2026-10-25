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

pub(crate) fn payload_or_error(
    item: &crate::modules::shared::SharedItemResponse,
) -> anyhow::Result<EncryptedPayload> {
    let payload = item.payload.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "payload unavailable for {} (encrypted payloads are not supported here)",
            item.path
        )
    })?;

    if let Ok(payload) = serde_json::from_value::<EncryptedPayload>(payload.clone()) {
        return Ok(payload);
    }

    if let Ok(payload) = serde_json::from_value::<LegacySecretPayload>(payload.clone()) {
        let mut normalized = EncryptedPayload::new("secret");
        normalized.fields.insert(
            "password".to_string(),
            FieldValue {
                kind: FieldKind::Password,
                value: payload.value,
                meta: None,
            },
        );
        if let Some(meta) = payload.meta {
            for (key, value) in meta {
                normalized.fields.insert(
                    key,
                    FieldValue {
                        kind: FieldKind::Text,
                        value,
                        meta: None,
                    },
                );
            }
        }
        normalized.extra = Some(HashMap::from([("policy".to_string(), payload.policy)]));
        return Ok(normalized);
    }

    anyhow::bail!(
        "payload unavailable for {} (unsupported payload format)",
        item.path
    )
}

#[derive(serde::Deserialize)]
struct LegacySecretPayload {
    value: String,
    policy: String,
    #[serde(default)]
    meta: Option<HashMap<String, String>>,
}
use std::collections::HashMap;

use zann_core::{EncryptedPayload, FieldKind, FieldValue};
