use super::*;
use std::collections::BTreeMap;
mod xml;
pub(super) fn xml(bytes: &[u8]) -> Result<ExchangeDocument, ExchangeError> {
    xml::read(bytes)
}

pub(super) fn passkey(value: &Value) -> Result<ExchangeDocument, ExchangeError> {
    for key in [
        "relyingParty",
        "url",
        "username",
        "credentialId",
        "userHandle",
        "privateKey",
    ] {
        json::text(value, key, MAX_SECRET_BYTES)?;
    }
    let credential = from_parts(
        json::text(value, "relyingParty", 253)?,
        json::text(value, "username", 1024)?,
        json::text(value, "credentialId", 1364)?,
        json::text(value, "userHandle", 88)?,
        json::text(value, "privateKey", 2048)?,
        None,
    )?;
    let mut metadata = ExchangeMetadata::empty();
    metadata.title = Some(credential.rp_id.as_str().into());
    let url = json::text(value, "url", 4096)?;
    if !url.is_empty() {
        metadata.urls.push(url.into());
    }
    Ok(ExchangeDocument {
        entries: vec![ExchangeEntry {
            id: credential.identity().to_vec(),
            title: credential.rp_id.as_str().into(),
            credentials: vec![credential],
            metadata,
            favorite: false,
            tags: Vec::new(),
        }],
        ignored_records: 0,
    })
}
fn from_parts(
    rp: &str,
    username: &str,
    id: &str,
    user: &str,
    pem: &str,
    created: Option<DateTime<Utc>>,
) -> Result<Credential, ExchangeError> {
    let key = pem_key(pem)?;
    credential(
        rp,
        "",
        bytes(id, crate::MAX_CREDENTIAL_ID_BYTES)?.to_vec(),
        UserEntity {
            id: bytes(user, crate::MAX_USER_HANDLE_BYTES)?.to_vec(),
            name: username.into(),
            display_name: String::new(),
        },
        key,
        created,
    )
}
fn pem_key(pem: &str) -> Result<Es256Key, ExchangeError> {
    let mut lines = pem.lines();
    if lines.next() != Some("-----BEGIN PRIVATE KEY-----") {
        return Err(ExchangeError::new("passkey_pem_invalid"));
    }
    let mut body = Zeroizing::new(String::new());
    let mut end = false;
    for line in lines {
        if line == "-----END PRIVATE KEY-----" {
            if end {
                return Err(ExchangeError::new("passkey_pem_invalid"));
            }
            end = true;
            continue;
        }
        if end || line.is_empty() || body.len().saturating_add(line.len()) > 700 {
            return Err(ExchangeError::new("passkey_pem_invalid"));
        }
        body.push_str(line);
    }
    if !end {
        return Err(ExchangeError::new("passkey_pem_invalid"));
    }
    let der = Zeroizing::new(
        STANDARD
            .decode(body.as_bytes())
            .map_err(|e| ExchangeError::source("passkey_pem_invalid", e))?,
    );
    if der.len() > 512 {
        return Err(ExchangeError::new("passkey_pem_invalid"));
    }
    Es256Key::from_pkcs8_der(&der)
        .map_err(PasskeyError::Crypto)
        .map_err(Into::into)
}
fn attributes(
    fields: &BTreeMap<String, Zeroizing<String>>,
    id: &str,
    created: Option<DateTime<Utc>>,
) -> Result<Option<ExchangeEntry>, ExchangeError> {
    if !fields.keys().any(|key| key.starts_with("KPEX_PASSKEY_")) {
        return Ok(None);
    }
    let get = |key: &str| {
        fields
            .get(key)
            .map(|s| s.as_str())
            .ok_or_else(|| ExchangeError::new("passkey_required_field"))
    };
    // Import the current KeePassXC attributes, without StrongBox/legacy aliases.
    let key = from_parts(
        get("KPEX_PASSKEY_RELYING_PARTY")?,
        get("KPEX_PASSKEY_USERNAME")?,
        get("KPEX_PASSKEY_CREDENTIAL_ID")?,
        get("KPEX_PASSKEY_USER_HANDLE")?,
        get("KPEX_PASSKEY_PRIVATE_KEY_PEM")?,
        created,
    )?;
    for flag in ["KPEX_PASSKEY_FLAG_BE", "KPEX_PASSKEY_FLAG_BS"] {
        if fields.get(flag).is_some_and(|v| v.as_str() != "1") {
            return Err(ExchangeError::new("passkey_backup_flags_invalid"));
        }
    }
    let source_id = Zeroizing::new(
        STANDARD
            .decode(id)
            .map_err(|e| ExchangeError::source("passkey_source_id_invalid", e))?,
    );
    if source_id.len() != 16 {
        return Err(ExchangeError::new("passkey_source_id_invalid"));
    }
    let title = get("Title")?.to_string();
    let mut metadata = ExchangeMetadata::empty();
    metadata.title = Some(title.clone());
    if let Some(url) = fields.get("URL").filter(|v| !v.is_empty()) {
        metadata.urls.push(url.to_string());
    }
    metadata.note = fields.get("Notes").map(|v| v.to_string());
    let username = fields.get("UserName").map(|v| v.to_string());
    let password = fields.get("Password").map(|v| v.to_string());
    if username.is_some() || password.is_some() {
        metadata.login = Some(LoginMetadata { username, password });
    }
    Ok(Some(ExchangeEntry {
        id: source_id.to_vec(),
        title,
        credentials: vec![key],
        metadata,
        favorite: false,
        tags: Vec::new(),
    }))
}
