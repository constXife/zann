use super::*;
use json::{array, optional_array, optional_text, text};
pub(super) fn read(root: &Value) -> Result<ExchangeDocument, ExchangeError> {
    if root.get("encrypted").and_then(Value::as_bool) != Some(false) {
        return Err(ExchangeError::new("passkey_bitwarden_encrypted"));
    }
    let mut document = ExchangeDocument::new();
    for item in array(root, "items", MAX_EXCHANGE_ENTRIES)? {
        let Some(login) = item.get("login").filter(|v| !v.is_null()) else {
            document.ignored_records += 1;
            continue;
        };
        let Some(values) = optional_array(login, "fido2Credentials", 64)? else {
            document.ignored_records += 1;
            continue;
        };
        if values.is_empty() {
            document.ignored_records += 1;
            continue;
        }
        let id = uuid::Uuid::parse_str(text(item, "id", 36)?)
            .map_err(|e| ExchangeError::source("passkey_source_id_invalid", e))?;
        let title = text(item, "name", 1024)?.to_string();
        let mut metadata = ExchangeMetadata::empty();
        metadata.title = Some(title.clone());
        let username = optional_text(login, "username", MAX_SECRET_BYTES)?.map(str::to_string);
        let password = optional_text(login, "password", MAX_SECRET_BYTES)?.map(str::to_string);
        if username.is_some() || password.is_some() {
            metadata.login = Some(LoginMetadata { username, password });
        }
        metadata.note = optional_text(item, "notes", MAX_SECRET_BYTES)?.map(str::to_string);
        if let Some(uris) = optional_array(login, "uris", 32)? {
            for uri in uris {
                if let Some(uri) = optional_text(uri, "uri", 4096)? {
                    metadata.urls.push(uri.into());
                }
            }
        }
        let mut credentials = Vec::new();
        for value in values {
            if text(value, "keyType", 32)? != "public-key"
                || text(value, "keyAlgorithm", 32)? != "ECDSA"
                || text(value, "keyCurve", 32)? != "P-256"
            {
                return Err(PasskeyError::Algorithm.into());
            }
            if text(value, "discoverable", 5)? != "true" || text(value, "counter", 20)? != "0" {
                return Err(ExchangeError::new(
                    "passkey_counter_or_residency_unsupported",
                ));
            }
            let encoded = text(value, "credentialId", 1370)?;
            let id = match encoded.strip_prefix("b64.") {
                Some(encoded) => bytes(encoded, crate::MAX_CREDENTIAL_ID_BYTES)?.to_vec(),
                None => uuid::Uuid::parse_str(encoded)
                    .map_err(|e| ExchangeError::source("passkey_credential_id_invalid", e))?
                    .as_bytes()
                    .to_vec(),
            };
            let key = bytes(text(value, "keyValue", 700)?, 512)?;
            let user = UserEntity {
                id: bytes(text(value, "userHandle", 88)?, crate::MAX_USER_HANDLE_BYTES)?.to_vec(),
                name: optional_text(value, "userName", 1024)?.unwrap_or("").into(),
                display_name: optional_text(value, "userDisplayName", 1024)?
                    .unwrap_or("")
                    .into(),
            };
            credentials.push(credential(
                text(value, "rpId", 253)?,
                optional_text(value, "rpName", 1024)?.unwrap_or(""),
                id,
                user,
                Es256Key::from_pkcs8_der(&key).map_err(PasskeyError::Crypto)?,
                Some(json::time(text(value, "creationDate", 64)?)?),
            )?);
        }
        let favorite = match item.get("favorite") {
            Some(Value::Bool(value)) => *value,
            Some(_) => return Err(ExchangeError::new("passkey_metadata_invalid")),
            None => false,
        };
        document.entries.push(ExchangeEntry {
            id: id.as_bytes().to_vec(),
            title,
            credentials,
            metadata,
            favorite,
            tags: Vec::new(),
        });
    }
    Ok(document)
}
