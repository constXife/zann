//! CXF 1.0 PS + March 2026 errata. Optional provider metadata never changes key identity.
use super::*;
use json::{array, optional_array, optional_text, text, timestamp};
const METADATA_EXTENSION: &str = "zann.app/PasskeyMetadata";

pub(super) fn read(root: &Value) -> Result<ExchangeDocument, ExchangeError> {
    let version = root
        .get("version")
        .ok_or_else(|| ExchangeError::new("passkey_cxf_version"))?;
    if version.get("major").and_then(Value::as_u64) != Some(1)
        || version.get("minor").and_then(Value::as_u64) != Some(0)
    {
        return Err(ExchangeError::new("passkey_cxf_version"));
    }
    RpId::parse(text(root, "exporterRpId", 253)?).map_err(PasskeyError::Origin)?;
    text(root, "exporterDisplayName", 1024)?;
    timestamp(root, "timestamp")?.ok_or_else(|| ExchangeError::new("passkey_time_invalid"))?;
    let mut document = ExchangeDocument::new();
    let mut account_ids = std::collections::BTreeSet::new();
    for account in array(root, "accounts", 64)? {
        let account_id = bytes(text(account, "id", 88)?, 64)?;
        if !account_ids.insert(account_id.to_vec()) {
            return Err(ExchangeError::new("passkey_duplicate_account"));
        }
        text(account, "username", 1024)?;
        text(account, "email", 1024)?;
        array(account, "collections", MAX_EXCHANGE_ENTRIES)?;
        let mut item_ids = std::collections::BTreeSet::new();
        for item in array(account, "items", MAX_EXCHANGE_ENTRIES)? {
            let item_id = bytes(text(item, "id", 88)?, 64)?;
            if !item_ids.insert(item_id.to_vec()) {
                return Err(ExchangeError::new("passkey_duplicate_item"));
            }
            let title = text(item, "title", 1024)?.to_string();
            let created_at = timestamp(item, "creationAt")?;
            let mut metadata = ExchangeMetadata::empty();
            metadata.title = Some(title.clone());
            if let Some(scope) = item.get("scope") {
                for url in array(scope, "urls", 32)? {
                    let value = url
                        .as_str()
                        .ok_or_else(|| ExchangeError::new("passkey_scope_invalid"))?;
                    json::bounded_text(value, 4096)?;
                    metadata.urls.push(value.into());
                }
                array(scope, "androidApps", 32)?;
            }
            let mut credentials = Vec::new();
            let mut unused = 0;
            for value in array(item, "credentials", 64)? {
                match text(value, "type", 128)? {
                    "passkey" => {
                        if value
                            .get("fido2Extensions")
                            .is_some_and(|ext| ext.as_object().is_none_or(|ext| !ext.is_empty()))
                        {
                            return Err(ExchangeError::new("passkey_extensions_unsupported"));
                        }
                        let id = bytes(
                            text(value, "credentialId", 1364)?,
                            crate::MAX_CREDENTIAL_ID_BYTES,
                        )?;
                        let (rp_name, created) =
                            provider_metadata(item, text(value, "rpId", 253)?, &id, created_at)?;
                        let der = bytes(text(value, "key", 700)?, 512)?;
                        credentials.push(credential(
                            text(value, "rpId", 253)?,
                            rp_name,
                            id.to_vec(),
                            UserEntity {
                                id: bytes(
                                    text(value, "userHandle", 88)?,
                                    crate::MAX_USER_HANDLE_BYTES,
                                )?
                                .to_vec(),
                                name: text(value, "username", 1024)?.into(),
                                display_name: text(value, "userDisplayName", 1024)?.into(),
                            },
                            Es256Key::from_pkcs8_der(&der).map_err(PasskeyError::Crypto)?,
                            created,
                        )?);
                    }
                    "basic-auth" => {
                        if metadata.login.is_some() {
                            return Err(ExchangeError::new("passkey_ambiguous_login"));
                        }
                        metadata.login = Some(LoginMetadata {
                            username: editable(value, "username", "string")?,
                            password: editable(value, "password", "concealed-string")?,
                        });
                    }
                    "note" => {
                        if metadata.note.is_some() {
                            return Err(ExchangeError::new("passkey_ambiguous_note"));
                        }
                        metadata.note = Some(
                            editable(value, "content", "string")?
                                .ok_or_else(|| ExchangeError::new("passkey_required_field"))?,
                        );
                    }
                    _ => unused += 1,
                }
            }
            document.ignored_records += unused;
            if credentials.is_empty() {
                document.ignored_records += 1;
                continue;
            }
            if document.entries.len() >= MAX_EXCHANGE_ENTRIES {
                return Err(ExchangeError::new("passkey_exchange_limit"));
            }
            let mut source_id = b"zann CXF source item v1".to_vec();
            source_id.extend_from_slice(&(account_id.len() as u32).to_le_bytes());
            source_id.extend_from_slice(&account_id);
            source_id.extend_from_slice(&item_id);
            let favorite = match item.get("favorite") {
                None => false,
                Some(value) => value
                    .as_bool()
                    .ok_or_else(|| ExchangeError::new("passkey_metadata_invalid"))?,
            };
            let mut tags = Vec::new();
            if let Some(values) = optional_array(item, "tags", 32)? {
                for tag in values {
                    let tag = tag
                        .as_str()
                        .ok_or_else(|| ExchangeError::new("passkey_metadata_invalid"))?;
                    json::bounded_text(tag, 128)?;
                    tags.push(tag.into());
                }
            }
            document.entries.push(ExchangeEntry {
                id: zann_crypto::es256::sha256(&source_id).to_vec(),
                title,
                credentials,
                metadata,
                favorite,
                tags,
            });
        }
    }
    Ok(document)
}
fn editable(value: &Value, key: &str, kind: &str) -> Result<Option<String>, ExchangeError> {
    match value.get(key) {
        None => Ok(None),
        Some(field) => {
            if text(field, "fieldType", 64)? != kind {
                return Err(ExchangeError::new("passkey_field_type_unsupported"));
            }
            Ok(Some(text(field, "value", MAX_SECRET_BYTES)?.into()))
        }
    }
}
fn provider_metadata<'a>(
    item: &'a Value,
    rp_id: &str,
    id: &[u8],
    created_at: Option<DateTime<Utc>>,
) -> Result<(&'a str, Option<DateTime<Utc>>), ExchangeError> {
    let mut found = None;
    let mut extension_seen = false;
    if let Some(extensions) = optional_array(item, "extensions", 32)? {
        for extension in extensions {
            if text(extension, "name", 256)? != METADATA_EXTENSION {
                continue;
            }
            if std::mem::replace(&mut extension_seen, true) {
                return Err(ExchangeError::new("passkey_ambiguous_metadata"));
            }
            let mut ids = std::collections::BTreeSet::new();
            for entry in array(extension, "credentials", 64)? {
                let entry_id = bytes(
                    text(entry, "credentialId", 1364)?,
                    crate::MAX_CREDENTIAL_ID_BYTES,
                )?;
                let entry_rp = text(entry, "rpId", 253)?;
                RpId::parse(entry_rp).map_err(PasskeyError::Origin)?;
                if !ids.insert((entry_rp, entry_id.to_vec())) {
                    return Err(ExchangeError::new("passkey_ambiguous_metadata"));
                }
                if entry_rp != rp_id || entry_id.as_slice() != id {
                    continue;
                }
                let rp_name = text(entry, "rpName", 1024)?;
                let exact = optional_text(entry, "createdAt", 64)?
                    .map(json::time)
                    .transpose()?;
                if created_at.is_some()
                    && exact.map(|d| d.timestamp()) != created_at.map(|d| d.timestamp())
                {
                    return Err(ExchangeError::new("passkey_metadata_conflict"));
                }
                if found.replace((rp_name, exact)).is_some() {
                    return Err(ExchangeError::new("passkey_ambiguous_metadata"));
                }
            }
        }
    }
    Ok(match found {
        Some(metadata) => metadata,
        None => ("", created_at),
    })
}

/// Export event metadata is supplied explicitly by the application/converter.
pub struct CxfExportContext<'a> {
    pub timestamp: DateTime<Utc>,
    pub account_id: &'a [u8],
    pub username: &'a str,
    pub email: &'a str,
}

pub fn write_cxf(
    mut writer: impl Write,
    document: &ExchangeDocument,
    context: CxfExportContext<'_>,
) -> Result<(), ExchangeError> {
    document.validate()?;
    if context.account_id.is_empty()
        || context.account_id.len() > 64
        || context.timestamp.timestamp() < 0
    {
        return Err(ExchangeError::new("passkey_export_context_invalid"));
    }
    json::bounded_text(context.username, 1024)?;
    json::bounded_text(context.email, 1024)?;
    let mut wire = json::SensitiveJson(
        serde_json::json!({"version":{"major":1,"minor":0},"exporterRpId":"zann.app","exporterDisplayName":"Zann","timestamp":context.timestamp.timestamp(),"accounts":[{"id":URL_SAFE_NO_PAD.encode(context.account_id),"username":context.username,"email":context.email,"collections":[],"items":[]}]}),
    );
    for entry in &document.entries {
        let mut item = wire_item(entry)?;
        wire.0["accounts"][0]["items"]
            .as_array_mut()
            .expect("items array")
            .push(std::mem::take(&mut item.0));
    }
    let mut writer = BudgetWriter {
        inner: &mut writer,
        remaining: MAX_EXCHANGE_BYTES,
    };
    serde_json::to_writer_pretty(&mut writer, &wire.0)?;
    writer.write_all(b"\n")?;
    Ok(())
}
fn wire_item(entry: &ExchangeEntry) -> Result<json::SensitiveJson, ExchangeError> {
    let mut item = json::SensitiveJson(
        serde_json::json!({"id":URL_SAFE_NO_PAD.encode(&entry.id),"title":entry.title,"credentials":[],"extensions":[{"name":METADATA_EXTENSION,"credentials":[]}]}),
    );
    for credential in &entry.credentials {
        let der = credential
            .key
            .to_pkcs8_der()
            .map_err(PasskeyError::Crypto)?;
        item.0["credentials"].as_array_mut().expect("credentials array").push(serde_json::json!({"type":"passkey","credentialId":URL_SAFE_NO_PAD.encode(&credential.id),"rpId":credential.rp_id.as_str(),"username":credential.user.name,"userDisplayName":credential.user.display_name,"userHandle":URL_SAFE_NO_PAD.encode(&credential.user.id),"key":URL_SAFE_NO_PAD.encode(&der)}));
        item.0["extensions"][0]["credentials"].as_array_mut().expect("metadata array").push(serde_json::json!({"credentialId":URL_SAFE_NO_PAD.encode(&credential.id),"rpId":credential.rp_id.as_str(),"rpName":credential.rp_name,"createdAt":credential.created_at.map(|t|t.to_rfc3339())}));
    }
    if let Some(login) = &entry.metadata.login {
        let mut value = serde_json::json!({"type":"basic-auth"});
        if let Some(username) = &login.username {
            value["username"] = serde_json::json!({"fieldType":"string","value":username});
        }
        if let Some(password) = &login.password {
            value["password"] =
                serde_json::json!({"fieldType":"concealed-string","value":password});
        }
        item.0["credentials"]
            .as_array_mut()
            .expect("credentials array")
            .push(value);
    }
    if let Some(note) = &entry.metadata.note {
        item.0["credentials"]
            .as_array_mut()
            .expect("credentials array")
            .push(serde_json::json!({"type":"note","content":{"fieldType":"string","value":note}}));
    }
    // CXF arrays with a defined empty default must be omitted when empty.
    if !entry.tags.is_empty() {
        item.0["tags"] = serde_json::json!(entry.tags);
    }
    if entry.favorite {
        item.0["favorite"] = Value::Bool(true);
    }
    if !entry.metadata.urls.is_empty() {
        item.0["scope"] = serde_json::json!({"urls":entry.metadata.urls,"androidApps":[]});
    }
    // A single Item timestamp cannot represent distinct passkey creation times;
    // exact per-credential metadata remains in the standard provider extension.
    if let Some(created) = entry.credentials.first().and_then(|c| c.created_at) {
        if entry
            .credentials
            .iter()
            .all(|c| c.created_at == Some(created))
            && created.timestamp() >= 0
        {
            item.0["creationAt"] = serde_json::json!(created.timestamp());
        }
    }
    Ok(item)
}

struct BudgetWriter<W> {
    inner: W,
    remaining: usize,
}
impl<W: Write> Write for BudgetWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(std::io::Error::other("passkey exchange limit"));
        }
        let written = self.inner.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
