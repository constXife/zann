//! Only plaintext KeePass XML; DTDs and protected ciphertext values are refused.
use super::*;
use quick_xml::{events::Event, Reader, XmlVersion};
#[derive(Default)]
struct Entry {
    fields: BTreeMap<String, Zeroizing<String>>,
    id: String,
    created: Option<String>,
}
pub(super) fn read(bytes: &[u8]) -> Result<ExchangeDocument, ExchangeError> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().expand_empty_elements = true;
    reader.config_mut().check_comments = true;
    let mut stack = Vec::<Vec<u8>>::new();
    let mut current = None::<Entry>;
    let mut field = Zeroizing::new(String::new());
    let mut value = Zeroizing::new(String::new());
    let mut buffer = Vec::new();
    let mut nodes = 0usize;
    let mut document = ExchangeDocument::new();
    let mut root_seen = false;
    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| xml_error_at(error, Some(reader.error_position())))?;
        nodes += 1;
        if nodes > MAX_JSON_NODES || event.as_ref().len() > MAX_SECRET_BYTES {
            return Err(ExchangeError::new("passkey_exchange_limit"));
        }
        match event {
            Event::Start(start) => {
                let name = start.name().as_ref().to_vec();
                if stack.is_empty() {
                    if root_seen || name != b"KeePassFile" {
                        return Err(ExchangeError::new("passkey_xml_invalid"));
                    }
                    root_seen = true;
                }
                if stack.len() >= 64 {
                    return Err(ExchangeError::new("passkey_exchange_limit"));
                }
                if name == b"Entry" && !stack.iter().any(|n| n == b"History") {
                    if current.is_some() {
                        return Err(ExchangeError::new("passkey_xml_invalid"));
                    }
                    current = Some(Entry::default());
                }
                if name == b"String" {
                    field.zeroize();
                    value.zeroize();
                }
                if name == b"Value" {
                    for attribute in start.attributes() {
                        let attribute = attribute
                            .map_err(|e| ExchangeError::source("passkey_xml_invalid", e))?;
                        if attribute.key.as_ref() == b"Protected"
                            && attribute.value.as_ref() == b"True"
                        {
                            return Err(ExchangeError::new("passkey_xml_encrypted"));
                        }
                    }
                }
                stack.push(name);
            }
            Event::End(end) => {
                let name = end.name().as_ref().to_vec();
                if stack.last() != Some(&name) {
                    return Err(ExchangeError::new("passkey_xml_invalid"));
                }
                if let Some(entry) = &mut current {
                    if !stack.iter().any(|n| n == b"History") {
                        if name == b"String"
                            && (entry.fields.len() >= 128
                                || entry
                                    .fields
                                    .insert(
                                        std::mem::take(&mut *field),
                                        Zeroizing::new(std::mem::take(&mut *value)),
                                    )
                                    .is_some())
                        {
                            return Err(ExchangeError::new("passkey_xml_duplicate_field"));
                        }
                        if name == b"Entry" {
                            let entry = current.take().expect("active entry");
                            let created = entry.created.as_deref().map(xml_time).transpose()?;
                            match attributes(&entry.fields, &entry.id, created)? {
                                Some(entry) => {
                                    if document.entries.len() >= MAX_EXCHANGE_ENTRIES {
                                        return Err(ExchangeError::new("passkey_exchange_limit"));
                                    }
                                    document.entries.push(entry);
                                }
                                None => document.ignored_records += 1,
                            }
                        }
                    }
                }
                stack.pop();
            }
            Event::Text(text) => {
                let text = text
                    .xml_content(XmlVersion::Explicit1_0)
                    .map_err(|e| ExchangeError::source("passkey_xml_invalid", e))?;
                append(&stack, &mut current, &mut field, &mut value, &text)?;
            }
            Event::CData(text) => {
                let text = text
                    .xml_content(XmlVersion::Explicit1_0)
                    .map_err(|e| ExchangeError::source("passkey_xml_invalid", e))?;
                append(&stack, &mut current, &mut field, &mut value, &text)?;
            }
            Event::GeneralRef(reference) => {
                let text = reference
                    .decode()
                    .map_err(|e| ExchangeError::source("passkey_xml_invalid", e))?;
                let expanded = match reference.resolve_char_ref().map_err(xml_error)? {
                    Some(c) => c.to_string(),
                    None => quick_xml::escape::resolve_xml_entity(&text)
                        .ok_or_else(|| ExchangeError::new("passkey_xml_entity_unsupported"))?
                        .to_string(),
                };
                append(&stack, &mut current, &mut field, &mut value, &expanded)?;
            }
            Event::Decl(declaration) => {
                if declaration.xml_version().map_err(xml_error)? != XmlVersion::Explicit1_0 {
                    return Err(ExchangeError::new("passkey_xml_version"));
                }
                if let Some(encoding) = declaration.encoding() {
                    if !encoding
                        .map_err(|e| ExchangeError::source("passkey_xml_invalid", e))?
                        .eq_ignore_ascii_case(b"UTF-8")
                    {
                        return Err(ExchangeError::new("passkey_xml_encoding"));
                    }
                }
            }
            Event::DocType(_) | Event::PI(_) => {
                return Err(ExchangeError::new("passkey_xml_entity_unsupported"))
            }
            Event::Eof => break,
            Event::Comment(_) => {}
            Event::Empty(_) => unreachable!("expanded by Reader"),
        }
        buffer.zeroize();
        buffer.clear();
    }
    if !root_seen || !stack.is_empty() || current.is_some() {
        return Err(ExchangeError::new("passkey_xml_invalid"));
    }
    Ok(document)
}
fn append(
    stack: &[Vec<u8>],
    current: &mut Option<Entry>,
    key: &mut String,
    value: &mut String,
    text: &str,
) -> Result<(), ExchangeError> {
    if stack.is_empty() && !text.trim().is_empty() {
        return Err(ExchangeError::new("passkey_xml_invalid"));
    }
    if stack.iter().any(|n| n == b"History") {
        return Ok(());
    }
    if let Some(entry) = current {
        if let Some(last) = stack.last() {
            let target = match last.as_slice() {
                b"Key" if stack.len() > 1 && stack[stack.len() - 2] == b"String" => Some(key),
                b"Value" if stack.len() > 1 && stack[stack.len() - 2] == b"String" => Some(value),
                b"UUID" if stack.len() > 1 && stack[stack.len() - 2] == b"Entry" => {
                    Some(&mut entry.id)
                }
                b"CreationTime" if stack.len() > 1 && stack[stack.len() - 2] == b"Times" => {
                    Some(entry.created.get_or_insert_with(String::new))
                }
                _ => None,
            };
            if let Some(target) = target {
                if target.len().saturating_add(text.len()) > MAX_SECRET_BYTES {
                    return Err(ExchangeError::new("passkey_exchange_limit"));
                }
                target.push_str(text);
            }
        }
    }
    Ok(())
}
fn xml_time(value: &str) -> Result<DateTime<Utc>, ExchangeError> {
    // Standalone XML uses ISO dates; KeePass 4 XML also defines an eight-byte
    // little-endian second count since 0001-01-01. These are distinct wire forms.
    if value.as_bytes().get(4) == Some(&b'-') {
        return json::time(value);
    }
    let decoded = STANDARD
        .decode(value)
        .map_err(|e| ExchangeError::source("passkey_time_invalid", e))?;
    let value: [u8; 8] = decoded
        .try_into()
        .map_err(|_| ExchangeError::new("passkey_time_invalid"))?;
    let seconds = i64::try_from(u64::from_le_bytes(value))
        .ok()
        .and_then(|s| s.checked_sub(62_135_596_800))
        .ok_or_else(|| ExchangeError::new("passkey_time_invalid"))?;
    DateTime::from_timestamp(seconds, 0).ok_or_else(|| ExchangeError::new("passkey_time_invalid"))
}
fn xml_error(error: quick_xml::Error) -> ExchangeError {
    xml_error_at(error, None)
}

fn xml_error_at(error: quick_xml::Error, offset: Option<u64>) -> ExchangeError {
    ExchangeError::source(
        "passkey_xml_invalid",
        XmlDiagnostic {
            _original: error,
            offset,
        },
    )
}
struct XmlDiagnostic {
    _original: quick_xml::Error,
    offset: Option<u64>,
}
impl std::fmt::Display for XmlDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(offset) = self.offset {
            write!(f, "XML structure is invalid at byte {offset}")
        } else {
            f.write_str("XML structure is invalid")
        }
    }
}
impl std::fmt::Debug for XmlDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for XmlDiagnostic {}
