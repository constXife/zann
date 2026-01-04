use zann_core::EncryptedPayload;

pub(crate) fn flatten_payload(
    payload: &EncryptedPayload,
) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for (key, value) in &payload.fields {
        map.insert(key.clone(), value.value.clone());
    }
    map
}

pub(crate) fn format_kv_flat(payload: &EncryptedPayload) -> String {
    let mut out = String::new();
    for (key, value) in flatten_payload(payload) {
        out.push_str(&format!("{key}={value}\n"));
    }
    out
}

pub(crate) fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn escape_env_value(value: &str) -> String {
    let safe = value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '/' | ':' | '-'));
    if safe && !value.is_empty() {
        return value.to_string();
    }

    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '$' => out.push_str("\\$"),
            '`' => out.push_str("\\`"),
            _ => out.push(ch),
        }
    }
    format!("\"{}\"", out)
}

pub(crate) fn format_env_flat(payload: &EncryptedPayload) -> String {
    let mut out = String::new();
    for (key, value) in flatten_payload(payload) {
        if !is_valid_env_key(&key) {
            eprintln!(
                "Warning: Key \"{}\" is not a valid shell identifier. Skipped.",
                key
            );
            continue;
        }
        let value = escape_env_value(&value);
        out.push_str(&format!("{key}={value}\n"));
    }
    out
}
