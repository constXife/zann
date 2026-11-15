use super::*;
pub(super) struct SensitiveJson(pub Value);
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        wipe(&mut self.0)
    }
}
fn wipe(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe),
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                wipe(&mut value);
            }
        }
        _ => {}
    }
}
pub(super) fn text<'a>(
    value: &'a Value,
    key: &str,
    maximum: usize,
) -> Result<&'a str, ExchangeError> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ExchangeError::new("passkey_required_field"))?;
    bounded_text(text, maximum)?;
    Ok(text)
}
pub(super) fn optional_text<'a>(
    value: &'a Value,
    key: &str,
    maximum: usize,
) -> Result<Option<&'a str>, ExchangeError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => text(value, key, maximum).map(Some),
    }
}
pub(super) fn bounded_text(value: &str, maximum: usize) -> Result<(), ExchangeError> {
    if value.len() > maximum {
        return Err(ExchangeError::new("passkey_exchange_limit"));
    }
    Ok(())
}
pub(super) fn array<'a>(
    value: &'a Value,
    key: &str,
    maximum: usize,
) -> Result<&'a [Value], ExchangeError> {
    let values = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| ExchangeError::new("passkey_required_array"))?;
    if values.len() > maximum {
        return Err(ExchangeError::new("passkey_exchange_limit"));
    }
    Ok(values)
}
pub(super) fn optional_array<'a>(
    value: &'a Value,
    key: &str,
    maximum: usize,
) -> Result<Option<&'a [Value]>, ExchangeError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => array(value, key, maximum).map(Some),
    }
}
pub(super) fn time(value: &str) -> Result<DateTime<Utc>, ExchangeError> {
    DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| ExchangeError::source("passkey_time_invalid", e))
}
pub(super) fn timestamp(value: &Value, key: &str) -> Result<Option<DateTime<Utc>>, ExchangeError> {
    match value.get(key) {
        None => Ok(None),
        Some(value) => {
            let seconds = value
                .as_u64()
                .and_then(|n| i64::try_from(n).ok())
                .ok_or_else(|| ExchangeError::new("passkey_time_invalid"))?;
            DateTime::from_timestamp(seconds, 0)
                .map(Some)
                .ok_or_else(|| ExchangeError::new("passkey_time_invalid"))
        }
    }
}
