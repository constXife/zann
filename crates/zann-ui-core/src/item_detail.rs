//! Toolkit-neutral projection of decrypted item fields. Translation and
//! temporary reveal/copy state belong to the consuming shell.

use std::fmt;

use zann_core::secrets::{EncryptedPayload, FieldKind, PayloadError};

use crate::TotpParams;

const FIELD_ORDER: &[&str] = &[
    "username", "email", "password", "otp", "totp", "url", "key", "value", "notes",
];

/// What every client shows in place of a masked value. A fixed width gives
/// away nothing about the secret's length and fits the narrowest column.
pub const MASKED_VALUE: &str = "••••••••";

/// A field ready for display, before translation or temporary reveal state.
/// Values and TOTP secrets remain local to the client.
#[derive(Clone)]
pub struct ItemDetailField {
    pub key: String,
    /// The key the row is labelled by (`Catalogue::field_label`): the field's
    /// own key, or `otp` for a field shown as its one-time code, since the
    /// row shows the code and never the secret its key names.
    pub label_key: String,
    pub value: String,
    pub masked: bool,
    pub multiline: bool,
    pub totp: Option<TotpParams>,
    /// An explicitly typed, unmasked HTTP(S) website without embedded credentials.
    /// Opening it is a separate, user-invoked platform action.
    pub website_url: Option<String>,
}

impl fmt::Debug for ItemDetailField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ItemDetailField(<redacted>)")
    }
}

/// Parse the canonical payload schema and project fields in reading order.
/// Explicit metadata overrides the field-kind masking and multiline policy.
pub fn project_item_fields(payload_json: &str) -> Result<Vec<ItemDetailField>, PayloadError> {
    Ok(project_payload_fields(EncryptedPayload::from_bytes(
        payload_json.as_bytes(),
    )?))
}

/// Consumes a decrypted payload, transferring field values to presentation.
/// No serialization or duplicate full payload is needed by native clients.
pub fn project_payload_fields(mut payload: EncryptedPayload) -> Vec<ItemDetailField> {
    let mut fields: Vec<_> = std::mem::take(&mut payload.fields)
        .into_iter()
        .map(|(key, mut field)| {
            let meta = field.meta.as_ref();
            let is_otp = matches!(field.kind, FieldKind::Otp);
            let masked = meta
                .and_then(|meta| meta.masked)
                .unwrap_or(matches!(field.kind, FieldKind::Password) || is_otp);
            let totp = is_otp.then(|| totp_params(&field.value, &payload));
            let website_url = if field.kind == FieldKind::Url && !masked {
                website_url(&field.value)
            } else {
                None
            };
            ItemDetailField {
                label_key: if is_otp {
                    "otp".to_string()
                } else {
                    key.clone()
                },
                key,
                value: std::mem::take(&mut field.value),
                masked,
                multiline: meta
                    .and_then(|meta| meta.multiline)
                    .unwrap_or(matches!(field.kind, FieldKind::Note)),
                totp,
                website_url,
            }
        })
        .collect();

    fields.sort_by(|left, right| compare_field_keys(&left.key, &right.key));
    fields
}

fn website_url(value: &str) -> Option<String> {
    let value = value.trim();
    let (scheme, _) = value.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return None;
    }
    let url = url::Url::parse(value).ok()?;
    if !url.has_host() || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    Some(url.into())
}

/// A bare secret takes parameters from payload.extra's canonical otp_* keys;
/// parameters present in an otpauth URI override those payload parameters.
fn totp_params(value: &str, payload: &EncryptedPayload) -> TotpParams {
    let extra = |key: &str| {
        payload
            .extra
            .as_ref()
            .and_then(|extra| extra.get(key))
            .cloned()
    };
    let mut params = TotpParams {
        secret: value.to_string(),
        algorithm: extra("otp_algorithm"),
        digits: extra("otp_digits").and_then(|digits| digits.parse().ok()),
        period: extra("otp_period").and_then(|period| period.parse().ok()),
    };

    if let Some(query) = value
        .strip_prefix("otpauth://")
        .and_then(|rest| rest.split_once('?'))
        .map(|(_, query)| query)
    {
        for (key, raw) in query.split('&').filter_map(|pair| pair.split_once('=')) {
            match key {
                "secret" => params.secret = raw.to_string(),
                "algorithm" => params.algorithm = Some(raw.to_string()),
                "digits" => params.digits = raw.parse().ok().or(params.digits),
                "period" => params.period = raw.parse().ok().or(params.period),
                _ => {}
            }
        }
    }

    params
}

pub(crate) fn compare_field_keys(left: &str, right: &str) -> std::cmp::Ordering {
    let rank = |key: &str| {
        FIELD_ORDER
            .iter()
            .position(|known| *known == key)
            .unwrap_or(FIELD_ORDER.len())
    };
    rank(left).cmp(&rank(right)).then_with(|| left.cmp(right))
}

/// Project the type from the validated payload, including for historical items.
pub fn payload_type_id(payload_json: &str) -> Result<String, PayloadError> {
    Ok(EncryptedPayload::from_bytes(payload_json.as_bytes())?
        .type_id
        .clone())
}
