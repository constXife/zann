//! Toolkit-neutral projection of decrypted item fields. Translation and
//! temporary reveal/copy state belong to the consuming shell.

use std::fmt;

use zann_core::secrets::{EncryptedPayload, FieldKind, PayloadError};

use crate::TotpParams;

const FIELD_ORDER: &[&str] = &[
    "username", "email", "password", "otp", "totp", "url", "key", "value", "notes",
];

/// A field ready for display, before translation or temporary reveal state.
/// Values and TOTP secrets remain local to the client.
#[derive(Clone)]
pub struct ItemDetailField {
    pub key: String,
    pub value: String,
    pub masked: bool,
    pub multiline: bool,
    pub totp: Option<TotpParams>,
}

impl fmt::Debug for ItemDetailField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ItemDetailField(<redacted>)")
    }
}

/// Parse the canonical payload schema and project fields in reading order.
/// Explicit metadata overrides the field-kind masking and multiline policy.
pub fn project_item_fields(payload_json: &str) -> Result<Vec<ItemDetailField>, PayloadError> {
    let payload = EncryptedPayload::from_bytes(payload_json.as_bytes())?;
    let mut fields: Vec<_> = payload
        .fields
        .iter()
        .map(|(key, field)| {
            let meta = field.meta.as_ref();
            let is_otp = matches!(field.kind, FieldKind::Otp);
            ItemDetailField {
                key: key.clone(),
                value: field.value.clone(),
                masked: meta
                    .and_then(|meta| meta.masked)
                    .unwrap_or(matches!(field.kind, FieldKind::Password) || is_otp),
                multiline: meta
                    .and_then(|meta| meta.multiline)
                    .unwrap_or(matches!(field.kind, FieldKind::Note)),
                totp: is_otp.then(|| totp_params(&field.value, &payload)),
            }
        })
        .collect();

    let rank = |key: &str| {
        FIELD_ORDER
            .iter()
            .position(|known| *known == key)
            .unwrap_or(FIELD_ORDER.len())
    };
    fields.sort_by(|left, right| {
        rank(&left.key)
            .cmp(&rank(&right.key))
            .then_with(|| left.key.cmp(&right.key))
    });
    Ok(fields)
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
