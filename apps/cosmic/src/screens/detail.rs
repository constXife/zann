//! Item detail: turning a decrypted payload into fields the column can show.
//!
//! Owned by [`super::vault`], which wraps these messages in its own.

use cosmic::iced::{Alignment, Length};
use cosmic::{theme, widget, Element};
use zann_crypto::secrets::{EncryptedPayload, FieldKind};
use zann_ffi::ItemDetail;
use zann_ui_core::{generate_totp, TotpParams};

use crate::i18n::{has, t};

/// Fields the schemas put first, in the order a reader expects them.
const FIELD_ORDER: &[&str] = &[
    "username", "email", "password", "otp", "totp", "url", "key", "value", "notes",
];

#[derive(Clone, Debug)]
pub enum Message {
    ToggleReveal(usize),
    Copy(String),
}

#[derive(Debug, Clone)]
pub struct Field {
    pub key: String,
    pub label: String,
    pub value: String,
    pub masked: bool,
    pub multiline: bool,
    pub revealed: bool,
    /// Set for `otp` fields: the parameters the code is generated from.
    pub totp: Option<TotpParams>,
}

#[derive(Debug, Clone)]
pub struct Detail {
    pub id: String,
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub fields: Vec<Field>,
}

impl Detail {
    pub fn parse(detail: ItemDetail) -> Result<Self, String> {
        let payload: EncryptedPayload =
            serde_json::from_str(&detail.payload_json).map_err(|err| err.to_string())?;

        let mut fields: Vec<Field> = payload
            .fields
            .iter()
            .map(|(key, value)| {
                let meta = value.meta.as_ref();
                let is_otp = matches!(value.kind, FieldKind::Otp);
                Field {
                    key: key.clone(),
                    label: label_for(key),
                    masked: meta
                        .and_then(|meta| meta.masked)
                        .unwrap_or(matches!(value.kind, FieldKind::Password) || is_otp),
                    multiline: meta
                        .and_then(|meta| meta.multiline)
                        .unwrap_or(matches!(value.kind, FieldKind::Note)),
                    totp: is_otp.then(|| totp_params(&value.value, &payload)),
                    value: value.value.clone(),
                    revealed: false,
                }
            })
            .collect();

        fields.sort_by_key(|field| {
            let rank = FIELD_ORDER
                .iter()
                .position(|known| *known == field.key)
                .unwrap_or(FIELD_ORDER.len());
            (rank, field.key.clone())
        });

        Ok(Self {
            id: detail.id,
            title: detail.title,
            path: detail.path,
            type_id: detail.type_id,
            fields,
        })
    }

    /// Only a one-time code needs the app to keep redrawing.
    pub fn has_totp(&self) -> bool {
        self.fields.iter().any(|field| field.totp.is_some())
    }

    pub fn update(&mut self, message: Message) {
        match message {
            Message::ToggleReveal(index) => {
                if let Some(field) = self.fields.get_mut(index) {
                    field.revealed = !field.revealed;
                }
            }
            // The shell owns the clipboard; vault forwards this one upwards.
            Message::Copy(_) => {}
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut column = widget::column::with_capacity(self.fields.len() + 2)
            .push(widget::text::caption(format!(
                "{} · {}",
                self.path, self.type_id
            )))
            .spacing(spacing.space_s);

        if self.fields.is_empty() {
            column = column.push(widget::text::body(t("items.noFields")));
        }

        for (index, field) in self.fields.iter().enumerate() {
            column = column.push(field_view(index, field, spacing.space_xxs));
        }

        column.into()
    }
}

/// An `otp` field holds either a bare secret or a full `otpauth://` URI; the
/// payload's `extra` map carries the defaults for the bare case.
///
/// This mirrors `extractTotpData` in the desktop app's `useItemDetails.ts` and
/// is a candidate for `zann-ui-core` once a second client needs it.
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

/// Field names are catalogue keys under `fields.`, which is where the desktop
/// app looks them up too. A name the catalogue has never heard of is spelled out
/// from the key rather than shown as one.
fn label_for(key: &str) -> String {
    match key {
        "otp" | "totp" => t("fields.otp"),
        named if has(&format!("fields.{named}")) => t(&format!("fields.{named}")),
        other => {
            let spaced = other.replace('_', " ");
            let mut chars = spaced.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => spaced,
            }
        }
    }
}

fn field_view(index: usize, field: &Field, gap: u16) -> Element<'_, Message> {
    let rows = widget::column::with_capacity(2)
        .push(widget::text::caption(field.label.clone()))
        .spacing(gap);

    if let Some(params) = field.totp.as_ref() {
        return rows.push(totp_view(params)).into();
    }

    let shown = if field.masked && !field.revealed {
        "•".repeat(field.value.chars().count().clamp(4, 24))
    } else {
        field.value.clone()
    };

    let value: Element<'_, Message> = if field.multiline {
        widget::text::body(shown).into()
    } else {
        widget::text::monotext(shown).into()
    };

    let mut controls = widget::row::with_capacity(3)
        .push(widget::container(value).width(Length::Fill))
        .spacing(gap)
        .align_y(Alignment::Center);

    if field.masked {
        controls = controls.push(
            widget::button::icon(widget::icon::from_name(if field.revealed {
                "image-red-eye-symbolic"
            } else {
                "document-properties-symbolic"
            }))
            .on_press(Message::ToggleReveal(index)),
        );
    }

    controls = controls.push(
        widget::button::icon(widget::icon::from_name("edit-copy-symbolic"))
            .on_press(Message::Copy(field.value.clone())),
    );

    rows.push(controls).into()
}

fn totp_view(params: &TotpParams) -> Element<'_, Message> {
    let spacing = theme::spacing();
    match generate_totp(params) {
        Ok(code) => {
            let split = code.code.len() / 2;
            widget::row::with_capacity(3)
                .push(
                    widget::container(widget::text::title3(format!(
                        "{} {}",
                        &code.code[..split],
                        &code.code[split..]
                    )))
                    .width(Length::Fill),
                )
                .push(widget::text::caption(format!(
                    "{}s",
                    code.remaining_seconds
                )))
                .push(
                    widget::button::icon(widget::icon::from_name("edit-copy-symbolic"))
                        .on_press(Message::Copy(code.code.clone())),
                )
                .spacing(spacing.space_xs)
                .align_y(Alignment::Center)
                .into()
        }
        Err(err) => widget::text::caption(format!("invalid one-time code: {err}")).into(),
    }
}
