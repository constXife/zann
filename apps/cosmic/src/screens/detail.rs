//! Item detail: turning a decrypted payload into fields the detail column can show.
//!
//! Owned by [`super::vault`], which wraps these messages in its own.

use cosmic::iced::{Alignment, Background, Color, Length, Vector};
use cosmic::{theme, widget, Element};
use zann_client::app::local::ItemDetail;
use zann_ui_core::{generate_totp, project_item_fields, TotpParams};

use crate::i18n::{has, t};

#[derive(Clone)]
pub enum Message {
    ToggleReveal(usize),
    Copy { index: usize, value: String },
}

#[derive(Clone)]
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

#[derive(Clone)]
pub struct Detail {
    pub id: String,
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub fields: Vec<Field>,
    payload_json: String,
    copied_field: Option<usize>,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToggleReveal(index) => {
                formatter.debug_tuple("ToggleReveal").field(index).finish()
            }
            Self::Copy { index, .. } => formatter
                .debug_struct("Copy")
                .field("index", index)
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}
impl std::fmt::Debug for Field {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Field(<redacted>)")
    }
}
impl std::fmt::Debug for Detail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Detail(<redacted>)")
    }
}

impl Detail {
    pub fn parse(detail: ItemDetail) -> Result<Self, String> {
        let payload_json = detail.payload_json.clone();
        let fields = project_item_fields(&payload_json)
            .map_err(|err| err.to_string())?
            .into_iter()
            .map(|field| Field {
                label: label_for(&field.key),
                key: field.key,
                value: field.value,
                masked: field.masked,
                multiline: field.multiline,
                totp: field.totp,
                revealed: false,
            })
            .collect();

        Ok(Self {
            id: detail.id,
            title: detail.title,
            path: detail.path,
            type_id: detail.type_id,
            fields,
            payload_json,
            copied_field: None,
        })
    }

    pub fn payload_json(&self) -> &str {
        &self.payload_json
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
            // The shell owns the clipboard; vault forwards the value upwards.
            // Keeping the index here lets the view acknowledge the exact block
            // without changing its text or geometry.
            Message::Copy { index, .. } => self.copied_field = Some(index),
        }
    }

    pub fn copied_field(&self) -> Option<usize> {
        self.copied_field
    }

    pub fn clear_copy_feedback(&mut self) {
        self.copied_field = None;
    }

    pub fn view(&self, reveal_all: bool) -> Element<'_, Message> {
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
            column = column.push(field_view(
                index,
                field,
                reveal_all,
                self.copied_field == Some(index),
                spacing.space_xxs,
            ));
        }

        column.into()
    }
}

impl Field {
    /// The explicit eye button persists for the configured timeout; holding
    /// the platform reveal modifier is ephemeral and never mutates that state.
    pub fn display_value(&self, reveal_all: bool) -> String {
        if self.masked && !self.revealed && !reveal_all {
            "•".repeat(self.value.chars().count().clamp(4, 24))
        } else {
            self.value.clone()
        }
    }
}

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

fn field_view(
    index: usize,
    field: &Field,
    reveal_all: bool,
    copied: bool,
    gap: u16,
) -> Element<'_, Message> {
    let rows = widget::column::with_capacity(2)
        .push(widget::text::caption(field.label.clone()))
        .spacing(gap);

    if let Some(params) = field.totp.as_ref() {
        return rows.push(totp_view(index, params, copied)).into();
    }

    let shown = field.display_value(reveal_all);
    let shown_revealed = field.revealed || reveal_all;

    let value: Element<'_, Message> = if field.multiline {
        widget::text::body(shown).into()
    } else {
        widget::text::monotext(shown).into()
    };

    let copy_content = widget::row::with_capacity(2)
        .push(widget::container(value).width(Length::Fill))
        .push(
            widget::icon::from_name("edit-copy-symbolic")
                .size(16)
                .icon(),
        )
        .spacing(gap)
        .align_y(Alignment::Center);
    let copy_block = widget::button::custom(copy_content)
        .class(copy_block_class(copied))
        .padding([8, 10])
        .width(Length::Fill)
        .on_press(Message::Copy {
            index,
            value: field.value.clone(),
        });

    let mut controls = widget::row::with_capacity(2)
        .push(copy_block)
        .spacing(gap)
        .align_y(Alignment::Center);

    if field.masked {
        controls = controls.push(
            widget::button::icon(widget::icon::from_name(if shown_revealed {
                "image-red-eye-symbolic"
            } else {
                "document-properties-symbolic"
            }))
            .on_press(Message::ToggleReveal(index)),
        );
    }

    rows.push(controls).into()
}

fn totp_view(index: usize, params: &TotpParams, copied: bool) -> Element<'_, Message> {
    let spacing = theme::spacing();
    match generate_totp(params) {
        Ok(code) => {
            let split = code.code.len() / 2;
            let content = widget::row::with_capacity(3)
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
                    widget::icon::from_name("edit-copy-symbolic")
                        .size(16)
                        .icon(),
                )
                .spacing(spacing.space_xs)
                .align_y(Alignment::Center);
            widget::button::custom(content)
                .class(copy_block_class(copied))
                .padding([8, 10])
                .width(Length::Fill)
                .on_press(Message::Copy {
                    index,
                    value: code.code,
                })
                .into()
        }
        Err(err) => widget::text::caption(format!("invalid one-time code: {err}")).into(),
    }
}

#[derive(Clone, Copy)]
enum CopyBlockVisual {
    Active,
    Hovered,
    Pressed,
    Disabled,
}

/// A copyable value should read as a quiet inspector surface, not as a stack
/// of primary form buttons. Hover makes the affordance clear; copying tints
/// the same surface without changing any content or geometry.
fn copy_block_class(copied: bool) -> theme::Button {
    theme::Button::Custom {
        active: Box::new(move |focused, theme| {
            copy_block_style(theme, copied, CopyBlockVisual::Active, focused)
        }),
        disabled: Box::new(move |theme| {
            copy_block_style(theme, copied, CopyBlockVisual::Disabled, false)
        }),
        hovered: Box::new(move |focused, theme| {
            copy_block_style(theme, copied, CopyBlockVisual::Hovered, focused)
        }),
        pressed: Box::new(move |focused, theme| {
            copy_block_style(theme, copied, CopyBlockVisual::Pressed, focused)
        }),
    }
}

fn copy_block_style(
    theme: &cosmic::Theme,
    copied: bool,
    visual: CopyBlockVisual,
    focused: bool,
) -> widget::button::Style {
    let cosmic = theme.cosmic();
    let component = &cosmic.primary(theme.transparent).component;
    let accent = Color::from(cosmic.accent_color());
    let mut accent_fill = accent;
    accent_fill.a = match visual {
        CopyBlockVisual::Active | CopyBlockVisual::Disabled => 0.12,
        CopyBlockVisual::Hovered => 0.16,
        CopyBlockVisual::Pressed => 0.22,
    };

    let background = if copied {
        accent_fill
    } else {
        Color::from(match visual {
            CopyBlockVisual::Active => component.base,
            CopyBlockVisual::Hovered => component.hover,
            CopyBlockVisual::Pressed => component.pressed,
            CopyBlockVisual::Disabled => component.disabled,
        })
    };
    let content_color = if matches!(visual, CopyBlockVisual::Disabled) {
        Color::from(component.on_disabled)
    } else {
        Color::from(component.on)
    };

    widget::button::Style {
        shadow_offset: Vector::default(),
        background: Some(Background::Color(background)),
        border_radius: cosmic.radius_s().into(),
        border_width: 1.0,
        border_color: if copied {
            accent
        } else {
            component.divider.into()
        },
        outline_width: if focused { 1.0 } else { 0.0 },
        outline_color: if focused { accent } else { Color::TRANSPARENT },
        icon_color: Some(if copied { accent } else { content_color }),
        text_color: Some(content_color),
        overlay: None,
    }
}
