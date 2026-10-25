//! Native create/edit form for decrypted item payloads.
//!
//! The form owns presentation state only. Persistence stays behind the shared
//! facade and the draft is converted to its JSON wire record only on submit.

use std::fmt;

use cosmic::iced::{Alignment, Length};
use cosmic::{theme, widget, Element};
#[cfg(test)]
use serde_json::Value;
use zann_client::app::local::{ItemCreate, ItemUpdate};
use zann_ui_core::item_editor::{field_schemas, DraftField, FieldKind, ItemDraft};

use super::detail::Detail;
use crate::i18n::{has, t};

const FIELD_KINDS: &[FieldKind] = &[
    FieldKind::Text,
    FieldKind::Password,
    FieldKind::Url,
    FieldKind::Otp,
    FieldKind::Note,
];

#[derive(Clone)]
enum Mode {
    Create,
    Edit(String),
}

pub struct State {
    mode: Mode,
    draft: ItemDraft,
    revealed: Vec<bool>,
    multiline: Vec<Option<widget::text_editor::Content>>,
    busy: bool,
    error: Option<String>,
}

#[derive(Clone)]
pub enum Message {
    Path(String),
    Type(String),
    FieldKey(usize, String),
    FieldValue(usize, String),
    Multiline(usize, widget::text_editor::Action),
    FieldKind(usize, FieldKind),
    ToggleReveal(usize),
    AddField,
    RemoveField(usize),
    Cancel,
    Submit,
}

// Text input messages contain decrypted values. libcosmic requires Debug on
// the application message, so redact those values instead of deriving it.
impl fmt::Debug for Message {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(_) => formatter.write_str("Path(<redacted>)"),
            Self::Type(value) => formatter.debug_tuple("Type").field(value).finish(),
            Self::FieldKey(index, _) => formatter
                .debug_tuple("FieldKey")
                .field(index)
                .field(&"<redacted>")
                .finish(),
            Self::Multiline(index, _) => formatter
                .debug_tuple("Multiline")
                .field(index)
                .field(&"<redacted>")
                .finish(),
            Self::FieldValue(index, _) => formatter
                .debug_tuple("FieldValue")
                .field(index)
                .field(&"<redacted>")
                .finish(),
            Self::FieldKind(index, kind) => formatter
                .debug_tuple("FieldKind")
                .field(index)
                .field(kind)
                .finish(),
            Self::ToggleReveal(index) => {
                formatter.debug_tuple("ToggleReveal").field(index).finish()
            }
            Self::AddField => formatter.write_str("AddField"),
            Self::RemoveField(index) => formatter.debug_tuple("RemoveField").field(index).finish(),
            Self::Cancel => formatter.write_str("Cancel"),
            Self::Submit => formatter.write_str("Submit"),
        }
    }
}

pub enum Outcome {
    None,
    Cancel,
    Submit(SaveRequest),
}

pub enum SaveRequest {
    Create(ItemCreate),
    Update { id: String, item: ItemUpdate },
}

impl State {
    pub fn create(type_id: impl Into<String>) -> Result<Self, String> {
        let draft = ItemDraft::create(&type_id.into()).map_err(|error| error.to_string())?;
        Ok(Self::from_draft(Mode::Create, draft))
    }

    pub fn edit(detail: &Detail) -> Result<Self, String> {
        let draft = ItemDraft::edit(detail.path.clone(), detail.payload_json())
            .map_err(|error| error.to_string())?;
        Ok(Self::from_draft(Mode::Edit(detail.id.clone()), draft))
    }

    fn from_draft(mode: Mode, draft: ItemDraft) -> Self {
        let revealed = vec![false; draft.fields.len()];
        let multiline = draft.fields.iter().map(multiline_content).collect();
        Self {
            mode,
            draft,
            revealed,
            multiline,
            busy: false,
            error: None,
        }
    }

    pub fn hide_revealed(&mut self) {
        self.revealed.fill(false);
    }

    pub fn is_busy(&self) -> bool {
        self.busy
    }

    pub fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
        if busy {
            self.error = None;
        }
    }

    pub fn set_error(&mut self, error: String) {
        self.busy = false;
        self.error = Some(error);
    }

    pub fn update(&mut self, message: Message) -> Outcome {
        if self.busy {
            return Outcome::None;
        }
        match message {
            Message::Path(value) => self.draft.path = value,
            Message::Type(value) => match self.draft.set_type(value) {
                Ok(true) => {
                    self.revealed = vec![false; self.draft.fields.len()];
                    self.multiline = self.draft.fields.iter().map(multiline_content).collect();
                }
                Ok(false) => {}
                Err(error) => self.error = Some(t(error.translation_key())),
            },
            Message::FieldKey(index, value) => {
                if let Some(field) = self.draft.fields.get_mut(index) {
                    field.key = value;
                }
            }
            Message::FieldValue(index, value) => {
                if let Some(field) = self.draft.fields.get_mut(index) {
                    field.value.value = value;
                }
            }
            Message::Multiline(index, action) => {
                if let (Some(field), Some(Some(content))) = (
                    self.draft.fields.get_mut(index),
                    self.multiline.get_mut(index),
                ) {
                    content.perform(action);
                    field.value.value = content.text();
                }
            }
            Message::FieldKind(index, kind) => {
                if let Some(field) = self.draft.fields.get_mut(index) {
                    field.value.kind = kind;
                    self.revealed[index] = false;
                    self.multiline[index] = multiline_content(field);
                }
            }
            Message::ToggleReveal(index) => {
                if let Some(revealed) = self.revealed.get_mut(index) {
                    *revealed = !*revealed;
                }
            }
            Message::AddField => {
                self.draft.fields.push(DraftField::blank());
                self.revealed.push(false);
                self.multiline.push(None);
            }
            Message::RemoveField(index) => {
                if index < self.draft.fields.len() {
                    self.draft.fields.remove(index);
                    self.revealed.remove(index);
                    self.multiline.remove(index);
                }
            }
            Message::Cancel => return Outcome::Cancel,
            Message::Submit => match self.save_request() {
                Ok(request) => {
                    self.set_busy(true);
                    return Outcome::Submit(request);
                }
                Err(error) => self.error = Some(error),
            },
        }
        Outcome::None
    }

    fn save_request(&self) -> Result<SaveRequest, String> {
        let path = self.draft.path.trim();
        let payload_json = self
            .draft
            .payload_json()
            .map_err(|error| t(error.translation_key()))?;
        let title = path
            .rsplit('/')
            .find(|segment| !segment.trim().is_empty())
            .unwrap_or(path)
            .trim()
            .to_string();

        Ok(match &self.mode {
            Mode::Create => SaveRequest::Create(ItemCreate {
                title,
                path: path.to_string(),
                type_id: self.draft.type_id.clone(),
                payload_json,
            }),
            Mode::Edit(id) => SaveRequest::Update {
                id: id.clone(),
                item: ItemUpdate {
                    title,
                    path: path.to_string(),
                    type_id: self.draft.type_id.clone(),
                    payload_json,
                },
            },
        })
    }

    pub fn view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let type_ids: Vec<_> = field_schemas().keys().map(String::as_str).collect();
        let type_labels: Vec<String> = type_ids.iter().map(|type_id| type_label(type_id)).collect();
        let selected_type = type_ids
            .iter()
            .position(|type_id| *type_id == self.draft.type_id);

        let heading = match self.mode {
            Mode::Create => t("create.itemHeader"),
            Mode::Edit(_) => t("create.itemEditHeader"),
        };
        let mut form = widget::column::with_capacity(self.draft.fields.len() + 8)
            .push(widget::text::title4(heading))
            .push(widget::text::caption(t("create.itemPath")))
            .push(
                widget::text_input::text_input(t("create.itemPathHint"), &self.draft.path)
                    .on_input(Message::Path),
            )
            .push(widget::text::caption(t("create.itemType")))
            .push(widget::dropdown(type_labels, selected_type, move |index| {
                Message::Type(type_ids[index].to_string())
            }))
            .push(widget::text::heading(t("create.customFields")))
            .spacing(spacing.space_s)
            .width(Length::Fill);

        for (index, field) in self.draft.fields.iter().enumerate() {
            form = form.push(field_row(
                index,
                field,
                self.revealed[index],
                self.multiline[index].as_ref(),
            ));
        }

        form =
            form.push(widget::button::standard(t("create.addField")).on_press(Message::AddField));
        if let Some(error) = self.error.as_ref() {
            form = form.push(widget::text::caption(error.clone()));
        }

        let mut save = widget::button::suggested(if self.busy {
            t("common.loading")
        } else {
            t("common.save")
        });
        if !self.busy {
            save = save.on_press(Message::Submit);
        }
        let mut cancel = widget::button::standard(t("common.cancel"));
        if !self.busy {
            cancel = cancel.on_press(Message::Cancel);
        }

        form.push(
            widget::row::with_capacity(2)
                .push(cancel)
                .push(save)
                .spacing(spacing.space_s)
                .align_y(Alignment::Center),
        )
        .into()
    }
}

fn multiline_content(field: &DraftField) -> Option<widget::text_editor::Content> {
    (field.multiline() && !field.masked())
        .then(|| widget::text_editor::Content::with_text(&field.value.value))
}

fn field_row<'a>(
    index: usize,
    field: &'a DraftField,
    revealed: bool,
    multiline: Option<&'a widget::text_editor::Content>,
) -> Element<'a, Message> {
    let spacing = theme::spacing();
    let selected_kind = FIELD_KINDS
        .iter()
        .position(|kind| *kind == field.value.kind);
    let kind_labels: Vec<String> = FIELD_KINDS.iter().map(|kind| kind_label(*kind)).collect();
    let key = widget::text_input::text_input(t("create.fieldKeyPlaceholder"), &field.key)
        .on_input(move |value| Message::FieldKey(index, value))
        .width(Length::Fixed(170.0));
    let value: Element<'_, Message> = if field.masked() {
        widget::text_input::secure_input(
            t("create.fieldValuePlaceholder"),
            &field.value.value,
            Some(Message::ToggleReveal(index)),
            !revealed,
        )
        .on_input(move |value| Message::FieldValue(index, value))
        .width(Length::Fill)
        .into()
    } else if let Some(content) = multiline {
        widget::text_editor(content)
            .on_action(move |action| Message::Multiline(index, action))
            .height(Length::Fixed(120.0))
            .into()
    } else {
        widget::text_input::text_input(t("create.fieldValuePlaceholder"), &field.value.value)
            .on_input(move |value| Message::FieldValue(index, value))
            .width(Length::Fill)
            .into()
    };

    widget::row::with_capacity(4)
        .push(key)
        .push(
            widget::dropdown(kind_labels, selected_kind, move |kind| {
                Message::FieldKind(index, FIELD_KINDS[kind])
            })
            .width(Length::Fixed(130.0)),
        )
        .push(value)
        .push(
            widget::button::icon(widget::icon::from_name("edit-delete-symbolic"))
                .on_press(Message::RemoveField(index)),
        )
        .spacing(spacing.space_xs)
        .align_y(Alignment::Center)
        .into()
}

fn type_label(type_id: &str) -> String {
    let key = format!("types.{type_id}");
    if has(&key) {
        t(&key)
    } else {
        type_id.to_string()
    }
}

fn kind_label(kind: FieldKind) -> String {
    t(match kind {
        FieldKind::Text => "create.kindText",
        FieldKind::Password => "create.kindPassword",
        FieldKind::Url => "create.kindUrl",
        FieldKind::Otp => "create.kindOtp",
        FieldKind::Note => "create.kindNote",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zann_client::app::local::ItemDetail;

    #[test]
    fn create_request_contains_typed_payload() {
        let mut editor = State::create("login").expect("known template");
        editor.update(Message::Path("personal/mail".to_string()));
        editor.update(Message::FieldValue(0, "alice@example.com".to_string()));
        editor.update(Message::FieldValue(1, "secret".to_string()));

        let Outcome::Submit(SaveRequest::Create(request)) = editor.update(Message::Submit) else {
            panic!("valid form should submit");
        };
        assert_eq!(request.title, "mail");
        assert_eq!(request.type_id, "login");
        let payload: Value = serde_json::from_str(&request.payload_json).expect("payload JSON");
        assert_eq!(payload["typeId"], "login");
        assert_eq!(payload["fields"]["password"]["kind"], "password");
        assert_eq!(payload["fields"]["password"]["value"], "secret");
    }

    #[test]
    fn duplicate_keys_do_not_submit() {
        let mut editor = State::create("note").expect("known template");
        editor.update(Message::Path("notes/one".to_string()));
        editor.update(Message::AddField);
        editor.update(Message::FieldKey(1, "text".to_string()));
        assert!(matches!(editor.update(Message::Submit), Outcome::None));
        assert!(!editor.is_busy());
    }

    #[test]
    fn editing_preserves_field_metadata_and_payload_extras() {
        let detail = Detail::parse(ItemDetail {
            id: "item-id".to_string(),
            title: "mail".to_string(),
            path: "personal/mail".to_string(),
            type_id: "login".to_string(),
            payload_json: r#"{"v":1,"typeId":"login","fields":{"password":{"kind":"password","value":"old","meta":{"masked":true,"placeholder":"generated"}}},"extra":{"issuer":"Zann"}}"#
                .to_string(),
        })
        .expect("detail");
        let mut editor = State::edit(&detail).expect("valid payload");
        editor.update(Message::FieldValue(0, "new".to_string()));

        let Outcome::Submit(SaveRequest::Update { id, item }) = editor.update(Message::Submit)
        else {
            panic!("valid edit should submit");
        };
        assert_eq!(id, "item-id");
        let payload: Value = serde_json::from_str(&item.payload_json).expect("payload JSON");
        assert_eq!(payload["fields"]["password"]["value"], "new");
        assert_eq!(
            payload["fields"]["password"]["meta"]["placeholder"],
            "generated"
        );
        assert_eq!(payload["extra"]["issuer"], "Zann");
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use zann_client::app::local::ItemDetail;
    #[test]
    fn explicit_reveals_are_reset_without_changing_the_draft() {
        let detail = Detail::parse(ItemDetail { id:"id".into(), title:"t".into(), path:"item".into(), type_id:"note".into(), payload_json:r#"{"v":1,"typeId":"note","fields":{"text":{"kind":"text","value":"private","meta":{"masked":true}}}}"#.into() }).unwrap();
        let mut editor = State::edit(&detail).unwrap();
        assert!(editor.draft.fields[0].masked());
        editor.update(Message::ToggleReveal(0));
        assert!(editor.revealed[0]);
        editor.hide_revealed();
        assert!(!editor.revealed[0]);
        assert_eq!(editor.draft.fields[0].value.value, "private");
    }
}
