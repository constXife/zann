//! Item history browser for the COSMIC detail column.

use cosmic::iced::{Alignment, Length};
use cosmic::{theme, widget, Element};
use zann_client::app::local::{ItemDetail, ItemHistoryDetail, ItemHistorySummary};

use super::detail::{self, Detail};
use crate::i18n::t;

pub struct State {
    item_id: String,
    title: String,
    path: String,
    entries: Vec<ItemHistorySummary>,
    selected_version: Option<i64>,
    detail: Option<Detail>,
    loading: bool,
    version_loading: bool,
    restoring: bool,
    confirming_restore: bool,
    error: Option<String>,
}

#[derive(Clone, Debug)]
pub enum Message {
    EntriesLoaded(Result<Vec<ItemHistorySummary>, String>),
    Select(i64),
    VersionLoaded {
        version: i64,
        result: Result<ItemHistoryDetail, String>,
    },
    Detail(detail::Message),
    AskRestore,
    CancelRestore,
    ConfirmRestore,
    Restored(Result<Detail, String>),
    Close,
}

pub enum Outcome {
    None,
    LoadVersion(i64),
    Restore(i64),
    Restored(Detail),
    Copy(String),
    Close,
}

impl State {
    pub fn new(detail: &Detail) -> Self {
        Self {
            item_id: detail.id.clone(),
            title: detail.title.clone(),
            path: detail.path.clone(),
            entries: Vec::new(),
            selected_version: None,
            detail: None,
            loading: true,
            version_loading: false,
            restoring: false,
            confirming_restore: false,
            error: None,
        }
    }

    pub fn is_loading(&self) -> bool {
        self.loading
    }

    pub fn item_id(&self) -> &str {
        &self.item_id
    }

    pub fn parse_detail(&self, history: ItemHistoryDetail) -> Result<Detail, String> {
        let type_id = zann_ui_core::item_detail::payload_type_id(&history.payload_json)
            .map_err(|error| error.to_string())?;
        Detail::parse(ItemDetail {
            id: self.item_id.clone(),
            title: self.title.clone(),
            path: self.path.clone(),
            type_id,
            payload_json: history.payload_json,
        })
    }

    pub fn hide_revealed(&mut self) {
        if let Some(detail) = self.detail.as_mut() {
            for field in &mut detail.fields {
                field.revealed = false;
            }
        }
    }

    pub fn has_totp(&self) -> bool {
        self.detail.as_ref().is_some_and(Detail::has_totp)
    }

    pub fn update(&mut self, message: Message) -> Outcome {
        match message {
            Message::EntriesLoaded(Ok(entries)) => {
                self.loading = false;
                self.entries = entries;
                self.error = None;
                if let Some(version) = self.entries.first().map(|entry| entry.version) {
                    return self.select(version);
                }
            }
            Message::EntriesLoaded(Err(error)) => {
                self.loading = false;
                self.error = Some(error);
            }
            Message::Select(version) => return self.select(version),
            Message::VersionLoaded { version, result } => {
                if self.selected_version != Some(version) {
                    return Outcome::None;
                }
                self.version_loading = false;
                match result.and_then(|history| self.parse_detail(history)) {
                    Ok(detail) => {
                        self.detail = Some(detail);
                        self.error = None;
                    }
                    Err(error) => self.error = Some(error),
                }
            }
            Message::Detail(detail::Message::Copy { value, .. }) => {
                return Outcome::Copy(value);
            }
            Message::Detail(message @ detail::Message::ToggleReveal(_)) => {
                if let Some(detail) = self.detail.as_mut() {
                    detail.update(message);
                }
            }
            Message::AskRestore => {
                if self.selected_version.is_some() && !self.restoring {
                    self.confirming_restore = true;
                }
            }
            Message::CancelRestore => self.confirming_restore = false,
            Message::ConfirmRestore => {
                let Some(version) = self.selected_version else {
                    return Outcome::None;
                };
                if self.restoring {
                    return Outcome::None;
                }
                self.confirming_restore = false;
                self.restoring = true;
                self.error = None;
                return Outcome::Restore(version);
            }
            Message::Restored(Ok(detail)) => return Outcome::Restored(detail),
            Message::Restored(Err(error)) => {
                self.restoring = false;
                self.error = Some(error);
            }
            Message::Close if self.restoring => {}
            Message::Close => return Outcome::Close,
        }
        Outcome::None
    }

    fn select(&mut self, version: i64) -> Outcome {
        if self.loading || self.restoring || self.selected_version == Some(version) {
            return Outcome::None;
        }
        self.selected_version = Some(version);
        self.detail = None;
        self.version_loading = true;
        self.confirming_restore = false;
        self.error = None;
        Outcome::LoadVersion(version)
    }

    pub fn view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let header = widget::row::with_capacity(2)
            .push(
                widget::column::with_capacity(2)
                    .push(widget::text::title4(t("items.historyTimeTravelTitle")))
                    .push(widget::text::caption(self.title.clone()))
                    .width(Length::Fill),
            )
            .push(widget::button::standard(t("common.close")).on_press(Message::Close))
            .spacing(spacing.space_s)
            .align_y(Alignment::Center);

        let mut page = widget::column::with_capacity(3)
            .push(header)
            .spacing(spacing.space_s)
            .padding(spacing.space_s)
            .height(Length::Fill);

        if self.loading {
            return page
                .push(super::centered(widget::text::body(t(
                    "items.previousPasswordsLoading",
                ))))
                .into();
        }

        if self.entries.is_empty() {
            page = page.push(super::centered(widget::text::body(t("items.historyEmpty"))));
        } else {
            let mut versions = widget::list_column();
            for entry in &self.entries {
                versions = versions.add(
                    widget::list::button(history_row(entry))
                        .selected(self.selected_version == Some(entry.version))
                        .on_press(Message::Select(entry.version)),
                );
            }

            let version_detail: Element<'_, Message> = if self.version_loading {
                super::centered(widget::text::body(t("items.historyVersionLoading")))
            } else if let Some(detail) = self.detail.as_ref() {
                let mut content = widget::column::with_capacity(4)
                    .push(widget::text::heading(format!(
                        "{} v{}",
                        t("items.historyVersionTitle"),
                        self.selected_version.unwrap_or_default()
                    )))
                    .push(detail.view(false).map(Message::Detail))
                    .spacing(spacing.space_s);

                if self.confirming_restore {
                    content = content
                        .push(widget::text::body(t("items.restorePreviousMessage")))
                        .push(
                            widget::row::with_capacity(2)
                                .push(
                                    widget::button::standard(t("common.cancel"))
                                        .on_press(Message::CancelRestore),
                                )
                                .push(
                                    widget::button::suggested(t("items.restorePreviousConfirm"))
                                        .on_press(Message::ConfirmRestore),
                                )
                                .spacing(spacing.space_s),
                        );
                } else {
                    let mut restore = widget::button::standard(if self.restoring {
                        t("common.loading")
                    } else {
                        t("items.historyRestore")
                    });
                    if !self.restoring {
                        restore = restore.on_press(Message::AskRestore);
                    }
                    content = content.push(restore);
                }
                widget::scrollable(content).height(Length::Fill).into()
            } else {
                super::centered(widget::text::body(t("items.historyVersionMissing")))
            };

            page = page.push(
                widget::row::with_capacity(3)
                    .push(
                        widget::scrollable(versions.into_element())
                            .width(Length::Fixed(230.0))
                            .height(Length::Fill),
                    )
                    .push(widget::divider::vertical::default())
                    .push(
                        widget::container(version_detail)
                            .padding([0, spacing.space_s])
                            .width(Length::Fill)
                            .height(Length::Fill),
                    )
                    .height(Length::Fill),
            );
        }

        if let Some(error) = self.error.as_ref() {
            page = page.push(widget::text::caption(error.clone()));
        }
        page.into()
    }
}

fn history_row(entry: &ItemHistorySummary) -> Element<'_, Message> {
    let spacing = theme::spacing();
    let author = entry
        .changed_by_name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&entry.changed_by_email);
    let change = t(match entry.change_type {
        1 => "items.historyChangeCreate",
        3 => "items.historyChangeDelete",
        4 => "items.historyChangeRestore",
        _ => "items.historyChangeUpdate",
    });
    let status = if entry.pending {
        format!(" · {}", t("items.historyPending"))
    } else {
        String::new()
    };
    widget::column::with_capacity(3)
        .push(widget::text::body(format!(
            "v{} · {change}{status}",
            entry.version
        )))
        .push(widget::text::caption(format_timestamp(&entry.created_at)))
        .push(widget::text::caption(author.to_string()))
        .spacing(spacing.space_xxxs)
        .into()
}

fn format_timestamp(timestamp: &str) -> String {
    timestamp
        .split_once('.')
        .map_or(timestamp, |(seconds, _)| seconds)
        .replace('T', " ")
        .trim_end_matches('Z')
        .to_string()
}
