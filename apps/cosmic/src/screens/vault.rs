//! The open vault: nav categories, the item list, and the detail drawer.

use std::time::Duration;

use cosmic::app::context_drawer::{self, ContextDrawer};
use cosmic::iced::{Alignment, Length, Subscription, Task};
use cosmic::prelude::*;
use cosmic::widget::nav_bar;
use cosmic::{theme, widget, Element};
use zann_ffi::ItemSummary;
use zann_ui_core::{
    category_views, filtered_indices, FolderFilter, ItemCounts, ItemFilter, VaultScope,
};

use super::detail::{self, Detail};
use crate::backend::local::{self, ItemsPage};
use crate::backend::off_thread;
use crate::session::Session;

/// Label keys come from `schemas/ui_categories.json`; until the clients share
/// an i18n catalogue every frontend maps them itself.
fn translate_label_key(key: &str) -> &'static str {
    match key {
        "nav.allItems" => "All items",
        "nav.logins" => "Logins",
        "nav.notes" => "Notes",
        "nav.cards" => "Cards",
        "nav.identity" => "Identity",
        "nav.api" => "API keys",
        "nav.kv" => "Key/Value",
        "nav.infrastructure" => "Infrastructure",
        "nav.trash" => "Trash",
        "items.trashShared" => "Shared trash",
        _ => "Unknown",
    }
}

/// Schema icon names mapped onto the freedesktop names COSMIC ships.
fn category_icon(schema_icon: &str) -> &'static str {
    match schema_icon {
        "grid" => "view-grid-symbolic",
        "key" => "dialog-password-symbolic",
        "doc" => "text-x-generic-symbolic",
        "card" => "credit-card-symbolic",
        "person" => "contact-new-symbolic",
        "network" => "network-server-symbolic",
        "list" => "view-list-symbolic",
        "trash" => "user-trash-symbolic",
        _ => "folder-symbolic",
    }
}

fn item_icon(type_id: &str) -> &'static str {
    match type_id {
        "login" => "dialog-password-symbolic",
        "note" => "text-x-generic-symbolic",
        "card" => "credit-card-symbolic",
        "identity" => "contact-new-symbolic",
        "api" => "network-server-symbolic",
        _ => "view-list-symbolic",
    }
}

pub struct State {
    items: Vec<ItemSummary>,
    counts: ItemCounts,
    next_cursor: Option<String>,
    total: u64,
    query: String,
    nav: nav_bar::Model,
    detail: Option<Detail>,
    busy: bool,
    error: Option<String>,
}

#[derive(Clone, Debug)]
pub enum Message {
    QueryInput(String),
    ClearQuery,
    LoadMore,
    MoreLoaded(Result<ItemsPage, String>),
    Select(String),
    Loaded(Result<Detail, String>),
    Detail(detail::Message),
    CloseDetail,
    Lock,
    OpenSettings,
    Tick,
}

pub enum Outcome {
    None,
    Task(Task<Message>),
    /// The clipboard belongs to the shell.
    Copy(String),
    /// The drawer opened or closed; the shell owns that part of the window.
    ShowDetail(bool),
    Locked,
    OpenSettings,
}

impl State {
    pub fn new(page: ItemsPage, sync_error: Option<String>) -> Self {
        let mut state = Self {
            items: Vec::new(),
            counts: ItemCounts::default(),
            next_cursor: None,
            total: 0,
            query: String::new(),
            nav: nav_bar::Model::default(),
            detail: None,
            busy: false,
            error: sync_error.map(|err| format!("sync failed: {err}")),
        };
        state.apply_page(page, true);
        state.rebuild_nav();
        state
    }

    pub fn nav_model(&self) -> &nav_bar::Model {
        &self.nav
    }

    /// The items the current category, folder and search leave visible.
    pub fn visible(&self) -> Vec<&ItemSummary> {
        filtered_indices(&self.items, &self.filter())
            .into_iter()
            .map(|index| &self.items[index])
            .collect()
    }

    pub fn detail(&self) -> Option<&Detail> {
        self.detail.as_ref()
    }

    pub fn activate_nav(&mut self, id: nav_bar::Id) {
        self.nav.activate(id);
    }

    pub fn context_drawer(&self) -> Option<ContextDrawer<'_, Message>> {
        let detail = self.detail.as_ref()?;
        Some(
            context_drawer::context_drawer(
                detail.view().map(Message::Detail),
                Message::CloseDetail,
            )
            .title(detail.title.clone()),
        )
    }

    /// One-time codes roll over every period, so an open drawer with one needs
    /// a redraw every second.
    pub fn subscription(&self) -> Subscription<Message> {
        match self.detail.as_ref() {
            Some(detail) if detail.has_totp() => {
                cosmic::iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick)
            }
            _ => Subscription::none(),
        }
    }

    pub fn update(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::QueryInput(value) => self.query = value,

            Message::ClearQuery => self.query.clear(),

            Message::LoadMore => {
                let Some(cursor) = self.next_cursor.clone() else {
                    return Outcome::None;
                };
                if self.busy {
                    return Outcome::None;
                }
                let facade = session.facade();
                self.busy = true;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::MoreLoaded(
                        off_thread(move || local::items(&facade, Some(cursor))).await,
                    )
                }));
            }

            Message::MoreLoaded(result) => {
                self.busy = false;
                match result {
                    Ok(page) => {
                        self.apply_page(page, false);
                        self.rebuild_nav();
                    }
                    Err(err) => self.error = Some(err),
                }
            }

            Message::Select(id) => {
                let facade = session.facade();
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Loaded(
                        off_thread(move || local::item_get(&facade, id).and_then(Detail::parse))
                            .await,
                    )
                }));
            }

            Message::Loaded(Ok(detail)) => {
                self.detail = Some(detail);
                return Outcome::ShowDetail(true);
            }

            Message::Loaded(Err(err)) => self.error = Some(err),

            Message::Detail(detail::Message::Copy(value)) => return Outcome::Copy(value),

            Message::Detail(message) => {
                if let Some(detail) = self.detail.as_mut() {
                    detail.update(message);
                }
            }

            Message::CloseDetail => {
                self.detail = None;
                return Outcome::ShowDetail(false);
            }

            Message::Lock => {
                session.lock();
                return Outcome::Locked;
            }

            Message::OpenSettings => return Outcome::OpenSettings,

            Message::Tick => {}
        }
        Outcome::None
    }

    pub fn view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let visible = self.visible();

        let toolbar = widget::row::with_capacity(3)
            .push(
                widget::text_input::search_input("Search items", &self.query)
                    .on_input(Message::QueryInput)
                    .on_clear(Message::ClearQuery)
                    .width(Length::Fill),
            )
            .push(widget::button::standard("Settings").on_press(Message::OpenSettings))
            .push(widget::button::standard("Lock").on_press(Message::Lock))
            .spacing(spacing.space_xs)
            .align_y(Alignment::Center);

        let list: Element<'_, Message> = if visible.is_empty() {
            widget::text::body("Nothing here.")
                .apply(widget::container)
                .width(Length::Fill)
                .padding(spacing.space_m)
                .into()
        } else {
            let selected = self.detail.as_ref().map(|detail| detail.id.as_str());
            let mut column = widget::list_column();
            for item in &visible {
                column = column.add(
                    widget::list::button(item_row(item))
                        .selected(selected == Some(item.id.as_str()))
                        .on_press(Message::Select(item.id.clone())),
                );
            }
            column.into_element()
        };

        let mut footer = widget::row::with_capacity(2)
            .push(widget::text::caption(format!(
                "{} of {} items loaded, {} shown",
                self.items.len(),
                self.total,
                visible.len()
            )))
            .spacing(spacing.space_xs)
            .align_y(Alignment::Center);

        if self.next_cursor.is_some() {
            let mut more = widget::button::text("Load more");
            if !self.busy {
                more = more.on_press(Message::LoadMore);
            }
            footer = footer.push(more);
        }

        let mut content = widget::column::with_capacity(4)
            .push(toolbar)
            .push(widget::scrollable(list).height(Length::Fill));

        if let Some(error) = self.error.as_ref() {
            content = content.push(widget::text::caption(error.clone()));
        }

        content
            .push(footer)
            .spacing(spacing.space_s)
            .padding(spacing.space_s)
            .into()
    }

    fn apply_page(&mut self, page: ItemsPage, replace: bool) {
        if replace {
            self.items = page.items;
        } else {
            self.items.extend(page.items);
        }
        self.counts = page.counts;
        self.next_cursor = page.next_cursor;
        self.total = page.total;
    }

    /// Rebuilds the nav entries from the shared schema, keeping the selection.
    fn rebuild_nav(&mut self) {
        let selected = self.selected_category();
        self.nav.clear();
        for view in category_views(&self.counts, VaultScope::Personal) {
            let label = format!("{} ({})", translate_label_key(&view.label_key), view.count);
            let entity = self
                .nav
                .insert()
                .text(label)
                .icon(widget::icon::from_name(category_icon(&view.icon)))
                .data(view.id.clone())
                .id();
            if selected.as_deref() == Some(view.id.as_str()) {
                self.nav.activate(entity);
            }
        }
        if self.nav.active_data::<String>().is_none() {
            self.nav.activate_position(0);
        }
    }

    fn selected_category(&self) -> Option<String> {
        self.nav.active_data::<String>().cloned()
    }

    fn filter(&self) -> ItemFilter {
        ItemFilter {
            category_id: self.selected_category(),
            folder: FolderFilter::Any,
            query: self.query.clone(),
        }
    }
}

fn item_row(item: &ItemSummary) -> Element<'_, Message> {
    let spacing = theme::spacing();
    widget::row::with_capacity(3)
        .push(
            widget::icon::from_name(item_icon(&item.type_id))
                .size(20)
                .icon(),
        )
        .push(
            widget::column::with_capacity(2)
                .push(widget::text::body(item.title.clone()))
                .push(widget::text::caption(item.path.clone()))
                .width(Length::Fill),
        )
        .push(widget::text::caption(item.type_id.clone()))
        .spacing(spacing.space_s)
        .align_y(Alignment::Center)
        .into()
}
