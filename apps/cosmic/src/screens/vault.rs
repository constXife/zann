//! The open vault: nav categories, the item list, and the detail column.
//!
//! The nav bar is the shell's (libcosmic draws it from [`State::nav_model`]);
//! the two columns in here are the same split the desktop app has, down to the
//! widths in [`layout`], so a reader moving between the clients is not asked to
//! learn a second shape.

use std::time::Duration;

use cosmic::iced::{event, mouse, Alignment, Event, Length, Subscription, Task};
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
use crate::i18n::{t, t_args};
use crate::session::Session;

/// Schema icon names mapped onto the freedesktop names COSMIC ships.
fn category_icon(schema_icon: &str) -> &'static str {
    match schema_icon {
        "grid" => "view-grid-symbolic",
        "key" => "dialog-password-symbolic",
        "doc" => "text-x-generic-symbolic",
        "card" => "payment-card-symbolic",
        "person" => "contact-new-symbolic",
        "network" => "network-server-symbolic",
        "list" => "view-list-symbolic",
        "trash" => "user-trash-symbolic",
        _ => "folder-symbolic",
    }
}

/// The widths the desktop app's `useAppLayout.ts` uses, so the split lands in
/// the same place in both clients. The list is the column that carries a width;
/// the detail takes whatever is left.
mod layout {
    pub const LIST_MIN: f32 = 320.0;
    pub const LIST_MAX: f32 = 560.0;
    pub const LIST_DEFAULT: f32 = 400.0;
    pub const DETAIL_MIN: f32 = 560.0;
    pub const HANDLE: f32 = 5.0;
}

fn item_icon(type_id: &str) -> &'static str {
    match type_id {
        "login" => "dialog-password-symbolic",
        "note" => "text-x-generic-symbolic",
        "card" => "payment-card-symbolic",
        "identity" => "contact-new-symbolic",
        "api" => "network-server-symbolic",
        _ => "view-list-symbolic",
    }
}

/// A held splitter. Pressing it does not say where the pointer is, so the
/// origin is recorded on the first move and every later move is a delta from
/// there — which also means a press that never moves changes nothing.
struct Drag {
    origin_x: Option<f32>,
    origin_width: f32,
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
    /// How long a revealed field stays revealed, `0` for as long as it likes.
    reveal_seconds: u32,
    /// Bumped on every reveal, so a hide scheduled for an earlier one does not
    /// take away a field the user has only just opened.
    reveal_generation: u64,
    /// The width the user dragged the list to. Kept as their intent even while
    /// a narrow window forces a smaller one, so it returns when the room does.
    list_width: f32,
    /// How much room the shell says the two columns have between them.
    content_width: f32,
    drag: Option<Drag>,
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
    /// A revealed field's time is up, for the reveal that was current when the
    /// clock started.
    HideRevealed(u64),
    CloseDetail,
    Tick,
    ResizeStart,
    ResizeMove(f32),
    ResizeEnd,
}

pub enum Outcome {
    None,
    Task(Task<Message>),
    /// The clipboard belongs to the shell.
    Copy(String),
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
            error: sync_error.map(|err| t_args("items.syncFailed", &[("error", &err)])),
            reveal_seconds: 0,
            reveal_generation: 0,
            list_width: layout::LIST_DEFAULT,
            // Enough for the default split until the shell reports the window.
            content_width: layout::LIST_DEFAULT + layout::HANDLE + layout::DETAIL_MIN,
            drag: None,
        };
        state.apply_page(page, true);
        state.rebuild_nav();
        state
    }

    pub fn nav_model(&self) -> &nav_bar::Model {
        &self.nav
    }

    /// The shell owns the window, so it is the one that knows how much of it
    /// the nav bar left for these two columns.
    pub fn set_content_width(&mut self, width: f32) {
        self.content_width = width;
    }

    /// The shell owns the settings, so it is the one that says how long a
    /// revealed field may stay that way.
    pub fn set_reveal_seconds(&mut self, seconds: u32) {
        self.reveal_seconds = seconds;
        if seconds == 0 {
            // Nothing left to hide; let any timer already out there go stale.
            self.reveal_generation += 1;
        }
    }

    /// Where the splitter currently sits, held to what the window allows.
    pub fn list_width(&self) -> f32 {
        self.clamped_list_width(self.list_width)
    }

    /// The stored width, held to what the window can actually give it. A window
    /// too narrow for both minimums keeps the list at its own minimum and lets
    /// the detail take the squeeze, which is the order the desktop app uses.
    fn clamped_list_width(&self, width: f32) -> f32 {
        let room = self.content_width - layout::HANDLE - layout::DETAIL_MIN;
        width.min(room.min(layout::LIST_MAX)).max(layout::LIST_MIN)
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

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subscriptions = Vec::with_capacity(2);

        // One-time codes roll over every period, so a shown one needs a redraw
        // every second.
        if self.detail.as_ref().is_some_and(Detail::has_totp) {
            subscriptions
                .push(cosmic::iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick));
        }

        // A splitter has to keep following the pointer after it leaves the few
        // pixels it was pressed on, so the drag is tracked window-wide and only
        // while it lasts.
        if self.drag.is_some() {
            subscriptions.push(event::listen_with(|event, _, _| match event {
                Event::Mouse(mouse::Event::CursorMoved { position }) => {
                    Some(Message::ResizeMove(position.x))
                }
                Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)) => {
                    Some(Message::ResizeEnd)
                }
                _ => None,
            }));
        }

        Subscription::batch(subscriptions)
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

            Message::Loaded(Ok(detail)) => self.detail = Some(detail),

            Message::Loaded(Err(err)) => self.error = Some(err),

            Message::Detail(detail::Message::Copy(value)) => return Outcome::Copy(value),

            Message::Detail(detail::Message::ToggleReveal(index)) => {
                let Some(detail) = self.detail.as_mut() else {
                    return Outcome::None;
                };
                detail.update(detail::Message::ToggleReveal(index));

                let revealed = detail.fields.get(index).is_some_and(|field| field.revealed);
                if !revealed || self.reveal_seconds == 0 {
                    return Outcome::None;
                }
                self.reveal_generation += 1;
                let generation = self.reveal_generation;
                let seconds = u64::from(self.reveal_seconds);
                return Outcome::Task(cosmic::task::future(async move {
                    tokio::time::sleep(Duration::from_secs(seconds)).await;
                    Message::HideRevealed(generation)
                }));
            }

            Message::HideRevealed(generation) => {
                // A later reveal has already replaced the one this was for.
                if generation != self.reveal_generation {
                    return Outcome::None;
                }
                if let Some(detail) = self.detail.as_mut() {
                    for field in &mut detail.fields {
                        field.revealed = false;
                    }
                }
            }

            Message::CloseDetail => self.detail = None,

            Message::Tick => {}

            Message::ResizeStart => {
                self.drag = Some(Drag {
                    origin_x: None,
                    origin_width: self.list_width,
                });
            }

            Message::ResizeMove(x) => {
                let Some(drag) = self.drag.as_mut() else {
                    return Outcome::None;
                };
                let origin_x = *drag.origin_x.get_or_insert(x);
                let desired = drag.origin_width + (x - origin_x);
                self.list_width = self.clamped_list_width(desired);
            }

            Message::ResizeEnd => self.drag = None,
        }
        Outcome::None
    }

    pub fn view(&self) -> Element<'_, Message> {
        widget::row::with_capacity(3)
            .push(widget::container(self.list_view()).width(Length::Fixed(self.list_width())))
            .push(self.handle_view())
            .push(widget::container(self.detail_view()).width(Length::Fill))
            .height(Length::Fill)
            .into()
    }

    /// The splitter. It is wider than the line it draws so there is something
    /// to grab; the pointer says so before the press does.
    fn handle_view(&self) -> Element<'_, Message> {
        widget::divider::vertical::default()
            .apply(widget::container)
            .width(Length::Fixed(layout::HANDLE))
            .height(Length::Fill)
            .align_x(Alignment::Center)
            .apply(widget::mouse_area)
            .interaction(mouse::Interaction::ResizingHorizontally)
            .on_press(Message::ResizeStart)
            .into()
    }

    /// The column stays in place with nothing selected, the way the desktop
    /// app's details panel does, so selecting an item does not reflow the list.
    fn detail_view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();

        let Some(detail) = self.detail.as_ref() else {
            return super::centered(widget::text::body(t("items.detailsHint")));
        };

        let header = widget::row::with_capacity(2)
            .push(widget::text::title4(detail.title.clone()).width(Length::Fill))
            .push(
                widget::button::icon(widget::icon::from_name("window-close-symbolic"))
                    .on_press(Message::CloseDetail),
            )
            .spacing(spacing.space_xs)
            .align_y(Alignment::Center);

        widget::column::with_capacity(2)
            .push(header)
            .push(widget::scrollable(detail.view().map(Message::Detail)).height(Length::Fill))
            .spacing(spacing.space_s)
            .padding(spacing.space_s)
            .into()
    }

    fn list_view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let visible = self.visible();

        // Only the search: locking is an action on the app, not on this list,
        // and lives in the header bar's menu with the rest of them.
        let toolbar = widget::text_input::search_input(t("items.searchPlaceholder"), &self.query)
            .on_input(Message::QueryInput)
            .on_clear(Message::ClearQuery)
            .width(Length::Fill);

        let list: Element<'_, Message> = if visible.is_empty() {
            widget::text::body(t("items.noItems"))
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
            .push(widget::text::caption(t_args(
                "items.loadedCount",
                &[
                    ("loaded", &self.items.len().to_string()),
                    ("total", &self.total.to_string()),
                    ("shown", &visible.len().to_string()),
                ],
            )))
            .spacing(spacing.space_xs)
            .align_y(Alignment::Center);

        if self.next_cursor.is_some() {
            let mut more = widget::button::text(t("items.loadMore"));
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
            // The label key is a catalogue key: `schemas/ui_categories.json` names
            // the same strings the clients translate.
            let label = format!("{} ({})", t(&view.label_key), view.count);
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
