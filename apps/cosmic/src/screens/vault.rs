//! The open vault: nav categories, the item list, and the detail column.
//!
//! The nav bar is the shell's (libcosmic draws it from [`State::nav_model`]);
//! the two columns in here mirror the desktop app's list/detail split, down to
//! the widths in [`layout`].

use std::time::{Duration, Instant};

use cosmic::iced::{event, mouse, Alignment, Event, Length, Subscription, Task};
use cosmic::prelude::*;
use cosmic::widget::nav_bar;
use cosmic::{theme, widget, Element};
use zann_ffi::{ItemSummary, VaultSummaryFfi};
use zann_ui_core::{
    category_views, filtered_indices, FolderFilter, ItemCounts, ItemFilter, VaultScope,
};

use super::detail::{self, Detail};
use crate::backend::local::{self, ItemsPage};
use crate::backend::off_thread;
use crate::i18n::{has, t, t_args};
use crate::session::Session;

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

/// Keep the list/detail split aligned with
/// `apps/desktop/src/composables/app/state/useAppLayout.ts`.
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
        "card" => "credit-card-symbolic",
        "identity" => "contact-new-symbolic",
        "api" => "network-server-symbolic",
        _ => "view-list-symbolic",
    }
}

/// How often that is checked. Coarse on purpose: the timeout is minutes, and
/// each check can cost a query to the authenticator.
const IDLE_TICK: Duration = Duration::from_secs(30);
const SEARCH_DEBOUNCE: Duration = Duration::from_millis(180);
const COPY_FEEDBACK: Duration = Duration::from_millis(480);
/// Item summaries are small, but the rendered widget tree is not. Five
/// backend pages keep scrolling smooth while placing a hard upper bound on
/// both. Global search remains able to query the entire vault past this cap.
const ITEM_CACHE_LIMIT: usize = local::PAGE_LIMIT as usize * 5;
const PREFETCH_VIEWPORTS: f32 = 1.25;
const MIN_VISIBLE_ROWS: usize = 24;

/// A held splitter. The press event has no pointer position, so the first move
/// records the origin and following moves resize relative to it.
struct Drag {
    origin_x: Option<f32>,
    origin_width: f32,
}

pub struct State {
    vaults: Vec<VaultSummaryFfi>,
    selected_vault_id: Option<String>,
    items: Vec<ItemSummary>,
    counts: ItemCounts,
    next_cursor: Option<String>,
    total: u64,
    query: String,
    /// The query that produced `items`. While a newer query is waiting for the
    /// backend, the old page is narrowed locally for responsive typing.
    applied_query: String,
    list_generation: u64,
    searching: bool,
    nav: nav_bar::Model,
    detail: Option<Detail>,
    busy: bool,
    error: Option<String>,
    last_activity: Instant,
    /// `0` disables idle locking. The shell keeps this aligned with the shared
    /// device preferences.
    auto_lock_minutes: u32,
    reveal_seconds: u32,
    reveal_generation: u64,
    copy_generation: u64,
    /// True only while the platform reveal modifier is physically held.
    /// Unlike the eye button this is never persisted and is cleared on focus loss.
    temporary_reveal: bool,
    /// The user's preferred list width. A narrow window may clamp the rendered
    /// width temporarily without throwing this preference away.
    list_width: f32,
    /// Space left after libcosmic's navigation column.
    content_width: f32,
    drag: Option<Drag>,
}

#[derive(Clone, Debug)]
pub enum Message {
    VaultsLoaded(Result<local::VaultContext, String>),
    SelectVault(usize),
    VaultSwitched {
        vault_id: String,
        result: Result<ItemsPage, String>,
    },
    QueryInput(String),
    ClearQuery,
    ListScrolled {
        remaining: f32,
        viewport_height: f32,
    },
    SearchReady(u64),
    SearchLoaded {
        generation: u64,
        query: String,
        result: Result<ItemsPage, String>,
    },
    LoadMore,
    MoreLoaded {
        generation: u64,
        result: Result<ItemsPage, String>,
    },
    Select(String),
    Loaded(Result<Detail, String>),
    Detail(detail::Message),
    ClearCopied(u64),
    HideRevealed(u64),
    /// The idle timer expired; whether that locks depends on the answer below.
    IdleCheck,
    /// Whether an enrolled authenticator is still plugged in.
    KeyPresent(bool),
    Tick,
    ResizeStart,
    ResizeMove(f32),
    ResizeEnd,
}

pub enum Outcome {
    None,
    Task(Task<Message>),
    /// The clipboard belongs to the shell.
    Copy {
        value: String,
        feedback: Task<Message>,
    },
    Locked,
}

impl State {
    pub fn new(page: ItemsPage, sync_error: Option<String>) -> Self {
        let mut state = Self {
            vaults: Vec::new(),
            selected_vault_id: None,
            items: Vec::new(),
            counts: ItemCounts::default(),
            next_cursor: None,
            total: 0,
            query: String::new(),
            applied_query: String::new(),
            list_generation: 0,
            searching: false,
            nav: nav_bar::Model::default(),
            detail: None,
            busy: false,
            error: sync_error.map(|err| t_args("items.syncFailed", &[("error", &err)])),
            last_activity: Instant::now(),
            auto_lock_minutes: 10,
            reveal_seconds: 20,
            reveal_generation: 0,
            copy_generation: 0,
            temporary_reveal: false,
            list_width: layout::LIST_DEFAULT,
            // Enough for the default split until the shell reports its width.
            content_width: layout::LIST_DEFAULT + layout::HANDLE + layout::DETAIL_MIN,
            drag: None,
        };
        state.apply_page(page, true);
        state.rebuild_nav();
        state
    }

    pub fn load_vaults(session: &Session) -> Task<Message> {
        let facade = session.facade();
        cosmic::task::future(async move {
            Message::VaultsLoaded(off_thread(move || local::vault_context(&facade)).await)
        })
    }

    pub fn nav_model(&self) -> &nav_bar::Model {
        &self.nav
    }

    /// Storage/vault context belongs to the navigation column, above the
    /// category tree. The shell embeds this in its custom libcosmic nav bar.
    pub fn vault_selector(&self) -> Option<Element<'_, Message>> {
        if self.vaults.len() <= 1 {
            return None;
        }
        let spacing = theme::spacing();
        let labels: Vec<String> = self.vaults.iter().map(vault_label).collect();
        let selected = self
            .selected_vault_id
            .as_deref()
            .and_then(|id| self.vaults.iter().position(|vault| vault.id == id));
        Some(
            widget::column::with_capacity(2)
                .push(widget::text::caption(t("nav.vaults")))
                .push(widget::dropdown(labels, selected, Message::SelectVault))
                .spacing(spacing.space_xxs)
                .padding(spacing.space_s)
                .width(Length::Fill)
                .into(),
        )
    }

    /// The shell owns the window and knows how much room its navigation column
    /// leaves for the list and detail columns.
    pub fn set_content_width(&mut self, width: f32) {
        self.content_width = width;
    }

    pub fn set_auto_lock_minutes(&mut self, minutes: u32) {
        self.auto_lock_minutes = minutes;
        self.last_activity = Instant::now();
    }

    pub fn set_reveal_seconds(&mut self, seconds: u32) {
        self.reveal_seconds = seconds;
        if seconds == 0 {
            self.reveal_generation += 1;
        }
    }

    pub fn set_temporary_reveal(&mut self, held: bool) {
        self.temporary_reveal = held;
    }

    pub fn record_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn refresh_translations(&mut self) {
        self.rebuild_nav();
    }

    /// Replace the visible projection after a settings workflow changed the
    /// underlying vault (for example an import).
    pub fn replace_page(&mut self, page: ItemsPage) {
        self.list_generation = self.list_generation.wrapping_add(1);
        self.searching = false;
        self.query.clear();
        self.applied_query.clear();
        self.detail = None;
        self.apply_page(page, true);
        self.rebuild_nav();
    }

    pub fn list_width(&self) -> f32 {
        self.clamped_list_width(self.list_width)
    }

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

    pub fn category_needs_prefetch(&self) -> bool {
        self.visible().len() < MIN_VISIBLE_ROWS && self.can_load_more()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subscriptions = Vec::with_capacity(3);
        if self.auto_lock_minutes > 0 {
            subscriptions.push(cosmic::iced::time::every(IDLE_TICK).map(|_| Message::IdleCheck));
        }

        // One-time codes roll over every period, so a shown one redraws each
        // second while the detail column is populated.
        if self.detail.as_ref().is_some_and(Detail::has_totp) {
            subscriptions
                .push(cosmic::iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick));
        }

        // Keep tracking after the pointer leaves the five-pixel handle.
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
        // Anything the user did counts as activity; the timer's own messages do
        // not, or the vault would never idle out.
        if !matches!(
            message,
            Message::VaultsLoaded(_)
                | Message::SearchReady(_)
                | Message::SearchLoaded { .. }
                | Message::MoreLoaded { .. }
                | Message::ListScrolled { .. }
                | Message::IdleCheck
                | Message::KeyPresent(_)
                | Message::Tick
                | Message::ClearCopied(_)
                | Message::HideRevealed(_)
        ) {
            self.last_activity = Instant::now();
        }

        match message {
            Message::VaultsLoaded(Ok(context)) => {
                self.vaults = context.vaults;
                self.selected_vault_id = context.current_vault_id;
                self.rebuild_nav();
            }

            Message::VaultsLoaded(Err(err)) => self.error = Some(err),

            Message::SelectVault(index) => {
                if self.busy || self.searching {
                    return Outcome::None;
                }
                let Some(vault) = self.vaults.get(index) else {
                    return Outcome::None;
                };
                if self.selected_vault_id.as_deref() == Some(vault.id.as_str()) {
                    return Outcome::None;
                }
                let vault_id = vault.id.clone();
                let worker_id = vault_id.clone();
                let facade = session.facade();
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::VaultSwitched {
                        vault_id,
                        result: off_thread(move || local::switch_vault(&facade, worker_id)).await,
                    }
                }));
            }

            Message::VaultSwitched { vault_id, result } => {
                self.busy = false;
                match result {
                    Ok(page) => {
                        self.selected_vault_id = Some(vault_id);
                        self.replace_page(page);
                    }
                    Err(err) => self.error = Some(err),
                }
            }

            Message::QueryInput(value) => return self.schedule_search(value),

            Message::ClearQuery => return self.schedule_search(String::new()),

            Message::ListScrolled {
                remaining,
                viewport_height,
            } => {
                if remaining <= viewport_height * PREFETCH_VIEWPORTS {
                    return self.load_more(session);
                }
            }

            Message::SearchReady(generation) => {
                if generation != self.list_generation {
                    return Outcome::None;
                }
                let query = self.query.trim().to_string();
                let backend_query = (!query.is_empty()).then(|| query.clone());
                let facade = session.facade();
                return Outcome::Task(cosmic::task::future(async move {
                    Message::SearchLoaded {
                        generation,
                        query,
                        result: off_thread(move || local::items(&facade, None, backend_query))
                            .await,
                    }
                }));
            }

            Message::SearchLoaded {
                generation,
                query,
                result,
            } => {
                if generation != self.list_generation {
                    return Outcome::None;
                }
                self.searching = false;
                match result {
                    Ok(page) => {
                        if self.detail.as_ref().is_some_and(|detail| {
                            !page.items.iter().any(|item| item.id == detail.id)
                        }) {
                            self.detail = None;
                        }
                        self.applied_query = query;
                        self.apply_page(page, true);
                        self.rebuild_nav();
                        if self.category_needs_prefetch() {
                            return self.load_more(session);
                        }
                    }
                    Err(err) => self.error = Some(err),
                }
            }

            Message::LoadMore => {
                return self.load_more(session);
            }

            Message::MoreLoaded { generation, result } => {
                if generation != self.list_generation {
                    return Outcome::None;
                }
                self.busy = false;
                match result {
                    Ok(page) => {
                        self.apply_page(page, false);
                        self.rebuild_nav();
                        if self.category_needs_prefetch() {
                            return self.load_more(session);
                        }
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

            Message::Detail(detail::Message::Copy { index, value }) => {
                if let Some(detail) = self.detail.as_mut() {
                    detail.update(detail::Message::Copy {
                        index,
                        value: value.clone(),
                    });
                }
                self.copy_generation = self.copy_generation.wrapping_add(1);
                let generation = self.copy_generation;
                return Outcome::Copy {
                    value,
                    feedback: cosmic::task::future(async move {
                        tokio::time::sleep(COPY_FEEDBACK).await;
                        Message::ClearCopied(generation)
                    }),
                };
            }

            Message::ClearCopied(generation) => {
                if generation != self.copy_generation {
                    return Outcome::None;
                }
                if let Some(detail) = self.detail.as_mut() {
                    detail.clear_copy_feedback();
                }
            }

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
                if generation != self.reveal_generation {
                    return Outcome::None;
                }
                if let Some(detail) = self.detail.as_mut() {
                    for field in &mut detail.fields {
                        field.revealed = false;
                    }
                }
            }

            Message::IdleCheck => {
                if self.auto_lock_minutes == 0
                    || self.last_activity.elapsed()
                        < Duration::from_secs(u64::from(self.auto_lock_minutes) * 60)
                {
                    return Outcome::None;
                }
                // An inserted key counts as presence: locking every ten minutes
                // while it sits in the port only teaches people to turn the
                // timeout off. Pulling the key is what locks.
                let facade = session.facade();
                return Outcome::Task(cosmic::task::future(async move {
                    let present = off_thread(move || {
                        let remembered = local::remembered_unlock(&facade)?;
                        if remembered.source != "hardware_key" {
                            return Ok(false);
                        }
                        local::hardware_key_present(&facade)
                    })
                    .await;
                    Message::KeyPresent(present.unwrap_or(false))
                }));
            }

            Message::KeyPresent(true) => self.last_activity = Instant::now(),

            Message::KeyPresent(false) => {
                session.lock();
                return Outcome::Locked;
            }

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

    /// The detail column remains present with no selection so choosing an item
    /// never changes the list's geometry, matching the Tauri shell.
    fn detail_view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let search = widget::text_input::search_input(t("items.searchPlaceholder"), &self.query)
            .on_input(Message::QueryInput)
            .on_clear(Message::ClearQuery)
            .width(Length::Fill);

        let body: Element<'_, Message> = match self.detail.as_ref() {
            Some(detail) => widget::column::with_capacity(2)
                .push(widget::text::title4(detail.title.clone()))
                .push(
                    widget::scrollable(detail.view(self.temporary_reveal).map(Message::Detail))
                        .height(Length::Fill),
                )
                .spacing(spacing.space_s)
                .padding(spacing.space_s)
                .into(),
            None => super::centered(widget::text::body(t("items.detailsHint"))),
        };

        widget::column::with_capacity(2)
            .push(widget::container(search).padding(spacing.space_s))
            .push(body)
            .height(Length::Fill)
            .into()
    }

    fn list_view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let visible = self.visible();

        let toolbar = widget::column::with_capacity(2)
            .push(widget::text::title4(self.selected_category_label()))
            .spacing(spacing.space_xs)
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

        let list_status = if self.searching || self.busy {
            t("common.loading")
        } else if self.items.len() >= ITEM_CACHE_LIMIT && self.next_cursor.is_some() {
            t_args(
                "items.memoryWindow",
                &[
                    ("loaded", &self.items.len().to_string()),
                    ("total", &self.total.to_string()),
                ],
            )
        } else {
            t_args(
                "items.loadedCount",
                &[
                    ("loaded", &self.items.len().to_string()),
                    ("total", &self.total.to_string()),
                    ("shown", &visible.len().to_string()),
                ],
            )
        };
        let footer = widget::row::with_capacity(1)
            .push(widget::text::caption(list_status))
            .spacing(spacing.space_xs)
            .align_y(Alignment::Center);

        let mut content = widget::column::with_capacity(4).push(toolbar).push(
            widget::scrollable(list)
                .height(Length::Fill)
                .on_scroll(|viewport| {
                    let offset = viewport.absolute_offset().y;
                    let bounds = viewport.bounds();
                    let content = viewport.content_bounds();
                    Message::ListScrolled {
                        remaining: (content.height - offset - bounds.height).max(0.0),
                        viewport_height: bounds.height,
                    }
                }),
        );

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
            let available = ITEM_CACHE_LIMIT.saturating_sub(self.items.len());
            self.items.extend(page.items.into_iter().take(available));
        }
        self.counts = page.counts;
        self.next_cursor = page.next_cursor;
        self.total = page.total;
    }

    /// Rebuilds the nav entries from the shared schema, keeping the selection.
    fn rebuild_nav(&mut self) {
        let selected = self.selected_category();
        self.nav.clear();
        for view in category_views(&self.counts, self.vault_scope()) {
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

    fn selected_category_label(&self) -> String {
        let selected = self.selected_category();
        category_views(&self.counts, self.vault_scope())
            .into_iter()
            .find(|view| selected.as_deref() == Some(view.id.as_str()))
            .map(|view| t(&view.label_key))
            .unwrap_or_else(|| t("nav.allItems"))
    }

    fn filter(&self) -> ItemFilter {
        ItemFilter {
            category_id: self.selected_category(),
            folder: FolderFilter::Any,
            query: if self.query.trim() == self.applied_query {
                String::new()
            } else {
                self.query.clone()
            },
        }
    }

    fn schedule_search(&mut self, value: String) -> Outcome {
        if self.busy || value == self.query {
            return Outcome::None;
        }
        self.query = value;
        self.list_generation = self.list_generation.wrapping_add(1);
        let generation = self.list_generation;
        self.searching = true;
        self.error = None;
        let delay = if self.query.trim().is_empty() {
            Duration::ZERO
        } else {
            SEARCH_DEBOUNCE
        };
        Outcome::Task(cosmic::task::future(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            Message::SearchReady(generation)
        }))
    }

    fn can_load_more(&self) -> bool {
        self.next_cursor.is_some()
            && !self.busy
            && !self.searching
            && self.items.len() < ITEM_CACHE_LIMIT
    }

    fn load_more(&mut self, session: &Session) -> Outcome {
        if !self.can_load_more() {
            return Outcome::None;
        }
        let Some(cursor) = self.next_cursor.clone() else {
            return Outcome::None;
        };
        let facade = session.facade();
        let generation = self.list_generation;
        let query = (!self.applied_query.is_empty()).then(|| self.applied_query.clone());
        self.busy = true;
        Outcome::Task(cosmic::task::future(async move {
            Message::MoreLoaded {
                generation,
                result: off_thread(move || local::items(&facade, Some(cursor), query)).await,
            }
        }))
    }

    fn vault_scope(&self) -> VaultScope {
        self.selected_vault_id
            .as_deref()
            .and_then(|id| self.vaults.iter().find(|vault| vault.id == id))
            .map_or(VaultScope::Personal, |vault| {
                if vault.kind == "shared" {
                    VaultScope::Shared
                } else {
                    VaultScope::Personal
                }
            })
    }
}

fn vault_label(vault: &VaultSummaryFfi) -> String {
    let kind = if vault.kind == "shared" {
        t("nav.shared")
    } else {
        t("nav.personal")
    };
    format!("{kind} · {} ({})", vault.name, vault.item_count)
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
        .push(widget::text::caption({
            let key = format!("types.{}", item.type_id);
            if has(&key) {
                t(&key)
            } else {
                item.type_id.clone()
            }
        }))
        .spacing(spacing.space_s)
        .align_y(Alignment::Center)
        .into()
}
