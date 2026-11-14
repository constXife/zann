//! The open vault: nav categories, the item list, and the detail column.
//!
//! The nav bar is the shell's (libcosmic draws it from [`State::nav_model`]);
//! the two columns in here mirror the desktop app's list/detail split, down to
//! the widths in [`layout`].

use std::time::{Duration, Instant};

use cosmic::iced::{event, keyboard, mouse, Alignment, Event, Length, Subscription, Task};
use cosmic::prelude::*;
use cosmic::widget::nav_bar;
use cosmic::{theme, widget, Element};
use zann_client::app::local::AutoSyncTicket;
use zann_client::app::local::{ItemSummary, VaultSummary};
use zann_ui_core::{
    category_views, create_type_for, filtered_indices, FolderFilter, ItemCounts, ItemFilter,
    VaultScope,
};

use super::detail::{self, Detail};
use super::editor::{self, SaveRequest};
use super::history;
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
        "card" => "credit-card-symbolic",
        "person" => "contact-new-symbolic",
        "network" => "network-server-symbolic",
        "server" => "computer-symbolic",
        "list" => "view-list-symbolic",
        "trash" => "user-trash-symbolic",
        _ => "folder-symbolic",
    }
}

/// Native list/detail geometry implementing docs/ux/Layout-Responsive-Spec.md.
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
    vaults: Vec<VaultSummary>,
    selected_vault_id: Option<String>,
    items: Vec<ItemSummary>,
    counts: ItemCounts,
    next_cursor: Option<String>,
    total: u64,
    query: String,
    search_id: cosmic::iced::widget::Id,
    /// The query that produced `items`. While a newer query is waiting for the
    /// backend, the old page is narrowed locally for responsive typing.
    applied_query: String,
    list_generation: u64,
    searching: bool,
    nav: nav_bar::Model,
    detail: Option<Detail>,
    selection: selection::Selection,
    editor: Option<editor::State>,
    history: Option<history::State>,
    editing_generation: u64,
    busy: bool,
    switching_context: bool,
    /// Only a failed list read can replace the list's empty-state actions.
    list_error: Option<String>,
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
    /// Only the latest armed auto-sync timer counts.
    sync_timer: u64,
    sync: sync_status::SyncView,
    workspace: context::Workspace,
}

#[derive(Clone, Debug)]
pub enum Message {
    VaultsLoaded {
        request: u64,
        result: Result<local::VaultContext, String>,
    },
    SelectVault(usize),
    SelectStorage(usize),
    ContextSwitched {
        request: u64,
        change: local::ContextChange,
    },
    QueryInput(String),
    ClearQuery,
    EscapeClearQuery,
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
    Loaded {
        request: u64,
        result: Result<Detail, String>,
    },
    DetailLoading(u64),
    Detail(detail::Message),
    OpenCreate,
    OpenEdit,
    Editor(editor::Message),
    OpenHistory,
    History(history::Message),
    HistoryResponse(u64, history::Message),
    Saved(u64, Result<Detail, String>),
    RefreshedAfterSave(u64, u64, Result<ItemsPage, String>),
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
    /// The auto-sync timer armed with this ID fired.
    SyncDue(u64),
    /// Network completion for an explicit source storage and list revision.
    AutoSynced {
        ticket: AutoSyncTicket,
        storage_id: String,
        list_generation: u64,
        result: Result<zann_client::app::local::LocalSyncOutcome, local::SyncFailure>,
    },
    /// Open the recovery for the server that changed its identity.
    ReviewStaleServer,
    /// Copy the error on screen, which the label itself cannot select.
    CopyError,
    /// The open storage's sync state, read again.
    SyncStateLoaded {
        storage_id: String,
        request: u64,
        result: Result<local::StorageSyncState, String>,
    },
    SyncedWorkspaceLoaded {
        storage_id: String,
        list_generation: u64,
        result: Result<(local::VaultContext, ItemsPage), String>,
    },
    SyncNow,
    CloseSyncDetails,
    RefreshSyncDetails,
    CopySyncError,
    /// Toggle details; starting a sync requires the explicit popover action.
    SyncIndicatorPressed,
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
    /// The storage's server changed its identity or its connection is gone;
    /// Settings offers the way out of that refusal.
    StaleServer(String, local::SyncFailure),
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
            search_id: cosmic::iced::widget::Id::unique(),
            applied_query: String::new(),
            list_generation: 0,
            searching: false,
            nav: nav_bar::Model::default(),
            detail: None,
            selection: selection::Selection::default(),
            editor: None,
            history: None,
            editing_generation: 0,
            busy: false,
            switching_context: false,
            list_error: None,
            error: None,
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
            sync_timer: 0,
            sync: sync_status::SyncView::new(sync_error),
            workspace: context::Workspace::new(),
        };
        state.apply_page(page, true);
        state.rebuild_nav();
        state
    }

    pub fn nav_model(&self) -> &nav_bar::Model {
        &self.nav
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

    pub fn hide_editor_revealed(&mut self) {
        if let Some(editor) = self.editor.as_mut() {
            editor.hide_revealed();
        }
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
        self.clear_selection();
        self.editor = None;
        self.history = None;
        self.editing_generation = crate::backend::next_view_request();
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
        filtered_indices(
            &self.items.iter().map(ItemSummaryView).collect::<Vec<_>>(),
            &self.filter(),
        )
        .into_iter()
        .map(|index| &self.items[index])
        .collect()
    }

    pub fn editing_request_id(&self) -> u64 {
        self.editing_generation
    }

    pub fn history(&self) -> Option<&history::State> {
        self.history.as_ref()
    }

    pub fn detail(&self) -> Option<&Detail> {
        self.detail.as_ref()
    }

    pub fn activate_nav(&mut self, id: nav_bar::Id) {
        if self.editor.is_some() || self.history.is_some() || self.switching_context {
            return;
        }
        self.sync.showing_details = false;
        self.nav.activate(id);
        self.reconcile_selection();
    }

    pub fn category_needs_prefetch(&self) -> bool {
        self.visible().len() < MIN_VISIBLE_ROWS && self.can_load_more()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subscriptions = Vec::with_capacity(4);
        if self.auto_lock_minutes > 0 {
            subscriptions.push(cosmic::iced::time::every(IDLE_TICK).map(|_| Message::IdleCheck));
        }

        // One-time codes roll over every period, so a shown one redraws each
        // second while the detail column is populated.
        if self.detail.as_ref().is_some_and(Detail::has_totp)
            || self.history.as_ref().is_some_and(history::State::has_totp)
        {
            subscriptions
                .push(cosmic::iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick));
        }

        let details_open = self.sync.showing_details;
        if details_open
            || (!self.query.is_empty() && self.editor.is_none() && self.history.is_none())
        {
            subscriptions.push(event::listen_with(|event, _, _| match event {
                Event::Keyboard(keyboard::Event::KeyPressed {
                    key: keyboard::Key::Named(keyboard::key::Named::Escape),
                    ..
                }) => Some(Message::EscapeClearQuery),
                _ => None,
            }));
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
            Message::VaultsLoaded { .. }
                | Message::SearchReady(_)
                | Message::SearchLoaded { .. }
                | Message::MoreLoaded { .. }
                | Message::RefreshedAfterSave(..)
                | Message::HistoryResponse(..)
                | Message::History(
                    history::Message::EntriesLoaded(_)
                        | history::Message::VersionLoaded { .. }
                        | history::Message::Restored(_),
                )
                | Message::ListScrolled { .. }
                | Message::IdleCheck
                | Message::KeyPresent(_)
                | Message::Tick
                | Message::ClearCopied(_)
                | Message::HideRevealed(_)
                | Message::SyncDue(_)
                | Message::AutoSynced { .. }
                | Message::SyncStateLoaded { .. }
                | Message::ContextSwitched { .. }
                | Message::SyncedWorkspaceLoaded { .. }
                | Message::Loaded { .. }
                | Message::DetailLoading(_)
        ) {
            self.last_activity = Instant::now();
        }

        if matches!(message, Message::Detail(_)) && !self.detail_ready() {
            return Outcome::None;
        }
        match message {
            message @ (Message::VaultsLoaded { .. }
            | Message::SelectVault(_)
            | Message::SelectStorage(_)
            | Message::ContextSwitched { .. }) => {
                return self.update_context(message, session);
            }

            message @ (Message::QueryInput(_)
            | Message::ClearQuery
            | Message::EscapeClearQuery
            | Message::ListScrolled { .. }
            | Message::SearchReady(_)
            | Message::SearchLoaded { .. }
            | Message::LoadMore
            | Message::MoreLoaded { .. }) => return self.update_search(message, session),

            Message::Select(id) => {
                if !self.switching_context
                    && self.editor.is_none()
                    && self.history.is_none()
                    && self.visible().iter().any(|item| item.id == id)
                {
                    return Outcome::Task(self.load_detail(id, session));
                }
            }
            Message::Loaded { request, result } => self.complete_detail(request, result),
            Message::DetailLoading(request) => {
                if request == self.selection.request && self.selection.loading() {
                    self.selection.show_loading = true;
                }
            }

            message @ (Message::OpenCreate
            | Message::OpenEdit
            | Message::OpenHistory
            | Message::Editor(_)
            | Message::History(_)
            | Message::HistoryResponse(..)
            | Message::Saved(..)
            | Message::RefreshedAfterSave(..)) => {
                return self.update_editing(message, session);
            }

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
                if let Some(history) = self.history.as_mut() {
                    history.hide_revealed();
                }
                self.hide_editor_revealed();
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

            Message::CopyError => {
                if let Some(error) = self.displayed_error().cloned() {
                    return Outcome::Copy {
                        value: error,
                        feedback: Task::none(),
                    };
                }
            }

            message @ (Message::SyncDue(_)
            | Message::AutoSynced { .. }
            | Message::SyncedWorkspaceLoaded { .. }) => {
                return self.update_auto_sync(message, session)
            }

            message @ (Message::SyncStateLoaded { .. }
            | Message::SyncIndicatorPressed
            | Message::SyncNow
            | Message::CloseSyncDetails
            | Message::RefreshSyncDetails
            | Message::CopySyncError
            | Message::ReviewStaleServer) => return self.update_sync_status(message, session),
        }
        Outcome::None
    }

    fn apply_page(&mut self, page: ItemsPage, replace: bool) {
        self.list_error = None;
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
        for view in self
            .vault_scope()
            .map(|scope| category_views(&self.counts, scope))
            .unwrap_or_default()
        {
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
        self.vault_scope()
            .map(|scope| category_views(&self.counts, scope))
            .unwrap_or_default()
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

    fn vault_scope(&self) -> Option<VaultScope> {
        self.selected_vault_id
            .as_deref()
            .and_then(|id| self.vaults.iter().find(|vault| vault.id == id))
            .map(|vault| {
                if vault.kind == zann_core::VaultKind::Shared {
                    VaultScope::Shared
                } else {
                    VaultScope::Personal
                }
            })
    }

    fn preferred_create_type(&self) -> &'static str {
        create_type_for(self.selected_category().as_deref())
    }
}

mod view;
use view::vault_label;
pub use view::ListEmptyState;

struct ItemSummaryView<'a>(&'a ItemSummary);
impl zann_ui_core::ItemLike for ItemSummaryView<'_> {
    fn title(&self) -> &str {
        &self.0.title
    }
    fn type_id(&self) -> &str {
        &self.0.type_id
    }
    fn path(&self) -> &str {
        &self.0.path
    }
    fn is_deleted(&self) -> bool {
        self.0.deleted
    }
}

mod auto_sync;
mod editing;
mod sync_status;

mod search;
mod selection;

mod context;
