use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListEmptyState {
    Loading,
    NoSearchResults,
    EmptyCategory,
    Failed,
}

impl State {
    pub fn empty_state(&self) -> Option<ListEmptyState> {
        if !self.visible().is_empty() {
            None
        } else if self.searching || self.busy {
            Some(ListEmptyState::Loading)
        } else if self.list_error.is_some() {
            Some(ListEmptyState::Failed)
        } else if self.category_needs_prefetch() {
            Some(ListEmptyState::Loading)
        } else if !self.query.trim().is_empty() {
            Some(ListEmptyState::NoSearchResults)
        } else {
            Some(ListEmptyState::EmptyCategory)
        }
    }

    pub(super) fn displayed_error(&self) -> Option<&String> {
        self.list_error.as_ref().or(self.error.as_ref())
    }

    pub fn empty_create_action(&self) -> Option<zann_ui_core::categories::CategoryCreateAction> {
        let selected = self.selected_category()?;
        category_views(&self.counts, self.vault_scope()?)
            .into_iter()
            .find(|view| view.id == selected)?
            .create_action
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
    /// never changes the list's geometry.
    fn detail_view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let body: Element<'_, Message> = match (
            self.editor.as_ref(),
            self.history.as_ref(),
            self.detail.as_ref(),
        ) {
            (Some(editor), _, _) => widget::scrollable(editor.view().map(Message::Editor))
                .height(Length::Fill)
                .apply(widget::container)
                .padding(spacing.space_s)
                .into(),
            (None, Some(history), _) => history.view().map(Message::History),
            (None, None, Some(detail)) => {
                let header = widget::row::with_capacity(3)
                    .push(
                        widget::container(widget::text::title4(detail.title.clone()))
                            .width(Length::Fill),
                    )
                    .push(
                        widget::button::standard(t("items.historyOpen"))
                            .on_press_maybe(self.detail_ready().then_some(Message::OpenHistory)),
                    )
                    .push(
                        widget::button::standard(t("common.edit"))
                            .on_press_maybe(self.detail_ready().then_some(Message::OpenEdit)),
                    )
                    .spacing(spacing.space_s)
                    .align_y(Alignment::Center);
                widget::column::with_capacity(2)
                    .push(header)
                    .push(
                        widget::scrollable(
                            detail
                                .view_with_interactions(self.temporary_reveal, self.detail_ready())
                                .map(Message::Detail),
                        )
                        .height(Length::Fill),
                    )
                    .spacing(spacing.space_s)
                    .padding(spacing.space_s)
                    .into()
            }
            (None, None, None) => {
                let mut placeholder = widget::column::with_capacity(2).spacing(spacing.space_s);
                if let Some(error) = &self.selection.error {
                    placeholder = placeholder.push(widget::text::body(error.clone()));
                    if let Some(id) = self.selected_item_id() {
                        placeholder = placeholder.push(
                            widget::button::standard(t("common.retry"))
                                .on_press(Message::Select(id.to_owned())),
                        );
                    }
                } else if self.selection.loading() {
                    if self.selection.show_loading {
                        placeholder = placeholder.push(widget::text::body(t("common.loading")));
                    }
                } else {
                    placeholder = placeholder.push(widget::text::body(t("items.detailsHint")));
                }
                super::super::centered(placeholder)
            }
        };

        body
    }

    fn list_view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let visible = self.visible();
        let search = widget::text_input::search_input(t("items.searchPlaceholder"), &self.query)
            .id(self.search_id.clone())
            .on_input(Message::QueryInput)
            .on_clear(Message::ClearQuery)
            .width(Length::Fill);

        let mut create = widget::button::suggested(t("common.create"));
        if !self.busy && !self.searching && self.editor.is_none() && self.history.is_none() {
            create = create.on_press(Message::OpenCreate);
        }
        let toolbar = widget::row::with_capacity(2)
            .push(
                widget::container(widget::text::title4(self.selected_category_label()))
                    .width(Length::Fill),
            )
            .push(create)
            .spacing(spacing.space_s)
            .align_y(Alignment::Center)
            .width(Length::Fill);

        let list: Element<'_, Message> = if let Some(state) = self.empty_state() {
            let mut content = widget::column::with_capacity(2).spacing(spacing.space_s);
            match state {
                ListEmptyState::Loading => {
                    content = content
                        .push(widget::progress_bar::indeterminate_circular().size(24.0))
                        .push(widget::text::body(t("common.loading")))
                }
                ListEmptyState::NoSearchResults => {
                    content = content
                        .push(widget::text::body(t("items.noSearchResults")))
                        .push(
                            widget::button::standard(t("items.clearSearch"))
                                .on_press(Message::ClearQuery),
                        );
                }
                ListEmptyState::EmptyCategory => {
                    content = content.push(widget::text::body(t("workspace.emptyBody")));
                    if let Some(action) = self.empty_create_action() {
                        let button = widget::button::suggested(t(&action.label_key))
                            .on_press_maybe(
                                (!self.busy && self.editor.is_none() && self.history.is_none())
                                    .then_some(Message::OpenCreate),
                            );
                        content = content.push(button);
                    }
                }
                ListEmptyState::Failed => {} // The existing error row carries the failure.
            }
            widget::container(content)
                .width(Length::Fill)
                .padding(spacing.space_m)
                .into()
        } else {
            let selected = self.selected_item_id();
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

        let mut content = widget::column::with_capacity(5)
            .push(search)
            .push(toolbar)
            .push(
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

        if let Some(error) = self.displayed_error() {
            content = content.push(
                widget::row::with_capacity(2)
                    .push(widget::text::caption(error.clone()).width(Length::Fill))
                    .push(
                        widget::button::icon(widget::icon::from_name("edit-copy-symbolic"))
                            .tooltip(t("common.copy"))
                            .on_press(Message::CopyError),
                    )
                    .spacing(spacing.space_xs)
                    .align_y(Alignment::Center),
            );
            if self.list_error.is_none() && self.stale_server_banner().is_some() {
                content = content.push(
                    widget::button::standard(t("items.reviewStaleServer"))
                        .on_press(Message::ReviewStaleServer),
                );
            }
        }

        content
            .push(footer)
            .spacing(spacing.space_s)
            .padding(spacing.space_s)
            .into()
    }
}

pub(super) fn vault_label(vault: &VaultSummary) -> String {
    let kind = if vault.kind == zann_core::VaultKind::Shared {
        t("nav.shared")
    } else {
        t("nav.personal")
    };
    format!("{kind} · {} ({})", vault.name, vault.item_count)
}

fn item_row(item: &ItemSummary) -> Element<'_, Message> {
    let spacing = theme::spacing();
    // The title names the item; the caption says who or where it is for
    // and where it lives.
    let mut text = widget::column::with_capacity(2).push(widget::text::body(item.title.clone()));
    let subtitle = item.subtitle.as_ref().map(|subtitle| subtitle.as_str());
    if let Some(caption) = zann_ui_core::item_caption(subtitle, &item.path) {
        text = text.push(widget::text::caption(caption));
    }
    widget::row::with_capacity(2)
        .push(
            widget::icon::from_name(item_icon(&item.type_id))
                .size(20)
                .icon(),
        )
        .push(text.width(Length::Fill))
        .spacing(spacing.space_s)
        .align_y(Alignment::Center)
        .into()
}
