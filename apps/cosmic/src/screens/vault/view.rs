use super::*;

impl State {
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
            None => super::super::centered(widget::text::body(t("items.detailsHint"))),
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
}

pub(super) fn vault_label(vault: &VaultSummary) -> String {
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
