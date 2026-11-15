//! Native field controls keep the value on its own full-width row.
use super::*;

pub(super) fn field_row<'a>(
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
        .width(Length::Fill);
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

    let metadata = widget::row::with_capacity(3)
        .push(key)
        .push(
            widget::dropdown(kind_labels, selected_kind, move |kind| {
                Message::FieldKind(index, FIELD_KINDS[kind])
            })
            .width(Length::Fixed(130.0)),
        )
        .push(
            widget::button::icon(widget::icon::from_name("edit-delete-symbolic"))
                .on_press(Message::RemoveField(index)),
        )
        .spacing(spacing.space_xs)
        .align_y(Alignment::Center);
    let mut row = widget::row::with_capacity(2).push(value);
    if field.value.kind == FieldKind::Password {
        row = row.push(
            widget::button::icon(widget::icon::from_name("view-refresh-symbolic"))
                .tooltip(t("create.generateSecret"))
                .on_press(Message::OpenGenerator(index)),
        );
    }
    widget::column::with_capacity(2)
        .push(metadata)
        .push(row.spacing(spacing.space_xs).align_y(Alignment::Center))
        .spacing(spacing.space_xxs)
        .width(Length::Fill)
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic::iced::{
        advanced::{layout, renderer::Headless, widget::Tree},
        futures::executor::block_on,
        Font, Pixels, Renderer, Size,
    };

    fn layout(mut view: Element<'_, Message>, width: f32) -> layout::Node {
        let renderer = block_on(Renderer::new(
            Font::default(),
            Pixels(14.0),
            Some("tiny-skia"),
        ))
        .expect("headless renderer");
        let mut tree = Tree::new(view.as_widget());
        view.as_widget_mut().layout(
            &mut tree,
            &renderer,
            &layout::Limits::new(Size::ZERO, Size::new(width, 4000.0)),
        )
    }

    #[test]
    fn password_input_keeps_usable_width_in_the_narrow_detail_panel() {
        let editor = State::create("login").unwrap();
        let password = &editor.draft.fields[1];
        assert_eq!(password.value.kind, FieldKind::Password);
        // 1200-wide window, native sidebar + list + splitter + panel padding.
        for width in [380.0, 480.0, 560.0] {
            let node = layout(field_row(1, password, false, None), width);
            let value_row = &node.children()[1];
            let input = &value_row.children()[0];
            assert!(input.size().width >= 280.0, "input collapsed at {width}");
            assert!(input.size().height > 0.0);
        }
        assert!(!editor.revealed[1]);
    }

    #[test]
    fn editor_does_not_stretch_across_a_maximized_display() {
        let editor = State::create("login").unwrap();
        for width in [480.0, 1830.0, 2300.0] {
            let node = layout(editor.view(), width);
            assert!(node.size().width <= width.min(crate::screens::DETAIL_CONTENT_MAX));
        }
    }
}
