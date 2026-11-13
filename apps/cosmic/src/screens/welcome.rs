//! First run: connect to a server before unlocking its offline replica.
//!
//! Stateless, so it has no `State` and no `update` — the shell acts on the
//! message directly.

use cosmic::iced::Length;
use cosmic::{theme, widget, Element};

use super::centered;
use crate::i18n::t;

#[derive(Clone, Debug)]
pub enum Message {
    ConnectToServer,
}

pub fn view<'a>() -> Element<'a, Message> {
    let spacing = theme::spacing();
    centered(
        widget::column::with_capacity(4)
            .push(widget::text::title3(t("wizard.title")))
            .push(widget::text::body(t("wizard.subtitle")))
            .push(
                widget::button::suggested(t("wizard.connect"))
                    .width(Length::Fill)
                    .on_press(Message::ConnectToServer),
            )
            .spacing(spacing.space_s)
            .width(Length::Fixed(360.0)),
    )
}
