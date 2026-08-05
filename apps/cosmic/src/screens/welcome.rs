//! First run: keep the vault local, or connect it to a server.
//!
//! Stateless, so it has no `State` and no `update` — the shell acts on the
//! message directly.

use cosmic::iced::Length;
use cosmic::{theme, widget, Element};

use super::centered;

#[derive(Clone, Debug)]
pub enum Message {
    UseLocalVault,
    ConnectToServer,
}

pub fn view<'a>() -> Element<'a, Message> {
    let spacing = theme::spacing();
    centered(
        widget::column::with_capacity(4)
            .push(widget::text::title3("Welcome to zann"))
            .push(widget::text::body(
                "Keep the vault on this machine, or connect it to a server.",
            ))
            .push(
                widget::button::suggested("Connect to a server")
                    .width(Length::Fill)
                    .on_press(Message::ConnectToServer),
            )
            .push(
                widget::button::standard("Use a local vault")
                    .width(Length::Fill)
                    .on_press(Message::UseLocalVault),
            )
            .spacing(spacing.space_s)
            .width(Length::Fixed(360.0)),
    )
}
