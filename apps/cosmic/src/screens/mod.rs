//! One module per screen. Each owns its own state, its own message type and a
//! small `Outcome` describing the ways it can hand control back — none of them
//! knows about [`Screen`] or about its siblings, so the routing lives in one
//! place (`main.rs`) instead of being spread across the screens.

pub mod connect;
pub mod detail;
pub mod master;
pub mod palette;
pub mod settings;
pub mod vault;
pub mod welcome;

use cosmic::iced::{Alignment, Length};
use cosmic::prelude::*;
use cosmic::{widget, Element};

/// The two screens that accumulate state are boxed so that switching screens
/// stays a pointer-sized move.
pub enum Screen {
    Welcome,
    Connect(Box<connect::State>),
    Master(master::State),
    Vault(Box<vault::State>),
}

/// The single-column layout the pre-vault screens share.
pub fn centered<'a, M: 'a>(content: impl Into<Element<'a, M>>) -> Element<'a, M> {
    content
        .into()
        .apply(widget::container)
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(Alignment::Center)
        .align_y(Alignment::Center)
        .into()
}
