//! One module per screen. Each owns its own state, its own message type and a
//! small `Outcome` describing the ways it can hand control back — none of them
//! knows about [`Screen`] or about its siblings, so the routing lives in one
//! place (`main.rs`) instead of being spread across the screens.

pub mod connect;
pub mod detail;
pub mod master;
pub mod settings;
pub mod vault;
pub mod welcome;

use cosmic::iced::{Alignment, Length};
use cosmic::prelude::*;
use cosmic::{widget, Element};

/// The screens that accumulate state are boxed so that switching screens stays
/// a pointer-sized move.
pub enum Screen {
    Welcome,
    Connect {
        state: Box<connect::State>,
        /// Opening Accounts → Add server must not discard the unlocked vault
        /// when the user presses Back.
        return_to: Option<Box<Screen>>,
    },
    Master(Box<master::State>),
    Vault(Box<vault::State>),
    /// Reached from the vault and always returns to it, so the vault it came
    /// from is parked here rather than rebuilt from the database.
    Settings {
        state: Box<settings::State>,
        vault: Box<vault::State>,
    },
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
