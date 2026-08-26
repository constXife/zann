// SPDX-License-Identifier: MIT

//! The parts of the PoC that are not the window: the backend, the session and
//! the screen state machines.
//!
//! `main.rs` is the shell on top of this. Keeping the split means the screens
//! can be driven from tests without a compositor — every screen is a plain
//! `update(message) -> Outcome`.

pub mod backend;
pub mod i18n;
pub mod preferences;
pub mod screens;
pub mod session;
