//! Authenticated local session service. The management handle is in-process
//! only; the socket never exports approval, revocation, unlock or raw vault APIs.
#![cfg(unix)]
mod channel;
mod engine;
mod error;
mod filesystem;
mod peer;
mod server;
mod settings;
mod transport;

pub use error::{DaemonError, Result};
pub use server::Daemon;
pub use settings::{DaemonControl, Pairing, PairingCode, PairingSettings};
