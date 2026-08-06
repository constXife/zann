//! Everything that talks to the zann core and to a zann server.
//!
//! Split by who owns the state on the other side: [`local`] drives the vault on
//! this machine, [`remote`] drives a login against a server. Both are
//! synchronous — the core blocks on its own tokio runtime and master key
//! derivation is deliberately expensive — so callers push the work onto a
//! worker thread with [`off_thread`].

pub mod local;
pub mod remote;

use std::path::{Path, PathBuf};

use cosmic::iced::futures::channel::oneshot;

const LOCAL_DB_FILENAME: &str = "local.sqlite";

/// Same resolution order as the other clients: `ZANN_DB_URL`, then
/// `~/.zann/local.sqlite`.
pub fn default_db_url() -> String {
    if let Ok(value) = std::env::var("ZANN_DB_URL") {
        if value.starts_with("sqlite://") {
            return value;
        }
        return format!("sqlite://{value}");
    }
    format!(
        "sqlite://{}",
        local_root().join(LOCAL_DB_FILENAME).display()
    )
}

fn local_root() -> PathBuf {
    dirs::home_dir()
        .map(|home| home.join(".zann"))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// The client state and identity config live next to the database file.
pub(crate) fn client_root(db_url: &str) -> PathBuf {
    db_url
        .strip_prefix("sqlite://")
        .and_then(|path| Path::new(path).parent().map(Path::to_path_buf))
        .unwrap_or_else(local_root)
}

/// Runs a blocking call on its own thread and awaits the result.
pub async fn off_thread<T, F>(work: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    let (sender, receiver) = oneshot::channel();
    std::thread::spawn(move || {
        let _ = sender.send(work());
    });
    receiver
        .await
        .unwrap_or_else(|_| Err("background task did not finish".to_string()))
}
