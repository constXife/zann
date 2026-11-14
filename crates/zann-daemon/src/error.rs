#[derive(thiserror::Error)]
pub enum DaemonError {
    #[error("local browser protocol failed")]
    Ipc(#[from] zann_client::browser_ipc::IpcError),
    #[error("{0}")]
    SocketPath(#[from] zann_client::native_messaging::SocketPathError),
    #[error("encrypted local channel failed")]
    Channel(#[from] zann_crypto::ipc_transport::IpcTransportError),
    #[error("local IPC I/O failed")]
    Io(#[from] std::io::Error),
    #[error("invalid local IPC JSON")]
    Json(#[from] serde_json::Error),
    #[error("local IPC authentication refused")]
    Authentication,
    #[error("local IPC protocol refused")]
    Protocol,
    #[error("local IPC resource limit reached")]
    Limit,
    #[error("local IPC owner is no longer running")]
    Closed,
    #[error("local IPC state permissions or identity are invalid")]
    Filesystem,
    #[error("local vault operation failed")]
    Vault(#[from] zann_client::app::local::LocalError),
}

pub type Result<T> = std::result::Result<T, DaemonError>;

impl std::fmt::Debug for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
