#[derive(thiserror::Error)]
pub enum IpcError {
    #[error("one-time browser pairing refused")]
    Pairing(#[from] zann_crypto::ipc_pairing::PairingError),
    #[error("encrypted local channel refused")]
    Channel(#[from] zann_crypto::ipc_transport::IpcTransportError),
    #[error("invalid local IPC JSON")]
    Json(#[from] serde_json::Error),
    #[error("local IPC authentication refused")]
    Authentication,
    #[error("local IPC protocol refused")]
    Protocol,
    #[error("local IPC resource limit reached")]
    Limit,
    #[error("browser context refused")]
    Context(#[source] zann_autofill::FillDenied),
    #[error("browser origin refused")]
    Policy(#[source] zann_autofill::AutofillError),
}
pub type Result<T> = std::result::Result<T, IpcError>;
impl std::fmt::Debug for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
