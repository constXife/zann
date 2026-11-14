//! Explicit native IPC lifecycle and in-process management projection.
use crate::{CoreError, CoreFacade, CoreResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum BrowserErrorKindFfi {
    NotRunning,
    PathTooLong,
    Busy,
    Security,
    Protocol,
    Transport,
    Vault,
    Stopped,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct BrowserPairingFfi {
    pub public_key: String,
    pub name: String,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct BrowserPairingSettingsFfi {
    pub paired: Vec<BrowserPairingFfi>,
    pub active_code_id: Option<String>,
}

/// Display-only secret returned to native UI, never a diagnostic record.
#[derive(uniffi::Record)]
pub struct BrowserPairingCodeFfi {
    pub id: String,
    pub value: String,
    pub expires_in_seconds: u32,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl From<zann_daemon::DaemonError> for CoreError {
    fn from(error: zann_daemon::DaemonError) -> Self {
        use zann_daemon::DaemonError as E;
        let kind = match &error {
            E::SocketPath(zann_client::native_messaging::SocketPathError::TooLong) => {
                BrowserErrorKindFfi::PathTooLong
            }
            E::SocketPath(_) | E::Json(_) | E::Protocol => BrowserErrorKindFfi::Protocol,
            E::Ipc(_) | E::Channel(_) | E::Authentication | E::Filesystem => {
                BrowserErrorKindFfi::Security
            }
            E::Io(_) => BrowserErrorKindFfi::Transport,
            E::Limit => BrowserErrorKindFfi::Busy,
            E::Closed => BrowserErrorKindFfi::Stopped,
            E::Vault(_) => BrowserErrorKindFfi::Vault,
        };
        Self::Browser {
            kind,
            message: error.to_string(),
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl CoreFacade {
    fn browser_control(&self) -> CoreResult<zann_daemon::DaemonControl> {
        self.daemon
            .lock()
            .expect("lock poisoned")
            .as_ref()
            .map(|d| d.control())
            .ok_or_else(|| CoreError::Browser {
                kind: BrowserErrorKindFfi::NotRunning,
                message: "native composition has not started the browser service".into(),
            })
    }
}

#[uniffi::export]
impl CoreFacade {
    /// Native composition activates IPC explicitly over this exact local vault.
    /// Idempotent when running; never substitutes another root/session on failure.
    pub fn start_browser_service(&self) -> CoreResult<()> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let mut owner = self.daemon.lock().expect("lock poisoned");
            if let Some(daemon) = owner.as_ref() {
                return daemon.control().settings().map(|_| ()).map_err(Into::into);
            }
            *owner = Some(zann_daemon::Daemon::start(
                self.inner.client_paths(),
                self.inner.clone(),
            )?);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Err(CoreError::Unimplemented(
            "local browser IPC is desktop-only".into(),
        ))
    }

    pub fn browser_pairings(&self) -> CoreResult<BrowserPairingSettingsFfi> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let settings = self.browser_control()?.settings()?;
            Ok(BrowserPairingSettingsFfi {
                active_code_id: settings.active_code_id,
                paired: settings
                    .paired
                    .into_iter()
                    .map(|p| BrowserPairingFfi {
                        public_key: p.public_key,
                        name: p.name,
                    })
                    .collect(),
            })
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Err(CoreError::Unimplemented(
            "local browser IPC is desktop-only".into(),
        ))
    }

    pub fn browser_begin_pairing(&self) -> CoreResult<BrowserPairingCodeFfi> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let code = self.browser_control()?.begin_pairing()?;
            Ok(BrowserPairingCodeFfi {
                id: code.id,
                value: code.value.to_string(),
                expires_in_seconds: code.expires_in_seconds,
            })
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Err(CoreError::Unimplemented(
            "local browser IPC is desktop-only".into(),
        ))
    }

    pub fn browser_revoke(&self, public_key: String) -> CoreResult<()> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            self.browser_control()?
                .revoke(&public_key)
                .map_err(Into::into)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = public_key;
            Err(CoreError::Unimplemented(
                "local browser IPC is desktop-only".into(),
            ))
        }
    }
}
