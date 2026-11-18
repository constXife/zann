//! Opaque passkey handoff across independent DeviceUnlock retries.
use super::*;
use std::sync::{Arc, Mutex};
use zann_client::app::{PasskeyVaultBootstrap, PasskeyVaultRequirement};
pub(super) struct PasskeySlot {
    bootstrap: Option<PasskeyVaultBootstrap>,
    failed: bool,
}
pub(super) type PendingPasskey = Arc<Mutex<PasskeySlot>>;
impl State {
    pub fn with_passkey(mut self, bootstrap: Option<PasskeyVaultBootstrap>) -> Self {
        if let Some(bootstrap) = bootstrap {
            self.passkey_login = true;
            match bootstrap.requirement() {
                PasskeyVaultRequirement::EncryptionPassword
                | PasskeyVaultRequirement::SharedCache => {}
                PasskeyVaultRequirement::Ready => {
                    self.passkey = Some(Arc::new(Mutex::new(PasskeySlot {
                        bootstrap: Some(bootstrap),
                        failed: false,
                    })))
                }
                PasskeyVaultRequirement::PrfUnavailable
                | PasskeyVaultRequirement::GrantUnavailable(_) => {
                    self.passkey_repair = true;
                    self.notice = Some(t("accountPasskey.grantUnavailable"));
                }
            }
        }
        self
    }
}
pub(super) fn failed(slot: &PendingPasskey) -> bool {
    slot.lock().expect("passkey bootstrap lock poisoned").failed
}
pub(super) fn activate(
    facade: &local::Facade,
    passkey: Option<PendingPasskey>,
) -> Result<bool, String> {
    if facade
        .activate_connected_account()
        .map_err(|e| e.to_string())?
    {
        return Ok(true);
    }
    let Some(slot) = passkey else {
        return Ok(false);
    };
    let bootstrap = slot
        .lock()
        .expect("passkey bootstrap lock poisoned")
        .bootstrap
        .take()
        .ok_or_else(|| t("accountPasskey.grantUnavailable"))?;
    let result = facade
        .complete_account_passkey_login(bootstrap)
        .map_err(|e| e.to_string())
        .and_then(|_| {
            if facade
                .activate_connected_account()
                .map_err(|e| e.to_string())?
            {
                Ok(true)
            } else {
                Err(t("accountPasskey.grantUnavailable"))
            }
        });
    if result.is_err() {
        slot.lock().expect("passkey bootstrap lock poisoned").failed = true;
    }
    result
}
