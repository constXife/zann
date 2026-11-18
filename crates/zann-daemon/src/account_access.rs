//! Bounded native-only ceremony admission. No vault/root-unlock capability.
use crate::{engine::Engine, DaemonControl, DaemonError, Result};
use std::{
    sync::{mpsc, Arc},
    time::{Duration, Instant},
};
use zann_client::browser_ipc::{AccountCeremonyCompletion, AccountCeremonyPrompt};

pub(crate) struct Pending {
    pub pairing: String,
    pub flight: [u8; 32],
    pub prompt: AccountCeremonyPrompt,
    pub deadline: Instant,
    pub channel: Option<([u8; 32], [u8; 32])>,
    pub deliver: mpsc::SyncSender<AccountCeremonyCompletion>,
}
pub struct AccountCeremonyWait {
    engine: Arc<Engine>,
    flight: [u8; 32],
    receiver: mpsc::Receiver<AccountCeremonyCompletion>,
    deadline: Instant,
}
impl AccountCeremonyWait {
    /// Called by the native adapter on a blocking worker, never a UI thread.
    pub fn wait(&self) -> Result<AccountCeremonyCompletion> {
        self.receiver
            .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            .map_err(DaemonError::CeremonyWait)
    }
}
impl Drop for AccountCeremonyWait {
    fn drop(&mut self) {
        let mut state = self.engine.state.lock().expect("lock poisoned");
        if state
            .account_ceremony
            .as_ref()
            .is_some_and(|p| p.flight == self.flight)
        {
            state.account_ceremony = None;
        }
    }
}
impl DaemonControl {
    pub fn begin_account_ceremony(
        &self,
        pairing: &str,
        prompt: AccountCeremonyPrompt,
    ) -> Result<AccountCeremonyWait> {
        let mut state = self.engine.state.lock().expect("lock poisoned");
        self.engine.check_running()?;
        if !state.pairings.iter().any(|p| p.public_key == pairing)
            || state
                .account_ceremony
                .as_ref()
                .is_some_and(|p| p.deadline > Instant::now())
        {
            return Err(DaemonError::Protocol);
        }
        // Validate all public context before it can cross to the browser.
        zann_client::browser_ipc::validate_account_prompt(&prompt)?;
        let (deliver, receiver) = mpsc::sync_channel(1);
        let deadline = Instant::now() + Duration::from_secs(120);
        let flight = zann_crypto::ipc_signatures::random_nonce();
        state.account_ceremony = Some(Pending {
            pairing: pairing.into(),
            flight,
            prompt,
            deadline,
            channel: None,
            deliver,
        });
        Ok(AccountCeremonyWait {
            engine: self.engine.clone(),
            flight,
            receiver,
            deadline,
        })
    }
    pub fn cancel_account_ceremony(&self) -> Result<()> {
        let mut state = self.engine.state.lock().expect("lock poisoned");
        self.engine.check_running()?;
        state.account_ceremony = None;
        Ok(())
    }
}

struct BrowserProvider {
    control: DaemonControl,
    pairing: String,
}
impl DaemonControl {
    pub fn account_ceremony_provider(
        &self,
        pairing: String,
    ) -> Arc<dyn zann_client::account_access::AccountCeremonyProvider> {
        Arc::new(BrowserProvider {
            control: self.clone(),
            pairing,
        })
    }
}
struct CancelOnDrop {
    engine: Arc<Engine>,
    flight: [u8; 32],
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let mut state = self.engine.state.lock().expect("lock poisoned");
        if state
            .account_ceremony
            .as_ref()
            .is_some_and(|p| p.flight == self.flight)
        {
            state.account_ceremony = None;
        }
    }
}
impl zann_client::account_access::AccountCeremonyProvider for BrowserProvider {
    fn perform(
        &self,
        prompt: AccountCeremonyPrompt,
    ) -> zann_client::account_access::AccountCeremonyFuture<'_> {
        Box::pin(async move {
            use zann_client::account_access::AccountCeremonyError;
            let wait = self
                .control
                .begin_account_ceremony(&self.pairing, prompt)
                .map_err(|e| AccountCeremonyError::Adapter(Box::new(e)))?;
            let _cancel = CancelOnDrop {
                engine: self.control.engine.clone(),
                flight: wait.flight,
            };
            let completion = tokio::task::spawn_blocking(move || wait.wait())
                .await
                .map_err(|e| AccountCeremonyError::Adapter(Box::new(e)))?
                .map_err(|e| AccountCeremonyError::Adapter(Box::new(e)))?;
            match completion {
                AccountCeremonyCompletion::Completed { result } => Ok(result),
                AccountCeremonyCompletion::Failed { reason } => {
                    Err(AccountCeremonyError::Failed(reason))
                }
            }
        })
    }
}
