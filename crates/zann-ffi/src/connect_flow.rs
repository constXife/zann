//! UniFFI projection of the pure Connect reducer. No transport or auth policy.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use zann_flows::connect as flow;

mod conversion;
mod records;
pub use records::*;

#[derive(uniffi::Object)]
pub struct ConnectFlowFfi(Mutex<flow::Connect>);

#[uniffi::export]
impl ConnectFlowFfi {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);
        Arc::new(Self(Mutex::new(flow::Connect::new(
            NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed),
        ))))
    }

    pub fn snapshot(&self) -> ConnectSnapshotFfi {
        self.0
            .lock()
            .expect("Connect flow lock poisoned")
            .snapshot()
            .into()
    }

    pub fn can_submit_password(&self, email: String, password: String) -> bool {
        self.0
            .lock()
            .expect("Connect flow lock poisoned")
            .can_submit_password(&email, &password)
    }

    pub fn dispatch(&self, action: ConnectActionFfi) -> Vec<ConnectEffectFfi> {
        self.0
            .lock()
            .expect("Connect flow lock poisoned")
            .dispatch(action.into())
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Adapters check before installing opaque prepared/browser capabilities.
    /// Their UI actor serializes this check, installation and completion.
    pub fn accepts(&self, id: ConnectOperationFfi, step: ConnectStepFfi) -> bool {
        self.0
            .lock()
            .expect("Connect flow lock poisoned")
            .accepts(id.into(), step.into())
    }

    pub fn complete(&self, completion: ConnectCompletionFfi) -> Vec<ConnectEffectFfi> {
        let (id, completion) = completion.into_parts();
        self.0
            .lock()
            .expect("Connect flow lock poisoned")
            .complete(id, completion)
            .into_iter()
            .map(Into::into)
            .collect()
    }
}
