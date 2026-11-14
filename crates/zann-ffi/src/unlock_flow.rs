//! Pure presentation/flow projections shared with the Rust native client.
use crate::{CoreFacade, CoreResult};
use zann_flows::unlock as flow;
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum UnlockPhaseFfi {
    Create,
    Unlock,
    AccountCreate,
    AccountUnlock,
}
impl From<UnlockPhaseFfi> for flow::Phase {
    fn from(value: UnlockPhaseFfi) -> Self {
        match value {
            UnlockPhaseFfi::Create => Self::Create,
            UnlockPhaseFfi::Unlock => Self::Unlock,
            UnlockPhaseFfi::AccountCreate => Self::AccountCreate,
            UnlockPhaseFfi::AccountUnlock => Self::AccountUnlock,
        }
    }
}
impl From<flow::Phase> for UnlockPhaseFfi {
    fn from(value: flow::Phase) -> Self {
        match value {
            flow::Phase::Create => Self::Create,
            flow::Phase::Unlock => Self::Unlock,
            flow::Phase::AccountCreate => Self::AccountCreate,
            flow::Phase::AccountUnlock => Self::AccountUnlock,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct UnlockPhaseViewFfi {
    pub creating: bool,
    pub account: bool,
    pub title_key: String,
    pub help_key: String,
    pub placeholder_key: String,
    pub confirmation_key: String,
}
#[derive(Clone, Debug, uniffi::Enum)]
pub enum UnlockRouteFfi {
    Password { phase: UnlockPhaseFfi },
    Open,
    ChooseAccount,
    Connect,
}
impl From<flow::Route> for UnlockRouteFfi {
    fn from(value: flow::Route) -> Self {
        match value {
            flow::Route::Password(phase) => Self::Password {
                phase: phase.into(),
            },
            flow::Route::Open => Self::Open,
            flow::Route::ChooseAccount => Self::ChooseAccount,
            flow::Route::Connect => Self::Connect,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasswordFeedbackFfi {
    pub strength_key: Option<String>,
    pub validation_key: Option<String>,
}
#[uniffi::export]
pub fn password_creation_feedback(password: String) -> PasswordFeedbackFfi {
    let password = zeroize::Zeroizing::new(password);
    let value = zann_ui_core::password::password_feedback(&password);
    PasswordFeedbackFfi {
        strength_key: value.strength_key.map(str::to_owned),
        validation_key: value.validation_key.map(str::to_owned),
    }
}
#[uniffi::export]
pub fn unlock_phase_view(phase: UnlockPhaseFfi) -> UnlockPhaseViewFfi {
    let phase = flow::Phase::from(phase);
    UnlockPhaseViewFfi {
        creating: phase.creating(),
        account: phase.account(),
        title_key: phase.title_key().into(),
        help_key: phase.help_key().into(),
        placeholder_key: phase.placeholder_key().into(),
        confirmation_key: phase.confirmation_key().into(),
    }
}
#[uniffi::export]
pub fn unlock_route_after_connection(
    initialized: bool,
    unlocked: bool,
    enrolled: bool,
    has_keys: bool,
) -> UnlockRouteFfi {
    flow::after_connection(initialized, unlocked, enrolled, has_keys).into()
}
#[uniffi::export]
pub fn unlock_route_after_device(
    enrolled: bool,
    connected_has_keys: Option<bool>,
) -> UnlockRouteFfi {
    flow::after_device_unlock(enrolled, connected_has_keys).into()
}

#[uniffi::export]
pub fn unlock_route_for_account(enrolled: bool, unlocked: bool) -> UnlockRouteFfi {
    flow::for_account(enrolled, unlocked).into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FlowOperationFfi {
    pub instance: u64,
    pub sequence: u64,
}

#[derive(uniffi::Object)]
pub struct UnlockOperationsFfi(std::sync::Mutex<flow::Operations>);
#[uniffi::export]
impl UnlockOperationsFfi {
    #[uniffi::constructor]
    pub fn new() -> std::sync::Arc<Self> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        std::sync::Arc::new(Self(std::sync::Mutex::new(flow::Operations::new(
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ))))
    }
    pub fn begin(&self) -> Option<FlowOperationFfi> {
        self.0
            .lock()
            .expect("unlock operation lock")
            .begin()
            .map(|id| FlowOperationFfi {
                instance: id.instance,
                sequence: id.sequence,
            })
    }
    pub fn finish(&self, operation: FlowOperationFfi) -> bool {
        self.0
            .lock()
            .expect("unlock operation lock")
            .finish(zann_flows::OperationId {
                instance: operation.instance,
                sequence: operation.sequence,
            })
    }
    pub fn cancel(&self) {
        self.0.lock().expect("unlock operation lock").cancel();
    }
}

#[uniffi::export]
pub fn unlock_idle_lock_due(unlocked: bool, timeout_minutes: u32, idle_millis: i64) -> bool {
    flow::idle_lock_due(unlocked, timeout_minutes, idle_millis)
}
#[uniffi::export]
impl CoreFacade {
    pub fn idle_unlock_key_present(&self) -> CoreResult<bool> {
        self.inner.idle_unlock_key_present().map_err(Into::into)
    }
}
#[uniffi::export]
pub fn unlock_focus_lock_required(
    unlocked: bool,
    work_pending: bool,
    platform_prompt: bool,
) -> bool {
    flow::focus_lock_required(unlocked, work_pending, platform_prompt)
}
#[uniffi::export]
pub fn unlock_attempt_remembered_at_startup(
    startup: bool,
    armed: bool,
    phase: UnlockPhaseFfi,
) -> bool {
    flow::attempt_remembered_at_startup(startup, armed, phase.into())
}
