//! Shared device-unlock/account-enrollment routing, admission and deadlines.
//! Adapters execute native effects; this module never holds passwords or I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Create,
    Unlock,
    AccountCreate,
    AccountUnlock,
}
impl Phase {
    pub fn creating(self) -> bool {
        matches!(self, Self::Create | Self::AccountCreate)
    }
    pub fn account(self) -> bool {
        matches!(self, Self::AccountCreate | Self::AccountUnlock)
    }
    pub fn title_key(self) -> &'static str {
        match self {
            Self::Create => "unlock.createTitle",
            Self::Unlock => "unlock.deviceTitle",
            Self::AccountCreate => "unlock.accountCreateTitle",
            Self::AccountUnlock => "unlock.accountTitle",
        }
    }
    pub fn help_key(self) -> &'static str {
        match self {
            Self::Create => "unlock.deviceCreateHelp",
            Self::Unlock => "unlock.deviceHelp",
            Self::AccountCreate => "unlock.accountCreateHelp",
            Self::AccountUnlock => "unlock.accountHelp",
        }
    }
    pub fn placeholder_key(self) -> &'static str {
        if self.account() {
            "unlock.accountPlaceholder"
        } else {
            "unlock.passwordPlaceholder"
        }
    }
    pub fn confirmation_key(self) -> &'static str {
        if self.account() {
            "unlock.confirmAccountPassword"
        } else {
            "unlock.confirmDevicePassword"
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Password(Phase),
    Open,
    ChooseAccount,
    Connect,
}
pub fn device_phase(initialized: bool) -> Phase {
    if initialized {
        Phase::Unlock
    } else {
        Phase::Create
    }
}
pub fn account_phase(has_keys: bool) -> Phase {
    if has_keys {
        Phase::AccountUnlock
    } else {
        Phase::AccountCreate
    }
}
pub fn after_connection(
    initialized: bool,
    unlocked: bool,
    enrolled: bool,
    has_keys: bool,
) -> Route {
    if !initialized {
        Route::Password(Phase::Create)
    } else if !unlocked {
        Route::Password(Phase::Unlock)
    } else if enrolled {
        Route::Open
    } else {
        Route::Password(account_phase(has_keys))
    }
}
pub fn after_device_unlock(enrolled: bool, connected_has_keys: Option<bool>) -> Route {
    if enrolled {
        Route::Open
    } else {
        connected_has_keys.map_or(Route::ChooseAccount, |keys| {
            Route::Password(account_phase(keys))
        })
    }
}
pub fn for_account(enrolled: bool, unlocked: bool) -> Route {
    if !enrolled {
        Route::Connect
    } else if unlocked {
        Route::Open
    } else {
        Route::Password(Phase::Unlock)
    }
}
/// Platform authentication may temporarily deactivate its own window.
pub fn focus_lock_required(unlocked: bool, work_pending: bool, platform_prompt: bool) -> bool {
    !platform_prompt && (unlocked || work_pending)
}
pub fn attempt_remembered_at_startup(startup: bool, armed: bool, phase: Phase) -> bool {
    startup && armed && phase == Phase::Unlock
}
pub fn idle_lock_due(unlocked: bool, timeout_minutes: u32, idle_millis: i64) -> bool {
    unlocked && timeout_minutes != 0 && idle_millis >= i64::from(timeout_minutes) * 60_000
}
/// Cancellation also invalidates native results already waiting for the UI.
#[derive(Debug)]
pub struct Operations {
    instance: u64,
    sequence: u64,
    active: Option<crate::OperationId>,
}
impl Operations {
    pub fn new(instance: u64) -> Self {
        Self {
            instance,
            sequence: 0,
            active: None,
        }
    }
    pub fn begin(&mut self) -> Option<crate::OperationId> {
        if self.active.is_some() {
            return None;
        }
        self.sequence = self.sequence.checked_add(1)?;
        let id = crate::OperationId {
            instance: self.instance,
            sequence: self.sequence,
        };
        self.active = Some(id);
        Some(id)
    }
    pub fn finish(&mut self, id: crate::OperationId) -> bool {
        if self.active != Some(id) {
            return false;
        }
        self.active = None;
        true
    }
    pub fn active(&self) -> Option<crate::OperationId> {
        self.active
    }
    pub fn cancel(&mut self) {
        self.active = None;
    }
}
#[cfg(test)]
mod tests;
