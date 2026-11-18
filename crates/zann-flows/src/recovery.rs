//! Shared account-recovery wizard policy (prepare → confirm successor code →
//! consume/retry/resume → enroll). Native executors keep code custody, replay
//! and recovery authority; this module never holds old codes or passwords.
mod types;
pub use types::*;
use zann_core::api::account_access::PasskeyMode;
use zann_core::recovery::RecoveryState;

/// Recovery is offered from the Connect method/password choice when idle.
pub fn can_open(connect: &crate::connect::Snapshot) -> bool {
    !connect.busy
        && matches!(
            connect.stage,
            crate::connect::Stage::Methods | crate::connect::Stage::Password { .. }
        )
}

pub struct AccountRecovery<P, H> {
    instance: u64,
    sequence: u64,
    active: Option<(OperationId, Step)>,
    closed: bool,
    error: Option<String>,
    locator: String,
    preparation: Option<P>,
    pending: Vec<H>,
    handle: Option<H>,
    consumed: bool,
    candidate: Option<Candidate>,
    restart: bool,
    name: String,
    mode: PasskeyMode,
    terminal: Option<Terminal>,
}

impl<P: Preparation, H: Clone> AccountRecovery<P, H> {
    pub fn new(instance: u64) -> Self {
        Self {
            instance,
            sequence: 0,
            active: None,
            closed: false,
            error: None,
            locator: String::new(),
            preparation: None,
            pending: Vec::new(),
            handle: None,
            consumed: false,
            candidate: None,
            restart: false,
            name: String::new(),
            mode: PasskeyMode::VaultUnlock,
            terminal: None,
        }
    }

    pub fn closed(&self) -> bool {
        self.closed
    }

    pub fn snapshot(&self) -> Snapshot<'_, H> {
        let phase = if let Some(terminal) = self.terminal {
            match terminal {
                Terminal::Completed => Phase::Completed,
                Terminal::Stopped => Phase::Stopped,
            }
        } else if self.handle.is_some() {
            let (name, mode) = self.enrollment();
            Phase::Recover {
                consumed: self.consumed,
                candidate: self.candidate.is_some(),
                restart: self.restart,
                editable: self.editable(),
                name,
                mode,
                password_required: mode == PasskeyMode::VaultUnlock,
            }
        } else if let Some(preparation) = &self.preparation {
            Phase::Confirm {
                successor_code: preparation.successor_code(),
                pending: &self.pending,
            }
        } else {
            Phase::Locate {
                locator: &self.locator,
            }
        };
        Snapshot {
            phase,
            busy: self.active.is_some(),
            error: self.error.as_deref(),
        }
    }

    /// The user must retype the successor code before the old one is spent.
    pub fn can_consume(&self, confirmation: &str) -> bool {
        self.idle()
            && self.handle.is_none()
            && self
                .preparation
                .as_ref()
                .is_some_and(|plan| plan.successor_code() == confirmation)
    }

    pub fn dispatch(&mut self, action: Action<'_>) -> Vec<Effect<P, H>> {
        if self.closed {
            return vec![];
        }
        if matches!(action, Action::Back) {
            self.closed = true;
            let mut effects: Vec<_> = self
                .active
                .take()
                .map(|(id, _)| Effect::Cancel { id })
                .into_iter()
                .collect();
            effects.push(Effect::Closed);
            return effects;
        }
        if !self.idle() {
            return vec![];
        }
        let recovering = self.handle.is_some();
        match action {
            Action::SetLocator(value) if !recovering && self.preparation.is_none() => {
                self.locator = value;
                vec![]
            }
            Action::SetName(value) if recovering && self.editable() => {
                self.name = value;
                vec![]
            }
            Action::SetMode(mode) if recovering && self.editable() => {
                self.mode = mode;
                vec![]
            }
            Action::SetRestart(restart) if recovering && self.candidate.is_some() => {
                self.restart = restart;
                vec![]
            }
            Action::Prepare if !recovering && self.preparation.is_none() => {
                let locator = self.locator.trim().to_owned();
                if locator.is_empty() {
                    return vec![];
                }
                let id = self.start(Step::Prepare);
                vec![Effect::Prepare { id, locator }]
            }
            Action::Consume { confirmation } => {
                if !self.can_consume(confirmation) {
                    return vec![];
                }
                let preparation = self.preparation.take().expect("admitted preparation");
                let id = self.start(Step::Consume);
                vec![Effect::Consume { id, preparation }]
            }
            Action::RetryConsume if !self.consumed => {
                let Some(handle) = self.handle.clone() else {
                    return vec![];
                };
                let id = self.start(Step::Consume);
                vec![Effect::RetryConsume { id, handle }]
            }
            Action::ResumeCurrent => {
                let Some(handle) = self.handle.clone() else {
                    return vec![];
                };
                let id = self.start(Step::Consume);
                vec![Effect::Resume { id, handle }]
            }
            Action::ResumePending(index) if !recovering && self.preparation.is_some() => {
                let Some(handle) = self.pending.get(index).cloned() else {
                    return vec![];
                };
                let id = self.start(Step::Consume);
                vec![Effect::Resume { id, handle }]
            }
            Action::Enroll { pairing } if self.consumed => {
                let Some(handle) = self.handle.clone() else {
                    return vec![];
                };
                let (name, mode) = self.enrollment();
                let name = name.trim().to_owned();
                let restart = self.restart;
                let id = self.start(Step::Enroll);
                vec![Effect::Enroll {
                    id,
                    handle,
                    restart,
                    name,
                    mode,
                    pairing,
                }]
            }
            _ => vec![],
        }
    }

    /// Late, cancelled or misrouted replies are discarded by operation ID.
    pub fn complete(&mut self, id: OperationId, reply: Result<Reply<P, H>, Failure>) {
        let Some((active, step)) = self.active else {
            return;
        };
        if self.closed || active != id || reply.as_ref().is_ok_and(|reply| !reply.fits(step)) {
            return;
        }
        self.active = None;
        match reply {
            Ok(Reply::Prepared {
                preparation,
                pending,
            }) => {
                self.preparation = Some(preparation);
                self.pending = pending;
            }
            Ok(Reply::Consumed(Consumed { handle, progress })) => {
                // A handle supersedes any unused preparation (e.g. a pending resume).
                self.preparation = None;
                self.pending.clear();
                self.handle = Some(handle);
                match progress {
                    Ok(progress) => self.apply(progress),
                    Err(failure) => self.fail(failure),
                }
            }
            Ok(Reply::Enrolled) => self.terminal = Some(Terminal::Completed),
            Err(failure) => self.fail(failure),
        }
    }

    fn apply(&mut self, progress: Progress) {
        self.consumed = true;
        self.restart = false;
        if let Some(candidate) = &progress.candidate {
            self.name.clone_from(&candidate.name);
            self.mode = candidate.mode;
        }
        self.candidate = progress.candidate;
        self.terminal = match progress.state {
            RecoveryState::Completed => Some(Terminal::Completed),
            state if state.is_terminal() => Some(Terminal::Stopped),
            _ => None,
        };
    }

    fn fail(&mut self, failure: Failure) {
        self.error = match failure {
            Failure::Cancelled => None,
            Failure::Message(message) => Some(message),
        };
    }

    fn idle(&self) -> bool {
        !self.closed && self.active.is_none() && self.terminal.is_none()
    }

    fn editable(&self) -> bool {
        self.candidate.is_none() || self.restart
    }

    fn enrollment(&self) -> (&str, PasskeyMode) {
        match &self.candidate {
            Some(candidate) if !self.restart => (&candidate.name, candidate.mode),
            _ => (&self.name, self.mode),
        }
    }

    fn start(&mut self, step: Step) -> OperationId {
        self.sequence = self
            .sequence
            .checked_add(1)
            .expect("recovery operation ID exhausted");
        let id = OperationId {
            instance: self.instance,
            sequence: self.sequence,
        };
        self.active = Some((id, step));
        self.error = None;
        id
    }
}

#[cfg(test)]
mod tests;
