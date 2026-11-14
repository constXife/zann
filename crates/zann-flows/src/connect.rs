//! One Connect policy for native shells. Canonical auth/trust capabilities stay
//! in effect executors; display metadata never authorizes a connection.
mod types;
pub use types::*;
use zann_core::AuthMethod;
use zann_ui_core::normalize_server_url;

#[derive(Clone)]
pub struct Snapshot {
    pub stage: Stage,
    pub server_url: String,
    pub methods: Vec<AuthMethod>,
    pub registration_available: bool,
    pub server_name: Option<String>,
    pub busy: bool,
    pub error: Option<String>,
}

pub struct Connect {
    instance: u64,
    sequence: u64,
    active: Option<(OperationId, Step)>,
    snapshot: Snapshot,
}

impl Connect {
    pub fn new(instance: u64) -> Self {
        Self {
            instance,
            sequence: 0,
            active: None,
            snapshot: Snapshot {
                stage: Stage::Server,
                server_url: String::new(),
                methods: Vec::new(),
                registration_available: false,
                server_name: None,
                busy: false,
                error: None,
            },
        }
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub fn accepts(&self, id: OperationId, step: Step) -> bool {
        self.active == Some((id, step))
    }

    /// Form adapters query admission before moving/clearing a password draft.
    pub fn can_submit_password(&self, email: &str, password: &str) -> bool {
        !self.snapshot.busy
            && matches!(self.snapshot.stage, Stage::Password { .. })
            && !email.trim().is_empty()
            && !password.is_empty()
    }

    pub fn dispatch(&mut self, action: Action) -> Vec<Effect> {
        if matches!(self.snapshot.stage, Stage::Closed | Stage::Complete) {
            return vec![];
        }
        match action {
            Action::Cancel => {
                let mut effects = self.cancel_active();
                self.snapshot.stage = Stage::Closed;
                effects.extend([Effect::ResetConnection, Effect::Closed]);
                effects
            }
            Action::Back => self.back(),
            Action::ReopenBrowser | Action::CopyBrowserUrl => {
                let Stage::Browser { url } = &self.snapshot.stage else {
                    return vec![];
                };
                let Some((id, _)) = self.active else {
                    return vec![];
                };
                vec![if matches!(action, Action::ReopenBrowser) {
                    Effect::OpenBrowser {
                        id,
                        url: url.clone(),
                    }
                } else {
                    Effect::CopyBrowserUrl {
                        id,
                        url: url.clone(),
                    }
                }]
            }
            _ if self.snapshot.busy => vec![],
            Action::Probe { url } if self.snapshot.stage == Stage::Server => {
                let url = normalize_server_url(&url);
                if url.is_empty() {
                    self.snapshot.error = Some("server URL is required".into());
                    return vec![];
                }
                self.snapshot.server_url = url.clone();
                self.clear_connection();
                let id = self.start(Step::Probe);
                vec![Effect::ResetConnection, Effect::Probe { id, url }]
            }
            Action::TrustFingerprint
                if matches!(self.snapshot.stage, Stage::Fingerprint { .. }) =>
            {
                let id = self.start(Step::Trust);
                vec![Effect::TrustFingerprint { id }]
            }
            Action::ChoosePassword if self.snapshot.stage == Stage::Methods => {
                if self.snapshot.methods.contains(&AuthMethod::Password) {
                    self.snapshot.error = None;
                    self.snapshot.stage = Stage::Password { register: false };
                }
                vec![]
            }
            Action::SetRegistering { register }
                if matches!(self.snapshot.stage, Stage::Password { .. }) =>
            {
                self.snapshot.error = None;
                self.snapshot.stage = Stage::Password {
                    register: register && self.snapshot.registration_available,
                };
                vec![]
            }
            Action::SubmitPassword {
                email,
                password,
                full_name,
            } => {
                let Stage::Password { register } = self.snapshot.stage else {
                    return vec![];
                };
                if !self.can_submit_password(&email, &password) {
                    return vec![];
                }
                let email = email.trim().to_string();
                let full_name = full_name
                    .map(|name| name.trim().to_string())
                    .filter(|name| !name.is_empty());
                let id = self.start(Step::Password);
                vec![Effect::Password {
                    id,
                    email,
                    password,
                    full_name,
                    register,
                }]
            }
            Action::StartOidc if self.snapshot.stage == Stage::Methods => self.begin_oidc(),
            _ => vec![],
        }
    }

    pub fn complete(&mut self, id: OperationId, completion: Completion) -> Vec<Effect> {
        if !self.accepts(id, completion.step()) {
            return vec![];
        }
        let step = completion.step();
        self.active = None;
        self.snapshot.busy = false;
        match completion {
            Completion::Probed(Ok(Probe::Ready(info))) | Completion::Trusted(Ok(info)) => {
                self.offer(info)
            }
            Completion::Probed(Ok(Probe::FingerprintChanged { old, new })) => {
                self.snapshot.stage = Stage::Fingerprint { old, new };
                vec![]
            }
            Completion::OidcStarted(Ok(url)) => {
                self.active = Some((id, Step::OidcFinish));
                self.snapshot.busy = true;
                self.snapshot.stage = Stage::Browser { url: url.clone() };
                vec![Effect::OpenBrowser { id, url }, Effect::FinishOidc { id }]
            }
            Completion::Password(Ok(connected)) | Completion::OidcFinished(Ok(connected)) => {
                self.snapshot.stage = Stage::Complete;
                vec![
                    Effect::Cancel { id },
                    Effect::ResetConnection,
                    Effect::Connected(connected),
                ]
            }
            Completion::Probed(Err(error))
            | Completion::Trusted(Err(error))
            | Completion::Password(Err(error))
            | Completion::OidcStarted(Err(error))
            | Completion::OidcFinished(Err(error)) => {
                let mut effects = vec![Effect::Cancel { id }];
                if step == Step::Trust {
                    self.clear_connection();
                    self.snapshot.stage = Stage::Server;
                    effects.push(Effect::ResetConnection);
                } else if matches!(self.snapshot.stage, Stage::Browser { .. }) {
                    self.snapshot.stage = Stage::Methods;
                }
                self.snapshot.error = match error {
                    Failure::Cancelled => None,
                    Failure::Message(message) => Some(message),
                };
                effects
            }
        }
    }

    fn offer(&mut self, info: ServerInfo) -> Vec<Effect> {
        // Auth methods are a set. Bound both native method lists to the two
        // interactive choices even if a remote advertisement repeats entries.
        let mut methods = Vec::with_capacity(2);
        for method in info.methods {
            if matches!(method, AuthMethod::Password | AuthMethod::Oidc)
                && !methods.contains(&method)
            {
                methods.push(method);
            }
        }
        self.snapshot.methods = methods;
        self.snapshot.registration_available = info.registration_available;
        self.snapshot.server_name = info.server_name;
        self.snapshot.stage = Stage::Methods;
        match self.snapshot.methods.as_slice() {
            [] => {
                self.snapshot.stage = Stage::Server;
                self.snapshot.error = Some("server offers no interactive auth methods".into());
                vec![Effect::ResetConnection]
            }
            [AuthMethod::Password] => {
                self.snapshot.stage = Stage::Password { register: false };
                vec![]
            }
            [AuthMethod::Oidc] => self.begin_oidc(),
            _ => vec![],
        }
    }

    fn begin_oidc(&mut self) -> Vec<Effect> {
        if !self.snapshot.methods.contains(&AuthMethod::Oidc) {
            return vec![];
        }
        let id = self.start(Step::OidcStart);
        vec![Effect::BeginOidc { id }]
    }

    fn start(&mut self, step: Step) -> OperationId {
        self.sequence = self
            .sequence
            .checked_add(1)
            .expect("Connect operation ID exhausted");
        let id = OperationId {
            instance: self.instance,
            sequence: self.sequence,
        };
        self.active = Some((id, step));
        self.snapshot.busy = true;
        self.snapshot.error = None;
        id
    }

    fn cancel_active(&mut self) -> Vec<Effect> {
        self.snapshot.busy = false;
        self.snapshot.error = None;
        self.active
            .take()
            .map(|(id, _)| vec![Effect::Cancel { id }])
            .unwrap_or_default()
    }

    fn clear_connection(&mut self) {
        self.snapshot.methods.clear();
        self.snapshot.registration_available = false;
        self.snapshot.server_name = None;
    }

    fn back(&mut self) -> Vec<Effect> {
        let mut effects = self.cancel_active();
        self.snapshot.stage = match self.snapshot.stage {
            Stage::Server => {
                effects.extend([Effect::ResetConnection, Effect::Closed]);
                Stage::Closed
            }
            Stage::Password { .. } | Stage::Browser { .. } if self.snapshot.methods.len() > 1 => {
                Stage::Methods
            }
            _ => {
                self.clear_connection();
                effects.push(Effect::ResetConnection);
                Stage::Server
            }
        };
        effects
    }
}

#[cfg(test)]
mod tests;
