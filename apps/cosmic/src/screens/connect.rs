//! Connect form and effect executor adapter. All flow policy is in zann-flows.
use crate::backend::remote::Remote;
use crate::backend::{next_view_request, off_thread};
use cosmic::iced::{Subscription, Task};
use std::collections::VecDeque;
use std::sync::Arc;
pub use zann_flows::connect::Stage;
use zann_flows::connect::{Action, Completion, Connect, Effect, Failure};
mod event;
mod view;
pub use event::{Event, Message, Outcome};
#[cfg(test)]
mod tests;

pub struct State {
    generation: u64,
    flow: Connect,
    remote: Option<Arc<Remote>>,
    url: String,
    email: String,
    password: String,
    full_name: String,
    password_hidden: bool,
}
impl Default for State {
    fn default() -> Self {
        let generation = next_view_request();
        Self {
            generation,
            flow: Connect::new(generation),
            remote: None,
            url: String::new(),
            email: String::new(),
            password: String::new(),
            full_name: String::new(),
            password_hidden: true,
        }
    }
}
impl State {
    pub fn with_server_url(url: String) -> Self {
        let mut state = Self::default();
        state.url = url;
        state
    }
    pub fn server_url(&self) -> &str {
        &self.url
    }
    pub fn stage(&self) -> &Stage {
        &self.flow.snapshot().stage
    }
    pub fn subscription(&self) -> Subscription<Event> {
        Subscription::none()
    }
    pub fn event(&self, message: Message) -> Event {
        Event {
            generation: self.generation,
            message,
        }
    }

    pub fn update(&mut self, event: Event) -> Vec<Outcome> {
        if event.generation != self.generation
            || matches!(self.stage(), Stage::Closed | Stage::Complete)
        {
            return vec![];
        }
        let action = match event.message {
            Message::UrlInput(value) => {
                if !self.flow.snapshot().busy {
                    self.url = value;
                }
                return vec![];
            }
            Message::EmailInput(value) => {
                self.email = value;
                return vec![];
            }
            Message::FullNameInput(value) => {
                self.full_name = value;
                return vec![];
            }
            Message::PasswordInput(value) => {
                self.password = value;
                return vec![];
            }
            Message::TogglePassword => {
                self.password_hidden = !self.password_hidden;
                return vec![];
            }
            Message::Completed { id, step, result } => {
                if !self.flow.accepts(id, step) {
                    return vec![];
                }
                let completion = match result {
                    Ok(reply) => self.remote.as_ref().and_then(|remote| remote.accept(reply)),
                    Err(message) => Some(Completion::failed(step, Failure::Message(message))),
                };
                let Some(completion) = completion else {
                    return vec![];
                };
                let effects = self.flow.complete(id, completion);
                return self.execute(effects);
            }
            Message::Probe => Action::Probe {
                url: self.url.clone(),
            },
            Message::SubmitPassword => {
                if !self.flow.can_submit_password(&self.email, &self.password) {
                    return vec![];
                }
                Action::SubmitPassword {
                    email: self.email.clone(),
                    password: std::mem::take(&mut self.password),
                    full_name: Some(self.full_name.clone()),
                }
            }
            Message::ChoosePassword => Action::ChoosePassword,
            Message::SetRegistering(register) => Action::SetRegistering { register },
            Message::StartOidc => Action::StartOidc,
            Message::OpenAuthUrl => Action::ReopenBrowser,
            Message::CopyAuthUrl => Action::CopyBrowserUrl,
            Message::TrustFingerprint => Action::TrustFingerprint,
            Message::Back => Action::Back,
            Message::Cancel => Action::Cancel,
        };
        let effects = self.flow.dispatch(action);
        self.execute(effects)
    }

    fn execute(&mut self, effects: Vec<Effect>) -> Vec<Outcome> {
        let mut effects: VecDeque<_> = effects.into();
        let mut outcomes = Vec::new();
        while let Some(effect) = effects.pop_front() {
            match effect {
                work @ (Effect::Probe { .. }
                | Effect::TrustFingerprint { .. }
                | Effect::Password { .. }
                | Effect::BeginOidc { .. }
                | Effect::FinishOidc { .. }) => {
                    let (id, step) = work.operation().expect("work has an operation");
                    let plan = self.remote().and_then(|remote| remote.plan(work));
                    match plan {
                        Ok(plan) => {
                            let generation = self.generation;
                            outcomes.push(Outcome::Task(Task::future(async move {
                                let result = off_thread(move || Ok(plan.run())).await;
                                Event {
                                    generation,
                                    message: Message::Completed { id, step, result },
                                }
                            })));
                        }
                        Err(error) => effects.extend(
                            self.flow
                                .complete(id, Completion::failed(step, Failure::Message(error))),
                        ),
                    }
                }
                Effect::Cancel { id } => {
                    if let Some(remote) = &self.remote {
                        remote.cancel(id);
                    }
                }
                Effect::ResetConnection => {
                    if let Some(remote) = &self.remote {
                        remote.reset();
                    }
                }
                Effect::OpenBrowser { url, .. } => outcomes.push(Outcome::OpenUrl(url)),
                Effect::CopyBrowserUrl { url, .. } => outcomes.push(Outcome::Copy(url)),
                Effect::Connected(connected) => outcomes.push(Outcome::Connected {
                    storage_id: connected.storage_id,
                    has_personal_keys: connected.has_personal_keys,
                }),
                Effect::Closed => {
                    self.password.clear();
                    outcomes.push(Outcome::Cancelled);
                }
            }
        }
        outcomes
    }

    fn remote(&mut self) -> Result<Arc<Remote>, String> {
        if self.remote.is_none() {
            self.remote = Some(Arc::new(Remote::new()?));
        }
        Ok(Arc::clone(
            self.remote.as_ref().expect("Remote initialized"),
        ))
    }
}
impl Drop for State {
    fn drop(&mut self) {
        if let Some(remote) = &self.remote {
            remote.close();
        }
    }
}
