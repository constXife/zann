use super::*;
use cosmic::iced::Subscription;
use std::time::{Duration, Instant};
use zann_daemon::{DaemonControl, PairingCode, PairingSettings};

#[cfg(test)]
mod tests;
mod view;

pub(super) struct ActiveCode {
    code: PairingCode,
    expires: Instant,
    copied_until: Option<Instant>,
    copying: bool,
    refreshing: bool,
}

impl ActiveCode {
    fn new(code: PairingCode) -> Self {
        let expires = Instant::now() + Duration::from_secs(code.expires_in_seconds.into());
        Self {
            code,
            expires,
            copied_until: None,
            copying: false,
            refreshing: false,
        }
    }
    fn valid(&self) -> bool {
        Instant::now() < self.expires
    }
    fn copied(&self) -> bool {
        self.copied_until
            .is_some_and(|until| Instant::now() < until)
    }
}

#[derive(Clone, Debug)]
pub enum Message {
    Refresh,
    Loaded {
        for_code: Option<String>,
        result: Result<PairingSettings, String>,
    },
    Begin,
    Code(Result<PairingCode, String>),
    Copy,
    CopyChecked {
        id: String,
        result: Result<PairingSettings, String>,
    },
    Tick,
    Revoke(String),
}

pub(super) fn load(control: DaemonControl, for_code: Option<String>) -> Task<super::Message> {
    cosmic::task::future(async move {
        super::Message::Browser(Message::Loaded {
            for_code,
            result: off_thread(move || control.settings().map_err(|e| e.to_string())).await,
        })
    })
}

impl State {
    pub fn subscription(&self) -> Subscription<super::Message> {
        if self.browser_code.is_some() {
            cosmic::iced::time::every(Duration::from_secs(1))
                .map(|_| super::Message::Browser(Message::Tick))
        } else {
            Subscription::none()
        }
    }

    fn code_id(&self) -> Option<String> {
        self.browser_code
            .as_ref()
            .map(|active| active.code.id.clone())
    }

    fn refresh_browser(&mut self, control: DaemonControl) -> Outcome {
        if let Some(active) = &mut self.browser_code {
            if active.refreshing {
                return Outcome::None;
            }
            active.refreshing = true;
        }
        Outcome::Task(load(control, self.code_id()))
    }

    fn apply_browser_settings(&mut self, settings: PairingSettings) {
        if self
            .browser_code
            .as_ref()
            .is_some_and(|active| settings.active_code_id.as_ref() != Some(&active.code.id))
        {
            self.browser_code = None;
        }
        self.browser_pairings = Some(settings);
    }

    pub(super) fn update_browser(&mut self, message: Message, session: &Session) -> Outcome {
        let control = session.browser_control();
        match message {
            Message::Refresh => self.refresh_browser(control),
            Message::Loaded { for_code, result } => {
                if for_code != self.code_id() {
                    return Outcome::None;
                }
                if let Some(active) = &mut self.browser_code {
                    active.refreshing = false;
                }
                match result {
                    Ok(settings) => self.apply_browser_settings(settings),
                    Err(error) => self.error = Some(error),
                }
                Outcome::None
            }
            Message::Begin => {
                if self.busy {
                    return Outcome::None;
                }
                self.busy = true;
                self.error = None;
                self.browser_code = None;
                Outcome::Task(cosmic::task::future(async move {
                    super::Message::Browser(Message::Code(
                        off_thread(move || control.begin_pairing().map_err(|e| e.to_string()))
                            .await,
                    ))
                }))
            }
            Message::Code(result) => {
                self.busy = false;
                match result {
                    Ok(code) => self.browser_code = Some(ActiveCode::new(code)),
                    Err(error) => self.error = Some(error),
                }
                Outcome::None
            }
            Message::Copy => {
                let Some(active) = &mut self.browser_code else {
                    return Outcome::None;
                };
                if self.busy || active.copying || !active.valid() {
                    return Outcome::None;
                }
                active.copying = true;
                let id = active.code.id.clone();
                // The daemon owns expiry/consumption. Check before releasing a copy.
                Outcome::Task(cosmic::task::future(async move {
                    super::Message::Browser(Message::CopyChecked {
                        id,
                        result: off_thread(move || control.settings().map_err(|e| e.to_string()))
                            .await,
                    })
                }))
            }
            Message::CopyChecked { id, result } => {
                if self.code_id().as_ref() != Some(&id) {
                    return Outcome::None;
                }
                match result {
                    Ok(settings) => self.apply_browser_settings(settings),
                    Err(error) => {
                        if let Some(active) = &mut self.browser_code {
                            active.copying = false;
                        }
                        self.error = Some(error);
                        return Outcome::None;
                    }
                }
                let Some(active) = &mut self.browser_code else {
                    return Outcome::None;
                };
                active.copying = false;
                if !active.valid() {
                    self.browser_code = None;
                    return Outcome::None;
                }
                active.copied_until = Some(Instant::now() + Duration::from_secs(2));
                Outcome::Copy(active.code.value.to_string())
            }
            Message::Tick => {
                if self
                    .browser_code
                    .as_ref()
                    .is_some_and(|active| !active.valid())
                {
                    self.browser_code = None;
                }
                self.refresh_browser(control)
            }
            Message::Revoke(key) => {
                let for_code = self.code_id();
                Outcome::Task(cosmic::task::future(async move {
                    let result = off_thread(move || {
                        control.revoke(&key).map_err(|e| e.to_string())?;
                        control.settings().map_err(|e| e.to_string())
                    })
                    .await;
                    super::Message::Browser(Message::Loaded { for_code, result })
                }))
            }
        }
    }
}
