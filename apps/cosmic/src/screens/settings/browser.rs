use super::*;
use zann_daemon::{DaemonControl, PairingCode, PairingSettings};

#[derive(Clone, Debug)]
pub enum Message {
    Refresh,
    Loaded(Result<PairingSettings, String>),
    Begin,
    Code(Result<PairingCode, String>),
    Expired(String),
    Revoke(String),
}

pub(super) fn load(control: DaemonControl) -> Task<super::Message> {
    cosmic::task::future(async move {
        super::Message::Browser(Message::Loaded(
            off_thread(move || control.settings().map_err(|e| e.to_string())).await,
        ))
    })
}

impl State {
    pub(super) fn update_browser(&mut self, message: Message, session: &Session) -> Outcome {
        let control = session.browser_control();
        match message {
            Message::Refresh => Outcome::Task(load(control)),
            Message::Loaded(result) => {
                match result {
                    Ok(settings) => {
                        if self
                            .browser_code
                            .as_ref()
                            .is_some_and(|c| settings.active_code_id.as_ref() != Some(&c.id))
                        {
                            self.browser_code = None;
                        }
                        self.browser_pairings = Some(settings);
                    }
                    Err(error) => self.error = Some(error),
                }
                Outcome::None
            }
            Message::Begin => {
                if self.busy {
                    return Outcome::None;
                }
                self.busy = true;
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
                    Ok(code) => {
                        let id = code.id.clone();
                        let lifetime = code.expires_in_seconds;
                        self.browser_code = Some(code);
                        Outcome::Task(cosmic::task::future(async move {
                            tokio::time::sleep(std::time::Duration::from_secs(lifetime.into()))
                                .await;
                            super::Message::Browser(Message::Expired(id))
                        }))
                    }
                    Err(error) => {
                        self.error = Some(error);
                        Outcome::None
                    }
                }
            }
            Message::Expired(id) => {
                if self.browser_code.as_ref().is_some_and(|c| c.id == id) {
                    self.browser_code = None;
                }
                Outcome::Task(load(control))
            }
            Message::Revoke(key) => Outcome::Task(cosmic::task::future(async move {
                let result = off_thread(move || {
                    control.revoke(&key).map_err(|e| e.to_string())?;
                    control.settings().map_err(|e| e.to_string())
                })
                .await;
                super::Message::Browser(Message::Loaded(result))
            })),
        }
    }

    pub(super) fn browser_section(&self) -> Element<'_, super::Message> {
        let mut section = widget::settings::section()
            .title(t("browser.title"))
            .add(widget::text::caption(t("browser.codeHint")))
            .add(
                widget::button::suggested(t("browser.connect"))
                    .on_press(super::Message::Browser(Message::Begin)),
            )
            .add(
                widget::button::standard(t("browser.refresh"))
                    .on_press(super::Message::Browser(Message::Refresh)),
            );
        if let Some(code) = &self.browser_code {
            section = section.add(widget::text::title3(format!(
                "{}: {}",
                t("browser.code"),
                code.value.as_str()
            )));
        }
        if let Some(settings) = &self.browser_pairings {
            for paired in &settings.paired {
                section = section.add(
                    widget::settings::item::builder(paired.name.clone())
                        .description(paired.public_key.clone())
                        .control(widget::button::destructive(t("browser.revoke")).on_press(
                            super::Message::Browser(Message::Revoke(paired.public_key.clone())),
                        )),
                );
            }
        }
        section.into()
    }
}
