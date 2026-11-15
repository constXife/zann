//! Native confirmation form. Authorization and policy enforcement live in LocalVault.
use super::*;
use zann_client::app::local::{ExportFactor, ExportPolicy, ExportSecurity, ExportStepUp};
use zann_client::app::{SessionCancellationHandle, SessionOperation};
use zeroize::Zeroize;

#[derive(Default)]
pub(super) struct State {
    security: Option<ExportSecurity>,
    target_policy: Option<ExportPolicy>,
    visible: bool,
    factor: usize,
    password: String,
    pin: String,
    pending: Option<SessionCancellationHandle>,
    generation: u64,
    error: Option<String>,
}
#[derive(Clone)]
pub enum Message {
    OpenPolicy,
    Loaded(u64, Result<ExportSecurity, String>),
    Factor(usize),
    Password(String),
    Pin(String),
    Submit,
    Cancel,
    Finished(u64, Result<Option<BackupExportReport>, String>),
}
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExportMessage(<redacted>)")
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.cancel();
    }
}
impl State {
    pub(super) fn cancel(&mut self) {
        if let Some(operation) = self.pending.take() {
            operation.cancel();
        }
        self.generation += 1;
        self.password.zeroize();
        self.pin.zeroize();
        self.visible = false;
    }
    pub(super) fn open(
        &mut self,
        session: &Session,
        policy: Option<ExportPolicy>,
    ) -> Task<Message> {
        self.cancel();
        self.visible = true;
        self.security = None;
        self.error = None;
        self.target_policy = policy;
        let generation = self.generation;
        let facade = session.facade();
        cosmic::task::future(async move {
            Message::Loaded(
                generation,
                off_thread(move || facade.export_security().map_err(|e| e.to_string())).await,
            )
        })
    }
    pub(super) fn update(
        &mut self,
        message: Message,
        session: &Session,
    ) -> (Task<Message>, Option<BackupExportReport>) {
        match message {
            Message::OpenPolicy => {
                // The current value is read from the core on each confirmation.
                return (
                    self.open(session, Some(ExportPolicy::PasswordAndHardwareOrBiometric)),
                    None,
                );
            }
            Message::Loaded(generation, result) if generation == self.generation => match result {
                Ok(security) => {
                    if self.target_policy.is_some() {
                        self.target_policy = Some(match security.policy {
                            ExportPolicy::AnyConfiguredFactor => {
                                ExportPolicy::PasswordAndHardwareOrBiometric
                            }
                            ExportPolicy::PasswordAndHardwareOrBiometric => {
                                ExportPolicy::AnyConfiguredFactor
                            }
                        });
                    }
                    self.factor = if security.policy == ExportPolicy::PasswordAndHardwareOrBiometric
                    {
                        if security.hardware_available {
                            1
                        } else {
                            2
                        }
                    } else {
                        0
                    };
                    self.security = Some(security);
                }
                Err(error) => self.error = Some(error),
            },
            Message::Password(value) => {
                self.password.zeroize();
                self.password = value;
            }
            Message::Pin(value) => {
                self.pin.zeroize();
                self.pin = value;
            }
            Message::Factor(value) if self.pending.is_none() => self.factor = value,
            Message::Cancel => self.cancel(),
            Message::Submit
                if self.visible && self.pending.is_none() && self.security.is_some() =>
            {
                let password =
                    (!self.password.is_empty()).then(|| std::mem::take(&mut self.password));
                let mut pin = zeroize::Zeroizing::new(
                    (!self.pin.is_empty()).then(|| std::mem::take(&mut self.pin)),
                );
                let factor = match self.factor {
                    0 => ExportFactor::DevicePassword,
                    1 => ExportFactor::HardwareKey { pin: pin.take() },
                    _ => ExportFactor::Biometric,
                };
                let proof = ExportStepUp { password, factor };
                let (operation, cancel) = SessionOperation::new(
                    std::time::Instant::now() + std::time::Duration::from_secs(120),
                );
                self.pending = Some(cancel);
                let generation = self.generation;
                let policy = self.target_policy;
                let facade = session.facade();
                return (
                    cosmic::task::future(async move {
                        Message::Finished(
                            generation,
                            off_thread(move || {
                                let authorization = facade
                                    .authorize_export(proof, operation)
                                    .map_err(|e| e.to_string())?;
                                match policy {
                                    Some(policy) => facade
                                        .set_export_policy(policy, authorization)
                                        .map(|()| None)
                                        .map_err(|e| e.to_string()),
                                    None => facade
                                        .backup_export_file(String::new(), authorization)
                                        .map(Some)
                                        .map_err(|e| e.to_string()),
                                }
                            })
                            .await,
                        )
                    }),
                    None,
                );
            }
            Message::Finished(generation, result) if generation == self.generation => {
                self.pending = None;
                match result {
                    Ok(report) => {
                        self.cancel();
                        return (Task::none(), report);
                    }
                    Err(error) => self.error = Some(error),
                }
            }
            _ => {}
        }
        (Task::none(), None)
    }
    pub(super) fn security_view(&self) -> Element<'_, Message> {
        widget::settings::section()
            .title(t("export.securityTitle"))
            .add(widget::text::caption(t("export.policyHelp")))
            .add(widget::button::standard(t("export.changePolicy")).on_press(Message::OpenPolicy))
            .add(if self.target_policy.is_some() {
                self.view()
            } else {
                widget::column::with_capacity(8).into()
            })
            .into()
    }
    pub(super) fn view(&self) -> Element<'_, Message> {
        let mut column = widget::column::with_capacity(8).spacing(theme::spacing().space_s);
        if !self.visible {
            return column.into();
        }
        column = column
            .push(widget::text::title4(t("export.confirmTitle")))
            .push(widget::text::caption(t(if self.target_policy.is_some() {
                "export.policyHelp"
            } else {
                "settings.backups.plainWarningDesc"
            })));
        if let Some(security) = self.security {
            if let Some(policy) = self.target_policy {
                column = column.push(widget::text::caption(t(
                    if policy == ExportPolicy::PasswordAndHardwareOrBiometric {
                        "export.enableStrict"
                    } else {
                        "export.disableStrict"
                    },
                )));
            }
            column = column.push(widget::text::caption(t(match security.policy {
                ExportPolicy::AnyConfiguredFactor => "export.anyFactor",
                ExportPolicy::PasswordAndHardwareOrBiometric => "export.strictPolicy",
            })));
            let choices = [
                (0, "export.password", true),
                (1, "export.hardware", security.hardware_available),
                (2, "export.biometric", security.biometric_available),
            ];
            for (index, label, available) in choices {
                if available {
                    column = column.push(widget::radio(
                        widget::text::body(t(label)),
                        index,
                        Some(self.factor),
                        Message::Factor,
                    ));
                }
            }
            column = column.push(
                widget::text_input::secure_input(
                    t("unlock.devicePassword"),
                    &self.password,
                    None::<Message>,
                    true,
                )
                .on_input(Message::Password),
            );
            if self.factor == 1 {
                column = column.push(
                    widget::text_input::secure_input(
                        t("export.pin"),
                        &self.pin,
                        None::<Message>,
                        true,
                    )
                    .on_input(Message::Pin),
                );
            }
            let mut submit = widget::button::suggested(t("export.confirm"));
            if self.pending.is_none() {
                submit = submit.on_press(Message::Submit);
            }
            column = column.push(submit);
        }
        if let Some(error) = &self.error {
            column = column.push(widget::text::caption(error));
        }
        column
            .push(widget::button::standard(t("common.cancel")).on_press(Message::Cancel))
            .into()
    }
}
