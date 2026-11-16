//! File selection and summaries only; all admission/parsing belongs to native core.
use super::*;
use zann_client::app::local::{
    PasskeyExchangeFormat, PasskeyImportPreview, PasskeyImportReport, PasskeyTarget,
    PasskeyTargetSummary, SessionCancellationHandle, SessionOperation,
};
#[derive(Default)]
pub(super) struct State {
    targets: Vec<PasskeyTargetSummary>,
    target: Option<usize>,
    format: usize,
    path: Option<String>,
    preview: Option<PasskeyImportPreview>,
    report: Option<PasskeyImportReport>,
    error: Option<String>,
    busy: bool,
    generation: u64,
    cancellation: Option<SessionCancellationHandle>,
}
#[derive(Clone, Debug)]
pub enum Message {
    Load,
    Targets(u64, Result<Vec<PasskeyTargetSummary>, String>),
    Target(usize),
    Format(usize),
    Choose,
    Chosen(u64, Result<Option<(String, PasskeyImportPreview)>, String>),
    Import,
    Imported(u64, Result<PasskeyImportReport, String>),
    Export,
}
impl State {
    pub(super) fn cancel(&mut self) {
        self.generation += 1;
        if let Some(cancel) = self.cancellation.take() {
            cancel.cancel();
        }
        self.path = None;
        self.preview = None;
        self.report = None;
        self.targets.clear();
        self.target = None;
        self.busy = false;
    }
    pub(super) fn target(&self) -> Option<PasskeyTarget> {
        self.target
            .and_then(|i| self.targets.get(i))
            .map(|t| t.target.clone())
    }
    pub(super) fn update(&mut self, message: Message, session: &Session) -> Task<Message> {
        let facade = session.facade();
        let generation = self.generation;
        match message {
            Message::Load if !self.busy => {
                self.cancel();
                self.busy = true;
                let generation = self.generation;
                return cosmic::task::future(async move {
                    Message::Targets(
                        generation,
                        off_thread(move || facade.passkey_targets().map_err(|e| e.to_string()))
                            .await,
                    )
                });
            }
            Message::Targets(epoch, result) if epoch == generation => {
                self.busy = false;
                match result {
                    Ok(rows) => self.targets = rows,
                    Err(error) => self.error = Some(error),
                }
            }
            Message::Target(index) if !self.busy => self.target = Some(index),
            Message::Format(index) if !self.busy => {
                self.format = index;
                self.preview = None;
                self.path = None;
            }
            Message::Choose if !self.busy => {
                self.busy = true;
                self.error = None;
                self.preview = None;
                self.report = None;
                let format = match self.format {
                    0 => PasskeyExchangeFormat::Cxf,
                    1 => PasskeyExchangeFormat::Bitwarden,
                    2 => PasskeyExchangeFormat::KeepassXcPasskey,
                    _ => PasskeyExchangeFormat::KeepassXml,
                };
                return cosmic::task::future(async move {
                    let result = match file_chooser::open::Dialog::new()
                        .title(t("passkeyExchange.choose"))
                        .open_file()
                        .await
                    {
                        Ok(response) => match response.url().to_file_path() {
                            Ok(path) => {
                                off_thread(move || {
                                    let path = path.display().to_string();
                                    facade
                                        .passkey_preflight_file(path.clone(), format)
                                        .map(|preview| Some((path, preview)))
                                        .map_err(|e| e.to_string())
                                })
                                .await
                            }
                            Err(()) => Err("The selected file has no native path".into()),
                        },
                        Err(file_chooser::Error::Cancelled) => Ok(None),
                        Err(error) => Err(error.to_string()),
                    };
                    Message::Chosen(generation, result)
                });
            }
            Message::Chosen(epoch, result) if epoch == generation => {
                self.busy = false;
                match result {
                    Ok(Some((path, preview))) => {
                        self.path = Some(path);
                        self.preview = Some(preview)
                    }
                    Ok(None) => {}
                    Err(error) => self.error = Some(error),
                }
            }
            Message::Import if !self.busy => {
                if let (Some(path), Some(target), Some(_)) =
                    (self.path.clone(), self.target(), self.preview.as_ref())
                {
                    self.busy = true;
                    self.error = None;
                    let format = match self.format {
                        0 => PasskeyExchangeFormat::Cxf,
                        1 => PasskeyExchangeFormat::Bitwarden,
                        2 => PasskeyExchangeFormat::KeepassXcPasskey,
                        _ => PasskeyExchangeFormat::KeepassXml,
                    };
                    let (operation, cancel) = SessionOperation::new(
                        std::time::Instant::now() + std::time::Duration::from_secs(120),
                    );
                    self.cancellation = Some(cancel);
                    return cosmic::task::future(async move {
                        Message::Imported(
                            generation,
                            off_thread(move || {
                                facade
                                    .passkey_import_file(path, format, target, operation)
                                    .map_err(|e| e.to_string())
                            })
                            .await,
                        )
                    });
                }
            }
            Message::Imported(epoch, result) if epoch == generation => {
                self.busy = false;
                self.cancellation = None;
                match result {
                    Ok(report) => {
                        self.report = Some(report);
                        self.preview = None;
                        self.path = None
                    }
                    Err(error) => self.error = Some(error),
                }
            }
            _ => {}
        }
        Task::none()
    }
    pub(super) fn view(&self) -> Element<'_, Message> {
        let mut column = widget::column::with_capacity(16)
            .spacing(theme::spacing().space_s)
            .push(widget::text::title3(t("passkeyExchange.title")))
            .push(widget::text::caption(t("passkeyExchange.help")));
        if !self.busy {
            column = column
                .push(widget::button::standard(t("passkeyExchange.load")).on_press(Message::Load));
        }
        for (index, row) in self.targets.iter().enumerate() {
            column = column.push(widget::radio(
                widget::text::body(&row.name),
                index,
                self.target,
                Message::Target,
            ));
        }
        for (index, label) in [
            "FIDO CXF",
            "Bitwarden JSON",
            "KeePassXC .passkey",
            "KeePass XML",
        ]
        .iter()
        .enumerate()
        {
            column = column.push(widget::radio(
                widget::text::body(*label),
                index,
                Some(self.format),
                Message::Format,
            ));
        }
        let mut choose = widget::button::standard(t("passkeyExchange.choose"));
        let mut export = widget::button::standard(t("passkeyExchange.export"));
        if !self.busy {
            choose = choose.on_press(Message::Choose);
            if self.target().is_some() {
                export = export.on_press(Message::Export);
            }
        }
        column = column.push(choose).push(export);
        if let Some(preview) = &self.preview {
            column = column.push(widget::text::caption(t_args(
                "passkeyExchange.preview",
                &[
                    ("count", &preview.credentials.to_string()),
                    ("ignored", &preview.ignored_records.to_string()),
                ],
            )));
            let mut import = widget::button::suggested(t("passkeyExchange.import"));
            if !self.busy && self.target().is_some() {
                import = import.on_press(Message::Import);
            }
            column = column.push(import);
        }
        if let Some(report) = &self.report {
            column = column.push(widget::text::caption(t_args(
                "passkeyExchange.result",
                &[
                    ("count", &report.imported.to_string()),
                    ("skipped", &report.skipped_existing.to_string()),
                ],
            )));
        }
        if let Some(error) = &self.error {
            column = column.push(widget::text::caption(error));
        }
        column.into()
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.cancel();
    }
}
