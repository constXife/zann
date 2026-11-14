//! Account selection and scoped recovery widgets over the canonical local port.
use super::centered;
use crate::{
    backend::{
        local::{self, ItemsPage},
        off_thread,
    },
    i18n::{t, t_args},
    session::Session,
};
use cosmic::iced::{Length, Task};
use cosmic::{theme, widget, Element};
use zann_client::app::local::{RecoveryOutcome, RecoveryPreview, RecoveryScope, SetupAccount};
use zann_flows::unlock::{self, Route};
mod view;

pub struct State {
    operations: unlock::Operations,
    accounts: Vec<SetupAccount>,
    preview: Option<RecoveryPreview>,
    selected: Option<String>,
    discard: bool,
    busy: bool,
    error: Option<String>,
    snapshot: Option<String>,
}
#[derive(Clone, Debug)]
pub enum Selection {
    Open(ItemsPage),
    Unlock(String),
    Connect(String),
}
#[derive(Clone, Debug)]
pub enum Message {
    Loaded(zann_flows::OperationId, Result<Vec<SetupAccount>, String>),
    Choose(String),
    Selected(zann_flows::OperationId, Result<Selection, String>),
    Prepare(Option<String>),
    Prepared(zann_flows::OperationId, Result<RecoveryPreview, String>),
    Discard(bool),
    Cancel,
    Cancelled(zann_flows::OperationId, Result<(), String>),
    Confirm,
    Recovered(
        zann_flows::OperationId,
        Result<(RecoveryOutcome, Vec<SetupAccount>), String>,
    ),
    Connect,
}
pub enum Outcome {
    None,
    Task(Task<Message>),
    Opened(ItemsPage),
    Unlock(String),
    Connect(Option<String>),
}
pub(super) fn message(error: zann_client::app::local::LocalError) -> String {
    if let zann_client::app::local::LocalError::Unlock { ref kind, .. } = error {
        let key = format!("errors.{kind}");
        let translated = t(&key);
        if translated != key {
            return translated;
        }
    }
    error.to_string()
}
impl State {
    pub fn new(session: &Session) -> (Self, Task<Message>) {
        static NEXT_INSTANCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let mut operations = unlock::Operations::new(
            NEXT_INSTANCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        let id = operations.begin().expect("fresh operation sequence");
        let facade = session.facade();
        let task = cosmic::task::future(async move {
            Message::Loaded(
                id,
                off_thread(move || facade.setup_accounts().map_err(message)).await,
            )
        });
        (
            Self {
                operations,
                accounts: Vec::new(),
                preview: None,
                selected: None,
                discard: false,
                busy: true,
                error: None,
                snapshot: None,
            },
            task,
        )
    }
    pub fn update(&mut self, event: Message, session: &Session) -> Outcome {
        match event {
            Message::Loaded(id, result) => {
                if !self.operations.finish(id) {
                    return Outcome::None;
                }
                self.busy = false;
                match result {
                    Ok(rows) => self.accounts = rows,
                    Err(error) => self.error = Some(error),
                }
            }
            Message::Choose(id) if !self.busy => {
                let Some(account) = self
                    .accounts
                    .iter()
                    .find(|a| a.location.storage_id == id)
                    .cloned()
                else {
                    return Outcome::None;
                };
                let Some(operation) = self.operations.begin() else {
                    return Outcome::None;
                };
                self.busy = true;
                let facade = session.facade();
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Selected(
                        operation,
                        off_thread(move || {
                            let status = facade.app_status().map_err(message)?;
                            match unlock::for_account(account.enrolled, !status.locked) {
                                Route::Open => {
                                    facade.set_current_storage(id).map_err(message)?;
                                    local::items(&facade, None, None).map(Selection::Open)
                                }
                                Route::Password(_) => Ok(Selection::Unlock(id)),
                                Route::Connect => {
                                    Ok(Selection::Connect(account.location.server_url))
                                }
                                Route::ChooseAccount => {
                                    unreachable!("account selection has a concrete target")
                                }
                            }
                        })
                        .await,
                    )
                }));
            }
            Message::Selected(id, result) => {
                if !self.operations.finish(id) {
                    return Outcome::None;
                }
                self.busy = false;
                match result {
                    Ok(Selection::Open(page)) => return Outcome::Opened(page),
                    Ok(Selection::Unlock(id)) => return Outcome::Unlock(id),
                    Ok(Selection::Connect(url)) => return Outcome::Connect(Some(url)),
                    Err(error) => self.error = Some(error),
                }
            }
            Message::Prepare(storage) if !self.busy => {
                let Some(operation) = self.operations.begin() else {
                    return Outcome::None;
                };
                self.busy = true;
                self.error = None;
                self.discard = false;
                self.selected = storage.clone();
                let facade = session.facade();
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Prepared(
                        operation,
                        off_thread(move || {
                            facade
                                .prepare_local_recovery(
                                    storage.map_or(RecoveryScope::Device, RecoveryScope::Account),
                                )
                                .map_err(message)
                        })
                        .await,
                    )
                }));
            }
            Message::Prepared(id, result) => {
                if !self.operations.finish(id) {
                    return Outcome::None;
                }
                self.busy = false;
                match result {
                    Ok(preview) => self.preview = Some(preview),
                    Err(error) => self.error = Some(error),
                }
            }
            Message::Discard(value) if !self.busy => self.discard = value,
            Message::Cancel if !self.busy => {
                let Some(preview) = self.preview.as_ref() else {
                    return Outcome::None;
                };
                let Some(operation) = self.operations.begin() else {
                    return Outcome::None;
                };
                let id = preview.id.clone();
                let facade = session.facade();
                self.busy = true;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Cancelled(
                        operation,
                        off_thread(move || facade.cancel_local_recovery(id).map_err(message)).await,
                    )
                }));
            }
            Message::Cancelled(id, result) => {
                if !self.operations.finish(id) {
                    return Outcome::None;
                }
                self.busy = false;
                match result {
                    Ok(()) => self.preview = None,
                    Err(error) => self.error = Some(error),
                }
            }
            Message::Confirm if !self.busy => {
                let Some(preview) = self.preview.as_ref() else {
                    return Outcome::None;
                };
                if preview.has_unsent() && !self.discard {
                    return Outcome::None;
                }
                let Some(operation) = self.operations.begin() else {
                    return Outcome::None;
                };
                let id = preview.id.clone();
                let discard = self.discard;
                let facade = session.facade();
                self.busy = true;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Recovered(
                        operation,
                        off_thread(move || {
                            let result = facade
                                .confirm_local_recovery(id, discard)
                                .map_err(message)?;
                            Ok((result, facade.setup_accounts().map_err(message)?))
                        })
                        .await,
                    )
                }));
            }
            Message::Recovered(id, result) => {
                if !self.operations.finish(id) {
                    return Outcome::None;
                }
                self.busy = false;
                match result {
                    Ok((result, rows)) => {
                        self.preview = None;
                        self.snapshot = Some(result.snapshot_path);
                        self.accounts = rows;
                    }
                    Err(error) => self.error = Some(error),
                }
            }
            Message::Connect if !self.busy => return Outcome::Connect(None),
            _ => {}
        }
        Outcome::None
    }
}
