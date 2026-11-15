//! Device unlock and account enrollment adapter.
mod view;

use cosmic::iced::Task;

use crate::backend::local::{self, ItemsPage};
use crate::backend::off_thread;
use crate::i18n::t;
use crate::session::Session;
use zann_client::app::local::RememberedUnlock;

pub use zann_flows::unlock::Phase as Mode;
pub struct State {
    operations: zann_flows::unlock::Operations,
    startup: bool,
    platform_prompt: bool,
    mode: Mode,
    connected_keys: Option<bool>,
    select_after: Option<String>,
    account_label: Option<String>,
    confirmation: String,
    /// Whether this device can open the vault without the master password, and
    /// with what. Absent until the shell has asked the facade.
    remembered: Option<RememberedUnlock>,
    password: String,
    hidden: bool,
    busy: bool,
    error: Option<String>,
    /// Something that happened before this screen appeared and the user needs
    /// to know about — a snapshot restore, above all, which can change which
    /// password opens the vault.
    notice: Option<String>,
    /// Set after a server login: the storage to pull once the vault is open.
    sync_after: Option<String>,
}

#[derive(Clone)]
pub enum OpenResult {
    AccountKeyRequired,
    Vault { page: ItemsPage },
}

#[derive(Clone)]
pub enum Message {
    /// What this device remembers, answered by the shell on the way in.
    Remembered(RememberedUnlock),
    /// Unlock with the remembered source instead of the password. Waits on a
    /// touch when that source is a hardware key.
    UseRemembered,
    PasswordInput(String),
    ConfirmationInput(String),
    ToggleVisibility,
    Submit,
    UseUnlocked,
    Recovery,
    /// The vault contents, plus the outcome of the sync that ran on the way
    /// in, if one did; a failed one did not stop the vault opening.
    Opened(zann_flows::OperationId, Result<OpenResult, String>),
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterMessage(<redacted>)")
    }
}

pub enum Outcome {
    None,
    Task(Task<Message>),
    Recovery,
    Opened {
        page: ItemsPage,
        sync_after: Option<String>,
    },
}

impl State {
    pub fn new(mode: Mode, sync_after: Option<String>) -> Self {
        static NEXT_INSTANCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            operations: zann_flows::unlock::Operations::new(
                NEXT_INSTANCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            ),
            mode,
            startup: false,
            platform_prompt: false,
            connected_keys: None,
            select_after: None,
            account_label: None,
            confirmation: String::new(),
            remembered: None,
            password: String::new(),
            hidden: true,
            busy: false,
            error: None,
            notice: None,
            sync_after,
        }
    }

    pub fn at_startup(mut self) -> Self {
        self.startup = true;
        self
    }
    pub fn platform_prompt_pending(&self) -> bool {
        self.busy && self.platform_prompt
    }
    pub fn current_operation(&self) -> Option<zann_flows::OperationId> {
        self.operations.active()
    }

    pub fn with_storage(mut self, id: String) -> Self {
        self.select_after = Some(id);
        self
    }
    pub fn with_account_label(mut self, label: String) -> Self {
        self.account_label = Some(label);
        self
    }

    pub fn with_account(mut self, has_keys: bool) -> Self {
        self.connected_keys = Some(has_keys);
        self
    }

    fn creating(&self) -> bool {
        self.mode.creating()
    }

    /// Carry a message onto the unlock screen from whatever sent the user back
    /// to it.
    pub fn with_notice(mut self, notice: String) -> Self {
        self.notice = Some(notice);
        self
    }

    pub fn update(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::Remembered(remembered) => {
                let armed = remembered.armed;
                self.remembered = Some(remembered);
                // A key already in the port should not need a click as well.
                let automatic = zann_flows::unlock::attempt_remembered_at_startup(
                    self.startup,
                    armed,
                    self.mode,
                );
                self.startup = false;
                if automatic && !self.busy {
                    return self.unlock_remembered(session);
                }
            }

            Message::Recovery if !self.busy => return Outcome::Recovery,
            Message::Recovery => {}
            Message::UseRemembered => return self.unlock_remembered(session),

            Message::PasswordInput(value) => self.password = value,
            Message::ConfirmationInput(value) => self.confirmation = value,

            Message::ToggleVisibility => self.hidden = !self.hidden,

            Message::Submit | Message::UseUnlocked => {
                self.platform_prompt = false;
                let use_unlocked = matches!(message, Message::UseUnlocked);
                if self.busy
                    || (!use_unlocked && self.password.is_empty())
                    || (!use_unlocked
                        && self.creating()
                        && (self.password != self.confirmation
                            || zann_ui_core::password::password_feedback(&self.password)
                                .validation_key
                                .is_some()))
                {
                    return Outcome::None;
                }
                let Some(id) = self.operations.begin() else {
                    return Outcome::None;
                };
                let facade = session.facade();
                let password = std::mem::take(&mut self.password);
                self.confirmation.clear();
                let storage = self.sync_after.clone();
                let selected = self.select_after.clone();
                let mode = self.mode;
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Opened(
                        id,
                        off_thread(move || {
                            if !use_unlocked {
                                match mode {
                                    Mode::Create => {
                                        local::initialize_master_password(&facade, password)?
                                    }
                                    Mode::Unlock => local::unlock(&facade, password)?,
                                    Mode::AccountCreate | Mode::AccountUnlock => {
                                        facade
                                            .enroll_account_key(password)
                                            .map_err(|e| e.to_string())?;
                                    }
                                }
                            }
                            if let Some(selected) = selected {
                                facade
                                    .set_current_storage(selected)
                                    .map_err(|e| e.to_string())?;
                            }
                            if storage.is_some()
                                && matches!(mode, Mode::Create | Mode::Unlock)
                                && !facade
                                    .activate_connected_account()
                                    .map_err(|e| e.to_string())?
                            {
                                return Ok(OpenResult::AccountKeyRequired);
                            }
                            if facade.current_storage_id().is_none()
                                && !facade
                                    .setup_accounts()
                                    .map_err(|e| e.to_string())?
                                    .iter()
                                    .any(|account| account.enrolled)
                            {
                                return Ok(OpenResult::AccountKeyRequired);
                            }
                            local::items(&facade, None, None).map(|page| OpenResult::Vault { page })
                        })
                        .await,
                    )
                }));
            }

            Message::Opened(id, Ok(OpenResult::Vault { page })) => {
                if !self.operations.finish(id) {
                    return Outcome::None;
                }
                self.busy = false;
                return Outcome::Opened {
                    page,
                    sync_after: self.sync_after.take(),
                };
            }

            Message::Opened(id, Ok(OpenResult::AccountKeyRequired)) => {
                if !self.operations.finish(id) {
                    return Outcome::None;
                }
                self.busy = false;
                if let zann_flows::unlock::Route::Password(phase) =
                    zann_flows::unlock::after_device_unlock(false, self.connected_keys)
                {
                    self.mode = phase;
                } else {
                    return Outcome::Recovery;
                }
            }

            Message::Opened(id, Err(err)) => {
                if !self.operations.finish(id) {
                    return Outcome::None;
                }
                self.busy = false;
                self.error = Some(err);
            }
        }
        Outcome::None
    }

    /// Open the vault with whatever this device remembers. Blocks the worker
    /// thread on a touch when the source is a hardware key, which is why the
    /// screen reports itself busy for the whole call.
    fn unlock_remembered(&mut self, session: &Session) -> Outcome {
        if self.busy {
            return Outcome::None;
        }
        let Some(id) = self.operations.begin() else {
            return Outcome::None;
        };
        self.platform_prompt = true;
        let facade = session.facade();
        let storage = self.sync_after.clone();
        let selected = self.select_after.clone();
        self.busy = true;
        self.error = None;
        Outcome::Task(cosmic::task::future(async move {
            Message::Opened(
                id,
                off_thread(move || {
                    local::unlock_remembered(&facade)?;
                    if let Some(selected) = selected {
                        facade
                            .set_current_storage(selected)
                            .map_err(|e| e.to_string())?;
                    }
                    if storage.is_some()
                        && !facade
                            .activate_connected_account()
                            .map_err(|e| e.to_string())?
                    {
                        return Ok(OpenResult::AccountKeyRequired);
                    }
                    if facade.current_storage_id().is_none()
                        && !facade
                            .setup_accounts()
                            .map_err(|e| e.to_string())?
                            .iter()
                            .any(|account| account.enrolled)
                    {
                        return Ok(OpenResult::AccountKeyRequired);
                    }
                    local::items(&facade, None, None).map(|page| OpenResult::Vault { page })
                })
                .await,
            )
        }))
    }
}
