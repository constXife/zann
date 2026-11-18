//! Account sign-in credentials are distinct from this device's unlock keys.
use super::*;
use zann_client::app::{LoginPassword, PasskeyEnrollmentAuthorization};
use zann_core::api::account_access::{AccountSecurity, PasskeyMode};
mod view;

#[derive(Default)]
pub(super) struct AccountKeys {
    security: Option<AccountSecurity>,
    active: Option<u64>,
    browsers: Vec<zann_daemon::Pairing>,
    selected: Option<usize>,
    name: String,
    password: String,
    auth_only: bool,
    confirm_revoke: Option<String>,
    code: Option<std::sync::Arc<zann_client::app::AccountRecoveryCode>>,
    code_confirmation: String,
    disable_password: bool,
}
#[derive(Clone)]
pub enum Message {
    PrepareCode,
    CodePrepared(
        u64,
        Result<std::sync::Arc<zann_client::app::AccountRecoveryCode>, String>,
    ),
    CodeConfirmation(String),
    DisablePassword(bool),
    ActivateCode,
    Refresh,
    Loaded(
        u64,
        Result<(AccountSecurity, Vec<zann_daemon::Pairing>), String>,
    ),
    Browser(usize),
    Name(String),
    Password(String),
    AuthOnly(bool),
    Enroll,
    AskRevoke(String),
    CancelRevoke,
    Revoke,
    Finished(u64, Result<(), String>),
}
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountKeysMessage(<redacted>)")
    }
}
impl State {
    pub(super) fn update_account_keys(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::CodeConfirmation(value) if !self.busy => {
                self.account_keys.code_confirmation = value
            }
            Message::DisablePassword(value) if !self.busy => {
                self.account_keys.disable_password = value
            }
            Message::PrepareCode if !self.busy && self.account_keys.code.is_none() => {
                let facade = session.facade();
                let request_id = self.account_keys.begin();
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    super::Message::AccountKeys(Message::CodePrepared(
                        request_id,
                        off_thread(move || {
                            facade
                                .prepare_server_recovery_code()
                                .map(std::sync::Arc::new)
                                .map_err(|e| e.to_string())
                        })
                        .await,
                    ))
                }));
            }
            Message::CodePrepared(id, result) => {
                if !self.account_keys.finish(id) {
                    return Outcome::None;
                }
                self.busy = false;
                match result {
                    Ok(code) => self.account_keys.code = Some(code),
                    Err(error) => self.error = Some(error),
                }
            }
            Message::ActivateCode if !self.busy => {
                let Some(candidate) = self.account_keys.code.clone() else {
                    return Outcome::None;
                };
                let Some(browser) = self
                    .account_keys
                    .selected
                    .and_then(|i| self.account_keys.browsers.get(i))
                else {
                    return Outcome::None;
                };
                let provider = session
                    .browser_control()
                    .account_ceremony_provider(browser.public_key.clone());
                let facade = session.facade();
                let confirmation = std::mem::take(&mut self.account_keys.code_confirmation);
                let disable = self.account_keys.disable_password;
                let request_id = self.account_keys.begin();
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    super::Message::AccountKeys(Message::Finished(
                        request_id,
                        off_thread(move || {
                            facade
                                .activate_server_recovery_code(
                                    &candidate,
                                    confirmation,
                                    disable,
                                    provider,
                                )
                                .map(|_| ())
                                .map_err(|e| e.to_string())
                        })
                        .await,
                    ))
                }));
            }
            Message::Name(value) if !self.busy => self.account_keys.name = value,
            Message::Password(value) if !self.busy => self.account_keys.password = value,
            Message::AuthOnly(value) if !self.busy => self.account_keys.auth_only = value,
            Message::Browser(index) if !self.busy && index < self.account_keys.browsers.len() => {
                self.account_keys.selected = Some(index)
            }
            Message::AskRevoke(id) if !self.busy => self.account_keys.confirm_revoke = Some(id),
            Message::CancelRevoke if !self.busy => self.account_keys.confirm_revoke = None,
            Message::Refresh if !self.busy => {
                let request_id = self.account_keys.begin();
                self.busy = true;
                let facade = session.facade();
                let control = session.browser_control();
                return Outcome::Task(cosmic::task::future(async move {
                    super::Message::AccountKeys(Message::Loaded(
                        request_id,
                        off_thread(move || {
                            let security = facade.account_security().map_err(|e| e.to_string())?;
                            let paired = control.settings().map_err(|e| e.to_string())?.paired;
                            Ok((security, paired))
                        })
                        .await,
                    ))
                }));
            }
            Message::Loaded(id, result) => {
                if !self.account_keys.finish(id) {
                    return Outcome::None;
                }
                self.busy = false;
                match result {
                    Ok((security, browsers)) => {
                        self.account_keys.security = Some(security);
                        self.account_keys.browsers = browsers;
                        self.account_keys.selected = None;
                        self.error = None;
                    }
                    Err(error) => self.error = Some(error),
                }
            }
            Message::Enroll | Message::Revoke if !self.busy => {
                let Some(index) = self.account_keys.selected else {
                    return Outcome::None;
                };
                let Some(browser) = self.account_keys.browsers.get(index) else {
                    return Outcome::None;
                };
                let Some(security) = &self.account_keys.security else {
                    return Outcome::None;
                };
                let provider = session
                    .browser_control()
                    .account_ceremony_provider(browser.public_key.clone());
                let facade = session.facade();
                let revoke = matches!(message, Message::Revoke);
                let name = self.account_keys.name.trim().to_owned();
                if !revoke && (name.is_empty() || name.len() > 128) {
                    return Outcome::None;
                }
                let id = self.account_keys.confirm_revoke.clone();
                if revoke && id.is_none() {
                    return Outcome::None;
                }
                let authorization = if security.descriptor.is_some() {
                    PasskeyEnrollmentAuthorization::EstablishedCustody
                } else if !security.credentials.is_empty() {
                    PasskeyEnrollmentAuthorization::ExistingPasskey
                } else {
                    let password =
                        match LoginPassword::new(std::mem::take(&mut self.account_keys.password)) {
                            Ok(password) => password,
                            Err(error) => {
                                self.error = Some(error.to_string());
                                return Outcome::None;
                            }
                        };
                    PasskeyEnrollmentAuthorization::ServerPassword(password)
                };
                let mode = if self.account_keys.auth_only {
                    PasskeyMode::AuthOnly
                } else {
                    PasskeyMode::VaultUnlock
                };
                let request_id = self.account_keys.begin();
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    super::Message::AccountKeys(Message::Finished(
                        request_id,
                        off_thread(move || {
                            if revoke {
                                facade
                                    .revoke_account_passkey(
                                        id.expect("confirmed credential"),
                                        provider,
                                    )
                                    .map_err(|e| e.to_string())?;
                            } else {
                                facade
                                    .enroll_account_passkey(name, mode, authorization, provider)
                                    .map_err(|e| e.to_string())?;
                            }
                            Ok(())
                        })
                        .await,
                    ))
                }));
            }
            Message::Finished(id, result) => {
                if !self.account_keys.finish(id) {
                    return Outcome::None;
                }
                self.busy = false;
                self.account_keys.confirm_revoke = None;
                match result {
                    Ok(()) => {
                        self.account_keys.code = None;
                        return self.update_account_keys(Message::Refresh, session);
                    }
                    Err(error) => self.error = Some(error),
                }
            }
            _ => {}
        }
        Outcome::None
    }
}

impl Drop for AccountKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.code_confirmation.zeroize();
    }
}

impl AccountKeys {
    fn begin(&mut self) -> u64 {
        let id = crate::backend::next_view_request();
        self.active = Some(id);
        id
    }
    fn finish(&mut self, id: u64) -> bool {
        if self.active != Some(id) {
            return false;
        }
        self.active = None;
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_account_security_completion_cannot_replace_a_new_settings_operation() {
        let root = tempfile::tempdir().unwrap();
        let (session, _) = Session::open_at(root.path().join("local.sqlite")).unwrap();
        let mut state = State::new(DevicePreferences::default(), false, root.path().into());
        let stale = state.account_keys.begin();
        let current = state.account_keys.begin();
        state.busy = true;
        state.update_account_keys(
            Message::Finished(stale, Err("stale failure".into())),
            &session,
        );
        assert!(state.busy);
        assert!(state.error.is_none());
        assert_eq!(state.account_keys.active, Some(current));
        state.update_account_keys(
            Message::Finished(current, Err("current failure".into())),
            &session,
        );
        assert!(!state.busy);
        assert_eq!(state.error.as_deref(), Some("current failure"));
    }
}
