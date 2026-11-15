//! Native commands and their single keyboard/menu binding map.
use super::{keyboard, menu, vault, App, Message, Screen, Shell, Task};
use std::{collections::HashMap, sync::OnceLock};

/// Commands in the native header menu. Keeping these separate from messages
/// lets libcosmic pair them with their keyboard shortcuts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Action {
    Create,
    Edit,
    Sync,
    Search,
    Lock,
    Settings,
    Quit,
}

impl menu::Action for Action {
    type Message = Message;

    fn message(&self) -> Message {
        Message::Command(*self)
    }
}

/// Native application shortcuts. The menu reads this same map to
/// print the shortcut beside each command.
pub(super) fn key_binds() -> &'static HashMap<menu::KeyBind, Action> {
    static BINDS: OnceLock<HashMap<menu::KeyBind, Action>> = OnceLock::new();
    BINDS.get_or_init(|| {
        let bind = |character: &str| menu::KeyBind {
            modifiers: vec![menu::key_bind::Modifier::Ctrl],
            key: keyboard::Key::Character(character.into()),
        };
        HashMap::from([
            (bind("n"), Action::Create),
            (bind("e"), Action::Edit),
            (bind("r"), Action::Sync),
            (bind("f"), Action::Search),
            (bind("l"), Action::Lock),
            (bind(","), Action::Settings),
            (bind("q"), Action::Quit),
        ])
    })
}

impl App {
    pub(super) fn command_enabled(&self, action: Action) -> bool {
        match action {
            Action::Lock => self.is_unlocked(),
            Action::Settings => self.can_open_settings(),
            Action::Quit => true,
            _ => match &self.shell {
                Shell::Ready {
                    screen: Screen::Vault(state),
                    ..
                } => match action {
                    Action::Create => state.can_create(),
                    Action::Edit => state.can_edit(),
                    Action::Search => state.can_focus_search(),
                    Action::Sync => true,
                    _ => unreachable!(),
                },
                _ => false,
            },
        }
    }

    pub(super) fn execute_command(&mut self, action: Action) -> Task<Message> {
        if !self.command_enabled(action) {
            return Task::none();
        }
        let message = match action {
            Action::Create => Message::Vault(vault::Message::OpenCreate),
            Action::Edit => Message::Vault(vault::Message::OpenEdit),
            Action::Sync => Message::Vault(vault::Message::SyncNow),
            Action::Search => Message::Vault(vault::Message::FocusSearch),
            Action::Lock => Message::Lock,
            Action::Settings => Message::OpenSettings,
            Action::Quit => Message::Quit,
        };
        cosmic::Application::update(self, message)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Core, DevicePreferences, Session};
    use super::*;
    use keyboard::{
        key::{Code, Physical},
        Key, Modifiers,
    };

    #[test]
    fn workspace_shortcuts_work_in_russian_and_caps_lock_without_extra_modifiers() {
        for (code, russian, action) in [
            (Code::KeyN, "т", Action::Create),
            (Code::KeyE, "у", Action::Edit),
            (Code::KeyR, "к", Action::Sync),
            (Code::KeyF, "а", Action::Search),
        ] {
            let bind = key_binds()
                .iter()
                .find(|(_, candidate)| **candidate == action)
                .unwrap()
                .0;
            let key = Key::Character(russian.into());
            let physical = Physical::Code(code);
            assert!(bind.matches(
                Modifiers::CTRL | Modifiers::CAPS_LOCK,
                &key,
                Some(&physical)
            ));
            assert!(!bind.matches(Modifiers::CTRL | Modifiers::SHIFT, &key, Some(&physical)));
            assert!(!bind.matches(Modifiers::NONE, &key, Some(&physical)));
        }
    }

    #[test]
    fn workspace_commands_do_not_reach_the_vault_parked_behind_settings() {
        let directory = tempfile::tempdir().unwrap();
        let (session, _) = Session::open_at(directory.path().join("local.sqlite")).unwrap();
        let vault = vault::State::new(
            zann_cosmic::backend::local::ItemsPage {
                items: vec![],
                next_cursor: None,
                total: 0,
                counts: Default::default(),
            },
            None,
        );
        let mut app = App {
            core: Core::default(),
            shell: Shell::Ready {
                session,
                screen: Screen::Settings {
                    state: Box::new(crate::settings::State::new(
                        DevicePreferences::default(),
                        false,
                        directory.path().into(),
                    )),
                    vault: Box::new(vault),
                },
            },
            window_width: super::super::WINDOW_SIZE.width,
            last_activity: std::time::Instant::now(),
            idle_check_pending: false,
            preferences: DevicePreferences::default(),
            close_to_tray: false,
            tray_available: false,
            preference_store: None,
            clipboard: (String::new(), 0),
            keyboard_status: Default::default(),
        };
        for action in [Action::Create, Action::Edit, Action::Sync, Action::Search] {
            assert!(!app.command_enabled(action));
            assert!(
                cosmic::iced::runtime::task::into_stream(app.execute_command(action)).is_none()
            );
        }
        assert!(matches!(
            app.shell,
            Shell::Ready {
                screen: Screen::Settings { .. },
                ..
            }
        ));
    }
}
