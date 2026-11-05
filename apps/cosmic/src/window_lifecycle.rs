//! Window lifecycle and native activation for the COSMIC shell.
use super::*;

impl App {
    pub(super) fn close_window_to_tray(&mut self) -> Task<Message> {
        let lock = if self.preferences.lock_on_hidden {
            self.lock()
        } else {
            Task::none()
        };
        let Some(id) = self.core.main_window_id() else {
            return lock;
        };
        // Keep the main view addressable until Iced confirms Closed: it
        // rebuilds existing views before executing the returned close task.
        Task::batch([lock, window::close::<cosmic::Action<Message>>(id)])
    }

    pub(super) fn show_window(&mut self, activation_token: Option<String>) -> Task<Message> {
        if let Some(id) = self.core.main_window_id() {
            let restore = window::minimize::<cosmic::Action<Message>>(id, false);
            return if let Some(token) = activation_token {
                restore.chain(cosmic::iced::Task::done(cosmic::Action::Cosmic(
                    cosmic::app::Action::Activate(token),
                )))
            } else {
                restore
            };
        }

        let (id, open) = window::open(main_window_settings());
        self.core.set_main_window_id(Some(id));
        let title = self.set_window_title("zann".to_string(), id);
        let open = open.map(move |_| match &activation_token {
            Some(token) => cosmic::Action::Cosmic(cosmic::app::Action::Activate(token.clone())),
            None => cosmic::Action::None,
        });
        Task::batch([open, title])
    }
}

fn main_window_settings() -> window::Settings {
    let mut settings = window::Settings {
        size: WINDOW_SIZE,
        min_size: Some(WINDOW_MIN),
        decorations: false,
        transparent: true,
        exit_on_close_request: false,
        ..window::Settings::default()
    };
    #[cfg(target_os = "linux")]
    {
        settings.platform_specific.application_id =
            <App as cosmic::Application>::APP_ID.to_string();
    }
    settings
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic::iced::futures::{executor::block_on, StreamExt};
    use cosmic::iced::runtime::{self, Action as RuntimeAction};
    use cosmic::Application;

    fn first_action(task: Task<Message>) -> RuntimeAction<cosmic::Action<Message>> {
        block_on(runtime::task::into_stream(task).unwrap().next()).unwrap()
    }

    fn app_with_window() -> App {
        let mut core = Core::default();
        core.set_main_window_id(Some(window::Id::unique()));
        App {
            core,
            shell: Shell::Blocked("window lifecycle fixture".into()),
            window_width: WINDOW_SIZE.width,
            preferences: DevicePreferences::default(),
            close_to_tray: true,
            tray_available: true,
            preference_store: None,
            clipboard: (String::new(), 0),
        }
    }

    #[test]
    fn header_close_keeps_the_view_until_closed_then_tray_reopens() {
        let mut shell = cosmic::app::cosmic::Cosmic::new(app_with_window());
        for _ in 0..3 {
            let old_id = shell.app.core.main_window_id().unwrap();
            let close = shell.update(cosmic::Action::Cosmic(cosmic::app::Action::Close));

            // Iced rebuilds views after update, before executing window::close.
            // Clearing main_window_id here routes this view to view_window,
            // whose default implementation panics.
            drop(shell.view(old_id));
            assert!(matches!(
                first_action(close),
                RuntimeAction::Window(runtime::window::Action::Close(id)) if id == old_id
            ));
            let _ = shell.update(cosmic::Action::Cosmic(cosmic::app::Action::SurfaceClosed(
                old_id,
            )));
            assert_eq!(shell.app.core.main_window_id(), None);

            let _ = shell.update(cosmic::Action::App(Message::Tray(tray::Event::Open)));
            let new_id = shell
                .app
                .core
                .main_window_id()
                .expect("new window requested");
            assert_ne!(new_id, old_id);
            drop(shell.view(new_id));

            // Late close notifications must not clear the replacement window.
            let _ = shell.update(cosmic::Action::Cosmic(cosmic::app::Action::SurfaceClosed(
                old_id,
            )));
            let _ = shell.update(cosmic::Action::App(Message::Tray(tray::Event::Open)));
            assert_eq!(shell.app.core.main_window_id(), Some(new_id));
        }
    }

    #[test]
    fn header_and_compositor_close_use_the_same_tray_policy() {
        for (close_to_tray, tray_available) in [(true, true), (false, true), (true, false)] {
            for header in [false, true] {
                let mut app = app_with_window();
                app.close_to_tray = close_to_tray;
                app.tray_available = tray_available;
                let close = if header {
                    app.on_app_exit()
                        .expect("header close must reach the shell")
                } else {
                    Message::CloseRequested
                };
                let action = first_action(app.update(close));
                if close_to_tray && tray_available {
                    assert!(matches!(
                        action,
                        RuntimeAction::Window(runtime::window::Action::Close(_))
                    ));
                    assert!(app.core.main_window_id().is_some());
                } else {
                    assert!(matches!(action, RuntimeAction::Exit));
                }
            }
        }
    }
}
