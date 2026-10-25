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
        self.core.set_main_window_id(None);
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
