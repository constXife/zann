//! The settings screen.
//!
//! Sections, names and choices are the desktop app's settings modal, in the
//! COSMIC idiom: `widget::settings::section` rows, so it reads like the system
//! settings rather than like a modal borrowed from a web app.
//!
//! Two of the desktop's five tabs are missing, and deliberately. Backups sits
//! on `backup_export_file` / `backup_import_file`, which `zann-ffi` answers
//! with `Unimplemented` — the desktop does that work on its own side. And the
//! keystore block under Security is inert on Linux for both clients:
//! `zann-keystore` only implements macOS, so its status is `supported: false`
//! here and every control under it would be greyed out.

use cosmic::iced::{Alignment, Length};
use cosmic::{theme, widget, Element};
use zann_ffi::StorageSummaryFfi;

use crate::i18n::t;
use crate::settings::{Change, Settings};
use zann_ui_core::LANGUAGES;

/// Minutes, paired with what to call them. The desktop app's choices.
const AUTO_LOCK: &[(u32, &str)] = &[
    (0, "Never"),
    (1, "1 minute"),
    (5, "5 minutes"),
    (10, "10 minutes"),
    (30, "30 minutes"),
    (60, "1 hour"),
];

const CLIPBOARD: &[(u32, &str)] = &[
    (0, "Never"),
    (15, "15 seconds"),
    (30, "30 seconds"),
    (60, "60 seconds"),
    (120, "2 minutes"),
    (300, "5 minutes"),
];

const REVEAL: &[(u32, &str)] = &[
    (0, "Never"),
    (10, "10 seconds"),
    (30, "30 seconds"),
    (60, "60 seconds"),
];

const DOCS_URL: &str = "https://docs.zann.app";
const SOURCE_URL: &str = "https://github.com/constxife/zann";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    General,
    Security,
    Accounts,
    About,
}

impl Section {
    const ALL: &'static [Self] = &[Self::General, Self::Security, Self::Accounts, Self::About];

    fn label(self) -> String {
        t(match self {
            Self::General => "settings.tabs.general",
            Self::Security => "settings.tabs.security",
            Self::Accounts => "settings.tabs.accounts",
            Self::About => "settings.tabs.about",
        })
    }

    fn icon(self) -> &'static str {
        match self {
            Self::General => "preferences-system-symbolic",
            Self::Security => "channel-secure-symbolic",
            Self::Accounts => "system-users-symbolic",
            Self::About => "help-about-symbolic",
        }
    }
}

pub struct State {
    section: Section,
    settings: Settings,
    /// Servers and local vaults, for the Accounts section.
    storages: Vec<StorageSummaryFfi>,
    error: Option<String>,
    syncing: bool,
}

#[derive(Clone, Debug)]
pub enum Message {
    Select(Section),
    Set(Change),
    SyncNow(String),
    Synced(Result<(), String>),
    AddServer,
    OpenUrl(String),
    Close,
}

pub enum Outcome {
    None,
    Task(cosmic::iced::Task<Message>),
    /// A setting changed; the shell owns persisting it and acting on it.
    Changed(Change),
    /// The vault is the shell's, so a sync is asked for rather than run here.
    Sync(String),
    /// Effects that leave the app, which are the shell's.
    OpenUrl(String),
    /// Straight to the connect screen, the way the desktop's "Add server" does.
    AddServer,
    Close,
}

impl State {
    pub fn new(settings: Settings, storages: Vec<StorageSummaryFfi>) -> Self {
        Self {
            section: Section::General,
            settings,
            storages,
            error: None,
            syncing: false,
        }
    }

    /// The shell persists the change, so the screen is told what stuck rather
    /// than assuming its own copy is authoritative.
    pub fn settings_changed(&mut self, settings: Settings) {
        self.settings = settings;
    }

    pub fn update(&mut self, message: Message) -> Outcome {
        match message {
            Message::Select(section) => {
                self.section = section;
                Outcome::None
            }
            Message::Set(change) => Outcome::Changed(change),
            Message::SyncNow(storage_id) => {
                if self.syncing {
                    return Outcome::None;
                }
                self.syncing = true;
                self.error = None;
                Outcome::Sync(storage_id)
            }
            Message::Synced(result) => {
                self.syncing = false;
                self.error = result.err();
                Outcome::None
            }
            Message::AddServer => Outcome::AddServer,
            Message::OpenUrl(url) => Outcome::OpenUrl(url),
            Message::Close => Outcome::Close,
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();

        let mut sections =
            widget::column::with_capacity(Section::ALL.len()).spacing(spacing.space_xxs);
        for section in Section::ALL {
            sections = sections.push(
                widget::button::custom(
                    widget::row::with_capacity(2)
                        .push(widget::icon::from_name(section.icon()).size(16).icon())
                        .push(widget::text::body(section.label()))
                        .spacing(spacing.space_xs)
                        .align_y(Alignment::Center),
                )
                .class(if *section == self.section {
                    theme::Button::Suggested
                } else {
                    theme::Button::Text
                })
                .width(Length::Fill)
                .on_press(Message::Select(*section)),
            );
        }

        let body = match self.section {
            Section::General => self.general(),
            Section::Security => self.security(),
            Section::Accounts => self.accounts(),
            Section::About => self.about(),
        };

        let header = widget::row::with_capacity(2)
            .push(widget::text::title3(t("settings.title")).width(Length::Fill))
            .push(
                widget::button::icon(widget::icon::from_name("window-close-symbolic"))
                    .on_press(Message::Close),
            )
            .align_y(Alignment::Center);

        let columns = widget::row::with_capacity(3)
            .push(widget::container(sections).width(Length::Fixed(180.0)))
            .push(widget::divider::vertical::default())
            .push(
                widget::scrollable(body)
                    .width(Length::Fill)
                    .height(Length::Fill),
            )
            .spacing(spacing.space_s)
            .height(Length::Fill);

        widget::column::with_capacity(2)
            .push(header)
            .push(columns)
            .spacing(spacing.space_s)
            .padding(spacing.space_s)
            .into()
    }

    fn general(&self) -> Element<'_, Message> {
        // The first entry is "follow the environment", which is what an unset
        // preference means, so its index is one ahead of the language list.
        let mut languages = Vec::with_capacity(LANGUAGES.len() + 1);
        languages.push(t("settings.general.languageSystem"));
        languages.extend(LANGUAGES.iter().map(|(_, name)| (*name).to_string()));
        let selected = self.settings.language.as_deref().map_or(0, |chosen| {
            LANGUAGES
                .iter()
                .position(|(tag, _)| *tag == chosen)
                .map_or(0, |index| index + 1)
        });

        let appearance = widget::settings::section()
            .title(t("settings.general.appearance"))
            .add(
                widget::settings::item::builder(t("settings.general.language")).control(
                    widget::dropdown(languages, Some(selected), |index| {
                        Message::Set(Change::Language(
                            index.checked_sub(1).map(|index| LANGUAGES[index].0),
                        ))
                    }),
                ),
            );

        let behavior = widget::settings::section()
            .title(t("settings.general.behavior"))
            .add(
                widget::settings::item::builder(t("settings.general.closeToTray"))
                    .description(t("settings.general.closeToTrayHelp"))
                    .toggler(self.settings.close_to_tray, |value| {
                        Message::Set(Change::CloseToTray(value))
                    }),
            );

        widget::settings::view_column(vec![appearance.into(), behavior.into()]).into()
    }

    fn security(&self) -> Element<'_, Message> {
        let settings = &self.settings;

        let auto_lock = widget::settings::section()
            .title(t("settings.autolock"))
            .add(
                widget::settings::item::builder(t("settings.autolockAfter")).control(choice(
                    AUTO_LOCK,
                    settings.auto_lock_minutes,
                    |value| Message::Set(Change::AutoLockMinutes(value)),
                )),
            )
            .add(
                widget::settings::item::builder(t("settings.lockOnHidden"))
                    .toggler(settings.lock_on_hidden, |value| {
                        Message::Set(Change::LockOnHidden(value))
                    }),
            )
            .add(
                widget::settings::item::builder(t("settings.lockOnFocusLoss"))
                    .toggler(settings.lock_on_focus_loss, |value| {
                        Message::Set(Change::LockOnFocusLoss(value))
                    }),
            );

        let clipboard = widget::settings::section()
            .title(t("settings.clipboard"))
            .add(
                widget::settings::item::builder(t("settings.clipboardAfter")).control(choice(
                    CLIPBOARD,
                    settings.clipboard_clear_seconds,
                    |value| Message::Set(Change::ClipboardSeconds(value)),
                )),
            )
            .add(
                widget::settings::item::builder(t("settings.clipboardOnLock"))
                    .toggler(settings.clipboard_clear_on_lock, |value| {
                        Message::Set(Change::ClipboardOnLock(value))
                    }),
            )
            .add(
                widget::settings::item::builder(t("settings.clipboardOnExit"))
                    .toggler(settings.clipboard_clear_on_exit, |value| {
                        Message::Set(Change::ClipboardOnExit(value))
                    }),
            )
            .add(
                widget::settings::item::builder(t("settings.clipboardIfUnchanged"))
                    .toggler(settings.clipboard_clear_if_unchanged, |value| {
                        Message::Set(Change::ClipboardIfUnchanged(value))
                    }),
            );

        let reveal = widget::settings::section().title(t("settings.reveal")).add(
            widget::settings::item::builder(t("settings.revealAfter")).control(choice(
                REVEAL,
                settings.auto_hide_reveal_seconds,
                |value| Message::Set(Change::AutoHideRevealSeconds(value)),
            )),
        );

        widget::settings::view_column(vec![auto_lock.into(), clipboard.into(), reveal.into()])
            .into()
    }

    fn accounts(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut servers =
            widget::settings::section().title(t("settings.accounts.connectedServers"));

        if self.storages.is_empty() {
            servers = servers.add(widget::text::body(t("settings.accounts.noServers")));
        }
        for storage in &self.storages {
            let mut sync = widget::button::standard(t("settings.accounts.syncNow"));
            if !self.syncing {
                sync = sync.on_press(Message::SyncNow(storage.id.clone()));
            }
            servers = servers.add(
                widget::settings::item::builder(storage.name.clone())
                    .description(storage.id.clone())
                    .control(sync),
            );
        }

        servers = servers.add(
            widget::settings::item::builder(t("storage.addServer"))
                .control(widget::button::standard(t("common.create")).on_press(Message::AddServer)),
        );

        let mut column = widget::settings::view_column(vec![servers.into()]);
        if let Some(error) = self.error.as_ref() {
            column = column.push(widget::text::caption(error.clone()));
        }

        column.spacing(spacing.space_s).into()
    }

    fn about(&self) -> Element<'_, Message> {
        let data = crate::backend::client_root(&crate::backend::default_db_url());
        let logs = data.join("logs");

        let app = widget::settings::section()
            .title(t("app.title"))
            .add(
                widget::settings::item::builder(t("settings.about.version"))
                    .control(widget::text::monotext(env!("CARGO_PKG_VERSION"))),
            )
            .add(
                widget::settings::item::builder(t("settings.about.openDataFolder"))
                    .description(data.display().to_string())
                    .control(
                        widget::button::standard(t("common.open"))
                            .on_press(Message::OpenUrl(data.display().to_string())),
                    ),
            )
            .add(
                widget::settings::item::builder(t("settings.about.viewLogs")).control(
                    widget::button::standard(t("common.open"))
                        .on_press(Message::OpenUrl(logs.display().to_string())),
                ),
            );

        let links = widget::settings::section()
            .title(t("settings.about.links"))
            .add(
                widget::settings::item::builder(t("settings.about.documentation")).control(
                    widget::button::standard(t("common.open"))
                        .on_press(Message::OpenUrl(DOCS_URL.to_string())),
                ),
            )
            .add(
                widget::settings::item::builder(t("settings.about.sourceCode")).control(
                    widget::button::standard(t("common.open"))
                        .on_press(Message::OpenUrl(SOURCE_URL.to_string())),
                ),
            );

        widget::settings::view_column(vec![app.into(), links.into()]).into()
    }
}

/// A dropdown over `(value, label)` pairs. An unknown stored value shows
/// nothing selected rather than silently becoming one of the choices.
fn choice(
    options: &'static [(u32, &'static str)],
    selected: u32,
    on_select: fn(u32) -> Message,
) -> Element<'static, Message> {
    let labels: Vec<&'static str> = options.iter().map(|(_, label)| *label).collect();
    let index = options.iter().position(|(value, _)| *value == selected);
    widget::dropdown(labels, index, move |index| on_select(options[index].0)).into()
}
