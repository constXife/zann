//! The header bar: the app menu at its start, the sync indicator at its end.
use super::*;

impl App {
    /// App-level actions live beside the nav toggle instead of taking room
    /// from the item list. The menu stays the same shape while commands that
    /// do not apply to the current screen become disabled.
    pub(super) fn header_menu(&self) -> Vec<Element<'_, Message>> {
        if matches!(self.shell, Shell::Blocked(_)) {
            return Vec::new();
        }

        let lock = if self.is_unlocked() {
            menu::Item::Button
        } else {
            menu::Item::ButtonDisabled
        }(
            t("common.lock"),
            Some(widget::icon::from_name("system-lock-screen-symbolic").handle()),
            Action::Lock,
        );
        let settings = if self.can_open_settings() {
            menu::Item::Button
        } else {
            menu::Item::ButtonDisabled
        }(
            t("common.settings"),
            Some(widget::icon::from_name("preferences-system-symbolic").handle()),
            Action::Settings,
        );
        let items = menu::items(
            key_binds(),
            vec![
                lock,
                settings,
                menu::Item::Divider,
                menu::Item::Button(
                    t("common.quit"),
                    Some(widget::icon::from_name("application-exit-symbolic").handle()),
                    Action::Quit,
                ),
            ],
        );
        let root = widget::button::icon(widget::icon::from_name("open-menu-symbolic"))
            .class(cosmic::theme::Button::MenuRoot)
            .apply(Element::from)
            .apply(widget::RcElementWrapper::new);

        vec![menu::bar(vec![menu::Tree::with_children(root, items)])
            .item_width(menu::ItemWidth::Uniform(240))
            .item_height(menu::ItemHeight::Uniform(36))
            .into()]
    }

    /// The open vault's sync indicator, on every screen that keeps it.
    pub(super) fn header_sync_status(&self) -> Vec<Element<'_, Message>> {
        let Shell::Ready {
            screen: Screen::Vault(vault) | Screen::Settings { vault, .. },
            ..
        } = &self.shell
        else {
            return Vec::new();
        };
        vault
            .sync_indicator()
            .map(|indicator| indicator.map(Message::Vault))
            .into_iter()
            .collect()
    }
}
