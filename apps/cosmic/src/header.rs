//! The header bar's app menu.
use super::*;

impl App {
    /// App-level actions live beside the nav toggle instead of taking room
    /// from the item list. The menu stays the same shape while commands that
    /// do not apply to the current screen become disabled.
    pub(super) fn header_menu(&self) -> Vec<Element<'_, Message>> {
        if matches!(self.shell, Shell::Blocked(_)) {
            return Vec::new();
        }

        let command = |label: &str, icon: &str, action: Action| {
            let button = if self.command_enabled(action) {
                menu::Item::Button
            } else {
                menu::Item::ButtonDisabled
            };
            button(
                t(label),
                Some(widget::icon::from_name(icon).handle()),
                action,
            )
        };
        let items = menu::items(
            key_binds(),
            vec![
                command("common.create", "list-add-symbolic", Action::Create),
                command("common.edit", "edit-symbolic", Action::Edit),
                command(
                    "items.searchPlaceholder",
                    "system-search-symbolic",
                    Action::Search,
                ),
                command(
                    "settings.accounts.syncNow",
                    "view-refresh-symbolic",
                    Action::Sync,
                ),
                menu::Item::Divider,
                command("common.lock", "system-lock-screen-symbolic", Action::Lock),
                command(
                    "common.settings",
                    "preferences-system-symbolic",
                    Action::Settings,
                ),
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
            .item_height(menu::ItemHeight::Dynamic(36))
            .into()]
    }
}
