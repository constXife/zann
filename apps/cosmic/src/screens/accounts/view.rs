use super::*;
impl State {
    pub fn view(&self) -> Element<'_, Message> {
        let mut form = widget::column::with_capacity(12)
            .spacing(theme::spacing().space_s)
            .width(Length::Fixed(520.0))
            .push(widget::text::title3(t("recovery.title")));
        if let Some(preview) = &self.preview {
            form = form.push(widget::text::body(t(if self.selected.is_some() {
                "recovery.accountWarning"
            } else {
                "recovery.deviceWarning"
            })));
            if let Some(account) = self
                .accounts
                .iter()
                .find(|a| Some(&a.location.storage_id) == self.selected.as_ref())
            {
                form = form.push(widget::text::body(account.location.server_url.clone()));
                if let Some(name) = &account.location.account_name {
                    form = form.push(widget::text::body(name.clone()));
                }
            }
            form = form.push(widget::text::body(t_args(
                "recovery.counts",
                &[
                    ("accounts", &preview.accounts.to_string()),
                    ("items", &preview.items.to_string()),
                    ("pending", &preview.pending.to_string()),
                    ("dirty", &preview.dirty.to_string()),
                    ("history", &preview.local_history.to_string()),
                ],
            )));
            if preview.has_unsent() {
                form = form.push(
                    widget::checkbox(self.discard)
                        .label(t("recovery.confirmUnsent"))
                        .on_toggle(Message::Discard),
                );
            }
            let mut confirm = widget::button::destructive(t("recovery.confirm"));
            if !self.busy && (!preview.has_unsent() || self.discard) {
                confirm = confirm.on_press(Message::Confirm);
            }
            let mut cancel = widget::button::standard(t("common.cancel"));
            if !self.busy {
                cancel = cancel.on_press(Message::Cancel);
            }
            form = form.push(
                widget::row::with_capacity(2)
                    .push(cancel)
                    .push(confirm)
                    .spacing(theme::spacing().space_s),
            );
        } else {
            form = form.push(widget::text::body(t("recovery.help")));
            let mut list = widget::column::with_capacity(self.accounts.len() * 5)
                .spacing(theme::spacing().space_s);
            for account in &self.accounts {
                list = list
                    .push(widget::text::heading(account.location.name.clone()))
                    .push(widget::text::caption(account.location.server_url.clone()));
                if let Some(name) = &account.location.account_name {
                    list = list.push(widget::text::body(name.clone()));
                }
                let id = &account.location.storage_id;
                let mut open = widget::button::standard(t(if account.enrolled {
                    "recovery.openAccount"
                } else {
                    "recovery.enrollAccount"
                }));
                let mut remove = widget::button::destructive(t("recovery.removeAccount"));
                if !self.busy {
                    open = open.on_press(Message::Choose(id.clone()));
                    remove = remove.on_press(Message::Prepare(Some(id.clone())));
                }
                list = list.push(
                    widget::row::with_capacity(2)
                        .push(open)
                        .push(remove)
                        .spacing(theme::spacing().space_s),
                );
            }
            form = form.push(widget::scrollable(list).height(Length::Fixed(280.0)));
            let mut connect = widget::button::standard(t("wizard.connect"));
            let mut reset = widget::button::destructive(t("recovery.resetDevice"));
            if !self.busy {
                connect = connect.on_press(Message::Connect);
                reset = reset.on_press(Message::Prepare(None));
            }
            form = form.push(connect).push(reset);
        }
        if self.busy {
            form = form.push(widget::text::caption(t("common.loading")));
        }
        if let Some(error) = &self.error {
            form = form.push(widget::text::body(error.clone()));
        }
        if let Some(snapshot) = &self.snapshot {
            form = form
                .push(widget::text::caption(t("recovery.snapshotSaved")))
                .push(widget::text::caption(snapshot.clone()));
        }
        centered(form)
    }
}
