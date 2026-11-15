use super::*;

impl State {
    pub(in crate::screens::settings) fn browser_section(
        &self,
    ) -> Element<'_, super::super::Message> {
        let mut section = widget::settings::section()
            .title(t("browser.title"))
            .add(widget::text::caption(t("browser.codeHint")))
            .add(
                widget::button::suggested(t("browser.connect")).on_press_maybe(
                    (!self.busy).then_some(super::super::Message::Browser(Message::Begin)),
                ),
            )
            .add(
                widget::button::standard(t("browser.refresh"))
                    .on_press(super::super::Message::Browser(Message::Refresh)),
            );
        if let Some(active) = &self.browser_code {
            let remaining = active
                .expires
                .saturating_duration_since(Instant::now())
                .as_millis()
                .div_ceil(1000)
                .to_string();
            let copy = widget::button::standard(t(if active.copied() {
                "common.copied"
            } else {
                "browser.copyCode"
            }))
            .width(Length::Fixed(180.0))
            .on_press_maybe(
                (!self.busy && !active.copying && active.valid())
                    .then_some(super::super::Message::Browser(Message::Copy)),
            );
            section = section
                .add(
                    widget::row::with_capacity(2)
                        .push(
                            widget::text::title3(format!(
                                "{}: {}",
                                t("browser.code"),
                                active.code.value.as_str()
                            ))
                            .width(Length::Fill),
                        )
                        .push(copy)
                        .spacing(theme::spacing().space_s)
                        .align_y(Alignment::Center),
                )
                .add(widget::text::caption(t_args(
                    "browser.codeRemaining",
                    &[("seconds", &remaining)],
                )));
        }
        if let Some(settings) = &self.browser_pairings {
            for paired in &settings.paired {
                section = section.add(
                    widget::settings::item::builder(paired.name.clone())
                        .description(t("browser.connected"))
                        .control(widget::button::destructive(t("browser.revoke")).on_press(
                            super::super::Message::Browser(Message::Revoke(
                                paired.public_key.clone(),
                            )),
                        )),
                );
            }
        }
        section.into()
    }
}
