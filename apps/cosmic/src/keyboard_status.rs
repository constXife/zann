//! OS keyboard state only. No key text is inspected or retained.
mod wayland;

use crate::i18n::t;
use cosmic::iced::{futures::SinkExt, stream, Length, Subscription};
use cosmic::{widget, Element};

#[derive(Default)]
pub struct Status {
    layout: Option<Result<String, String>>,
    caps_lock: bool,
}

impl Status {
    pub fn layout_changed(&mut self, layout: Result<String, String>) {
        self.layout = Some(layout);
    }
    pub fn modifiers_changed(&mut self, modifiers: cosmic::iced::keyboard::Modifiers) {
        self.caps_lock = modifiers.contains(cosmic::iced::keyboard::Modifiers::CAPS_LOCK);
    }
    pub fn unfocused(&mut self) {
        self.caps_lock = false;
    }

    /// A reserved header slot avoids resizing the form as keyboard state changes.
    pub fn view<Message: 'static>(&self) -> Element<'_, Message> {
        let layout = match &self.layout {
            Some(Ok(name)) => visible_layout(name).unwrap_or_default().to_string(),
            Some(Err(_)) => t("keyboard.unavailable"),
            None => String::new(),
        };
        let row = widget::row::with_capacity(2)
            .push(widget::text::caption(layout))
            .push(widget::text::caption(if self.caps_lock {
                t("keyboard.capsLock")
            } else {
                String::new()
            }))
            .spacing(12)
            .width(Length::Fixed(240.0))
            .height(Length::Fixed(24.0));
        if let Some(Err(error)) = &self.layout {
            widget::tooltip(
                row,
                widget::text::body(error.clone()),
                widget::tooltip::Position::Bottom,
            )
            .into()
        } else {
            row.into()
        }
    }
}

fn visible_layout(name: &str) -> Option<&str> {
    // XKB supplies canonical layout names, including variants such as English (US).
    (!(name == "English" || name.starts_with("English ("))).then_some(name)
}

pub fn subscription() -> Subscription<Result<String, String>> {
    Subscription::run(|| {
        stream::channel(1, async |mut output| {
            let (sender, mut receiver) = tokio::sync::watch::channel(None);
            std::thread::spawn(move || {
                if let Err(error) = wayland::observe(&sender) {
                    sender.send_replace(Some(Err(format!("keyboard layout monitor: {error}"))));
                }
            });
            while receiver.changed().await.is_ok() {
                let latest = receiver.borrow_and_update().clone();
                if let Some(value) = latest {
                    if output.send(value).await.is_err() {
                        return;
                    }
                }
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn english_variants_are_hidden_and_other_layouts_are_preserved() {
        for name in ["English", "English (US)", "English (UK, Dvorak)"] {
            assert_eq!(visible_layout(name), None);
        }
        for name in ["Russian", "French (Canada)", "Georgian"] {
            assert_eq!(visible_layout(name), Some(name));
        }
    }
    #[test]
    fn caps_uses_authoritative_modifiers_including_on_focus_entry() {
        use cosmic::iced::keyboard::Modifiers;
        let mut status = Status::default();
        status.modifiers_changed(Modifiers::CAPS_LOCK | Modifiers::SHIFT);
        assert!(status.caps_lock);
        status.modifiers_changed(Modifiers::SHIFT);
        assert!(!status.caps_lock);
        status.modifiers_changed(Modifiers::CAPS_LOCK);
        status.unfocused();
        assert!(!status.caps_lock);
    }
}
