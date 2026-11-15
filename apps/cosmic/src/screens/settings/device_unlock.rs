//! Device unlock methods and enrolled hardware keys.
use super::*;

impl State {
    pub(super) fn unlock_section(&self) -> Option<Element<'_, Message>> {
        let remembered = self.remembered.as_ref()?;
        let status = match remembered.source.as_str() {
            "hardware_key" => t("settings.unlockSourceHardwareKey"),
            _ if remembered.armed => t("settings.unlockSourceKeystore"),
            _ => t("unlock.placeholder"),
        };
        let mut section = widget::settings::section()
            .title(t("settings.keystore"))
            .add(widget::text::body(status));

        if remembered.hardware_supported {
            for (index, key) in remembered.hardware_keys.iter().enumerate() {
                let mut remove = widget::button::text(t("common.delete"));
                if !self.unlock_busy {
                    remove = remove.on_press(Message::Remove(key.credential_id.clone()));
                }
                section = section.add(
                    widget::settings::item::builder(format!("{} · {}", key.label, index + 1))
                        .description(crate::i18n::format_timestamp(&key.enrolled_at))
                        .control(remove),
                );
            }
            let mut enroll = widget::button::standard(if self.enrolling {
                t("settings.hardwareKeyTouch")
            } else {
                t("settings.hardwareKeyEnrol")
            });
            if !self.unlock_busy {
                enroll = enroll.on_press(Message::Enroll);
            }
            section = section.add(
                widget::settings::item::builder(t("settings.hardwareKeyEnrol"))
                    .description(t("settings.hardwareKeyBackupHint"))
                    .control(enroll),
            );
        }

        let mut source = widget::button::standard(if remembered.armed {
            t("settings.forgetDevice")
        } else {
            t("unlock.remember")
        });
        if !self.unlock_busy {
            source = source.on_press(if remembered.armed {
                Message::Forget
            } else {
                Message::UseKeystore
            });
        }
        Some(
            section
                .add(
                    widget::settings::item::builder(t("settings.unlockSourceKeystore"))
                        .control(source),
                )
                .into(),
        )
    }
}
