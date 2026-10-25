//! Freedesktop StatusNotifierItem bridge for the COSMIC shell.
//!
//! This stays out of `main.rs` so the window shell only decides what an event
//! means. `ksni` speaks the D-Bus protocol directly and does not pull a second
//! GUI toolkit into the libcosmic process.

use cosmic::iced::futures::SinkExt;
use cosmic::iced::{stream, Subscription};
use ksni::TrayMethods;
use tokio::sync::watch;

use crate::i18n::t;

const APP_ID: &str = "com.rlyeh.zann.Cosmic";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Ready,
    Unavailable,
    Open,
    Quit,
}

struct ZannTray {
    sender: watch::Sender<Event>,
    open_label: String,
    quit_label: String,
}

impl ksni::Tray for ZannTray {
    fn id(&self) -> String {
        APP_ID.into()
    }

    fn title(&self) -> String {
        "Zann".into()
    }

    fn icon_name(&self) -> String {
        APP_ID.into()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.sender.send(Event::Open);
    }

    fn watcher_online(&self) {
        let _ = self.sender.send(Event::Ready);
    }

    fn watcher_offline(&self, _reason: ksni::OfflineReason) -> bool {
        let _ = self.sender.send(Event::Unavailable);
        true
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;

        vec![
            StandardItem {
                label: self.open_label.clone(),
                icon_name: "window-restore-symbolic".into(),
                activate: Box::new(|tray: &mut Self| {
                    let _ = tray.sender.send(Event::Open);
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: self.quit_label.clone(),
                icon_name: "application-exit-symbolic".into(),
                activate: Box::new(|tray: &mut Self| {
                    let _ = tray.sender.send(Event::Quit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

pub fn subscription() -> Subscription<Event> {
    Subscription::run(|| {
        stream::channel(8, async |mut output| {
            let (sender, mut receiver) = watch::channel(Event::Ready);
            let tray = ZannTray {
                sender,
                open_label: t("common.open"),
                quit_label: t("common.quit"),
            };

            let handle = match tray.spawn().await {
                Ok(handle) => handle,
                Err(error) => {
                    eprintln!("could not register the system tray icon: {error}");
                    let _ = output.send(Event::Unavailable).await;
                    return;
                }
            };
            if output.send(Event::Ready).await.is_err() {
                handle.shutdown().await;
                return;
            }

            while receiver.changed().await.is_ok() {
                let event = *receiver.borrow_and_update();
                if output.send(event).await.is_err() {
                    break;
                }
            }
            handle.shutdown().await;
            let _ = output.send(Event::Unavailable).await;
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ksni::Tray;
    #[test]
    fn watcher_loss_and_return_reach_the_window_owner_without_an_unbounded_queue() {
        let (sender, mut receiver) = watch::channel(Event::Ready);
        let tray = ZannTray {
            sender,
            open_label: "Open".into(),
            quit_label: "Quit".into(),
        };
        assert!(tray.watcher_offline(ksni::OfflineReason::No));
        assert_eq!(*receiver.borrow_and_update(), Event::Unavailable);
        tray.watcher_online();
        assert_eq!(*receiver.borrow_and_update(), Event::Ready);
    }
}
