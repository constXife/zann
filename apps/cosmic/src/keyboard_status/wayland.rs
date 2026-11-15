//! COSMIC's layout protocol reports groups even without a focused surface.
use cosmic::cctk::{
    cosmic_protocols::keyboard_layout::v1::client::{
        zcosmic_keyboard_layout_manager_v1::ZcosmicKeyboardLayoutManagerV1 as Manager,
        zcosmic_keyboard_layout_v1::{self, ZcosmicKeyboardLayoutV1 as Layout},
    },
    sctk::reexports::{
        calloop::EventLoop,
        calloop_wayland_source::WaylandSource,
        client::{
            self,
            globals::registry_queue_init,
            protocol::{wl_keyboard, wl_registry, wl_seat},
            Connection, Dispatch, QueueHandle,
        },
    },
};
use std::{collections::HashMap, fs::File, os::unix::fs::FileExt, time::Duration};
use tokio::sync::watch;
use xkbcommon::xkb;

type Sender = watch::Sender<Option<Result<String, String>>>;
type Error = Box<dyn std::error::Error>;

struct Keyboard {
    proxy: wl_keyboard::WlKeyboard,
    layout: Layout,
    keymap: Option<xkb::Keymap>,
    group: Option<u32>,
}
struct Monitor {
    sender: Sender,
    manager: Manager,
    keyboards: HashMap<u32, Keyboard>,
}

pub(super) fn observe(sender: &Sender) -> Result<(), Error> {
    let connection = Connection::connect_to_env()?;
    let (globals, queue) = registry_queue_init::<Monitor>(&connection)?;
    let qh = queue.handle();
    let manager = globals.bind(&qh, 1..=1, ())?;
    let mut state = Monitor {
        sender: sender.clone(),
        manager,
        keyboards: HashMap::new(),
    };
    for global in globals.contents().clone_list() {
        if global.interface == "wl_seat" {
            globals.registry().bind::<wl_seat::WlSeat, _, _>(
                global.name,
                global.version.min(7),
                &qh,
                global.name,
            );
        }
    }
    let mut event_loop = EventLoop::<Monitor>::try_new()?;
    WaylandSource::new(connection, queue)
        .insert(event_loop.handle())
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    // Bounded dispatch also releases the connection when the subscription ends.
    while !sender.is_closed() {
        event_loop.dispatch(Duration::from_millis(250), &mut state)?;
    }
    Ok(())
}

impl Monitor {
    fn publish(&self, seat: u32) {
        let Some(keyboard) = self.keyboards.get(&seat) else {
            return;
        };
        if let (Some(keymap), Some(group)) = (&keyboard.keymap, keyboard.group) {
            if group < keymap.num_layouts() {
                self.sender
                    .send_replace(Some(Ok(keymap.layout_get_name(group).to_string())));
            } else {
                self.sender.send_replace(Some(Err(
                    "compositor supplied an invalid keyboard group".into(),
                )));
            }
        }
    }
}

impl Dispatch<wl_registry::WlRegistry, client::globals::GlobalListContents> for Monitor {
    fn event(
        state: &mut Self,
        registry: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _: &client::globals::GlobalListContents,
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        match event {
            wl_registry::Event::Global {
                name,
                interface,
                version,
            } if interface == "wl_seat" => {
                registry.bind::<wl_seat::WlSeat, _, _>(name, version.min(7), qh, name);
            }
            wl_registry::Event::GlobalRemove { name } => {
                if let Some(keyboard) = state.keyboards.remove(&name) {
                    keyboard.layout.destroy();
                    keyboard.proxy.release();
                    state
                        .sender
                        .send_replace(Some(Err("keyboard seat was removed".into())));
                }
            }
            _ => {}
        }
    }
}

impl Dispatch<wl_seat::WlSeat, u32> for Monitor {
    fn event(
        state: &mut Self,
        seat: &wl_seat::WlSeat,
        event: wl_seat::Event,
        id: &u32,
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_seat::Event::Capabilities {
            capabilities: client::WEnum::Value(capabilities),
        } = event
        {
            if capabilities.contains(wl_seat::Capability::Keyboard) {
                state.keyboards.entry(*id).or_insert_with(|| {
                    let proxy = seat.get_keyboard(qh, *id);
                    let layout = state.manager.get_keyboard_layout(&proxy, qh, *id);
                    Keyboard {
                        proxy,
                        layout,
                        keymap: None,
                        group: None,
                    }
                });
            } else if let Some(keyboard) = state.keyboards.remove(id) {
                keyboard.layout.destroy();
                keyboard.proxy.release();
            }
        }
    }
}

impl Dispatch<wl_keyboard::WlKeyboard, u32> for Monitor {
    fn event(
        state: &mut Self,
        _: &wl_keyboard::WlKeyboard,
        event: wl_keyboard::Event,
        seat: &u32,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let wl_keyboard::Event::Keymap { format, fd, size } = event {
            let result = (|| -> Result<xkb::Keymap, Error> {
                if format != client::WEnum::Value(wl_keyboard::KeymapFormat::XkbV1)
                    || size > 1024 * 1024
                {
                    return Err("unsupported or oversized compositor keymap".into());
                }
                read_keymap(File::from(fd), size)
            })();
            match result {
                Ok(keymap) => {
                    if let Some(keyboard) = state.keyboards.get_mut(seat) {
                        keyboard.keymap = Some(keymap);
                    }
                    state.publish(*seat);
                }
                Err(error) => {
                    state
                        .sender
                        .send_replace(Some(Err(format!("keyboard keymap: {error}"))));
                }
            }
        }
    }
}
impl Dispatch<Layout, u32> for Monitor {
    fn event(
        state: &mut Self,
        _: &Layout,
        event: zcosmic_keyboard_layout_v1::Event,
        seat: &u32,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let zcosmic_keyboard_layout_v1::Event::Group { group } = event {
            if let Some(keyboard) = state.keyboards.get_mut(seat) {
                keyboard.group = Some(group);
            }
            state.publish(*seat);
        }
    }
}
client::delegate_noop!(Monitor: ignore Manager);

fn read_keymap(file: File, size: u32) -> Result<xkb::Keymap, Error> {
    // SCM_RIGHTS shares the open-file offset with the compositor. COSMIC may
    // leave it at EOF; positional IO reads from zero without changing it.
    let mut bytes = vec![0; size as usize];
    file.read_exact_at(&mut bytes, 0)?;
    let text = std::str::from_utf8(&bytes)?;
    let context = xkb::Context::new(xkb::CONTEXT_NO_FLAGS);
    xkb::Keymap::new_from_string(
        &context,
        text.trim_end_matches('\0').to_string(),
        xkb::KEYMAP_FORMAT_TEXT_V1,
        xkb::KEYMAP_COMPILE_NO_FLAGS,
    )
    .ok_or_else(|| "invalid compositor keymap".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, Write};

    #[test]
    fn reads_keymap_from_zero_without_changing_the_shared_eof_offset() {
        let text = concat!(
            "xkb_keymap {\n",
            "xkb_keycodes { minimum = 8; maximum = 255; <SPCE> = 65; };\n",
            "xkb_types { type \"ONE_LEVEL\" { modifiers = none; }; };\n",
            "xkb_compatibility {};\n",
            "xkb_symbols { name[Group1] = \"English (US)\"; ",
            "key <SPCE> { [ space ] }; };\n",
            "};\n\0"
        );
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(text.as_bytes()).unwrap();
        let shared = file.try_clone().unwrap();
        let keymap = read_keymap(shared, text.len() as u32).unwrap();
        assert_eq!(keymap.layout_get_name(0), "English (US)");
        assert_eq!(file.stream_position().unwrap(), text.len() as u64);
    }

    #[test]
    fn truncated_keymap_is_reported_as_an_io_error() {
        let file = tempfile::tempfile().unwrap();
        let error = read_keymap(file, 10).err().expect("truncated keymap");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    #[ignore = "requires a running COSMIC Wayland compositor"]
    fn live_compositor_reports_a_keymap_and_group_without_receiving_key_text() {
        let (sender, mut receiver) = watch::channel(None);
        let worker = std::thread::spawn(move || {
            if let Err(error) = observe(&sender) {
                sender.send_replace(Some(Err(error.to_string())));
            }
        });
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(3), receiver.changed())
                    .await
                    .expect("compositor timeout")
                    .expect("layout monitor closed");
                receiver.borrow_and_update().clone().expect("layout result")
            });
        drop(receiver);
        worker.join().unwrap();
        assert!(!result.expect("COSMIC layout protocol").is_empty());
    }
}
