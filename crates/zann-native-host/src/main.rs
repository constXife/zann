//! Stateless stdio <-> Unix-socket framing. Does not parse application messages,
//! authenticate clients, keep keys, decrypt, or retain secret values.
use std::io;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref() {
        Some(value) if value == "--root" => {
            let root = args.next().map(PathBuf::from).ok_or("--root needs an absolute path")?;
            zann_native_host::relay(&root)?;
        }
        Some(value) if value == "install" => {
            let root = args.next().map(PathBuf::from).ok_or("install needs a client root")?;
            let directory = args.next().map(PathBuf::from).ok_or("install needs a manifest directory")?;
            let browser = args.next().ok_or("install needs chromium or firefox")?;
            let extension = args.next().ok_or("install needs an explicit extension id")?;
            if args.next().is_some() { return Err("unexpected install arguments".into()); }
            zann_native_host::install(&root, &directory, &browser.to_string_lossy(), &extension.to_string_lossy())?;
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "usage: zann-native-host --root PATH | install ROOT MANIFEST_DIRECTORY chromium|firefox EXTENSION_ID").into()),
    }
    Ok(())
}
