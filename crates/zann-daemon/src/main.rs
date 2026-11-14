//! Standalone composition. Master passwords are read with terminal echo off;
//! no browser IPC command can unlock, select a vault, or approve a pairing.
use std::io::{self, Write};
use std::path::PathBuf;
use zann_client_sqlite::local_vault::{open_vault_at_path, LocalVaultPorts};
use zann_daemon::Daemon;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--database")) {
        return Err("usage: zann-daemon --database ABSOLUTE_PATH".into());
    }
    let database = PathBuf::from(args.next().ok_or("missing database path")?);
    if args.next().is_some() {
        return Err("unexpected daemon argument".into());
    }
    let vault = open_vault_at_path(&database, LocalVaultPorts::system_default())?;
    let daemon = Daemon::start(vault.client_paths(), vault.clone())?;
    let control = daemon.control();
    println!("Zann local daemon. Server key: {}", daemon.server_key());
    println!(
        "Commands: settings, pair, revoke PUBLIC_KEY, unlock, lock, storage ID, vault ID, quit"
    );
    loop {
        print!("zann> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim();
        match line {
            "quit" => break,
            "unlock" => {
                vault.unlock(rpassword::prompt_password("Master password: ")?)?;
            }
            "lock" => {
                vault.lock()?;
            }
            "settings" => {
                let settings = control.settings()?;
                for pair in settings.paired {
                    println!("Paired: {}  {}", pair.public_key, pair.name);
                }
            }
            "pair" => {
                let code = control.begin_pairing()?;
                // Deliberate local UI display, not a log/diagnostic or argv value.
                println!(
                    "Enter in the Zann extension (valid {} seconds): {}",
                    code.expires_in_seconds,
                    code.value.as_str()
                );
            }
            value if value.starts_with("revoke ") => control.revoke(&value[7..])?,
            value if value.starts_with("storage ") => {
                vault.set_current_storage(value[8..].into())?
            }
            value if value.starts_with("vault ") => {
                vault.set_current_vault(value[6..].into())?;
            }
            _ => println!("Unknown command"),
        }
    }
    vault.lock()?;
    daemon.shutdown()?;
    Ok(())
}
