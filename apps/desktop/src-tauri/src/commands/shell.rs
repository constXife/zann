use std::process::Command;

#[tauri::command]
pub fn open_external_url(url: String) -> Result<(), String> {
    if url.is_empty() {
        return Err("empty url".to_string());
    }
    if !is_safe_external_url(&url) {
        return Err("unsupported url scheme".to_string());
    }

    #[cfg(target_os = "linux")]
    {
        open_linux(&url)
    }

    #[cfg(not(target_os = "linux"))]
    {
        open::that(url.as_str()).map_err(|err| err.to_string())
    }
}

fn is_safe_external_url(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://") || url.starts_with("mailto:")
}

#[cfg(target_os = "linux")]
fn open_linux(url: &str) -> Result<(), String> {
    // Order matters. xdg-open is last because on KDE it delegates to kde-open
    // → KIO, which downloads HTTPS responses to ~/.cache/kioexec/krun/... and
    // opens the saved file with the default text/html handler — so the
    // browser ends up loading a stale `file://` snapshot of the IdP login
    // page without cookies or JS context. gio open dispatches via GLib/GIO
    // and skips KIO, which is what we want.
    let mut errors: Vec<String> = Vec::new();

    if let Ok(browser) = std::env::var("BROWSER") {
        for entry in browser.split(':') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            match Command::new(entry).arg(url).spawn() {
                Ok(_) => {
                    println!("[shell] launched browser via $BROWSER={entry}");
                    return Ok(());
                }
                Err(err) => errors.push(format!("$BROWSER `{entry}`: {err}")),
            }
        }
    }

    match Command::new("gio").arg("open").arg(url).status() {
        Ok(status) if status.success() => {
            println!("[shell] launched browser via gio open");
            return Ok(());
        }
        Ok(status) => errors.push(format!("gio open exited with {status}")),
        Err(err) => errors.push(format!("gio open: {err}")),
    }

    match Command::new("xdg-open").arg(url).status() {
        Ok(status) if status.success() => {
            println!("[shell] launched browser via xdg-open");
            return Ok(());
        }
        Ok(status) => errors.push(format!("xdg-open exited with {status}")),
        Err(err) => errors.push(format!("xdg-open: {err}")),
    }

    Err(format!(
        "no browser launcher succeeded: {}",
        errors.join("; ")
    ))
}
