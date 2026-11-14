//! An explicit installation destination, browser and extension id. No HOME
//! discovery or permissive manifest templates; stdout is never used by relay.
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

fn text(path: &Path) -> io::Result<&str> {
    path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "native manifest paths must be UTF-8",
        )
    })
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "installation path needs a parent",
        )
    })?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o777 != mode
                || metadata.len() != bytes.len() as u64
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "installation destination is not the expected owned artifact",
                ));
            }
            let mut existing = Vec::new();
            file.take(bytes.len() as u64 + 1)
                .read_to_end(&mut existing)?;
            if existing != bytes {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "installation destination has different content",
                ));
            }
            Ok(())
        }
        Err(e) => Err(e.error),
    }
}

pub fn install(
    root: &Path,
    destination: &Path,
    browser: &str,
    extension_id: &str,
) -> io::Result<()> {
    zann_client::native_messaging::socket_path(root)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir()
        || root_metadata.uid() != unsafe { libc::geteuid() }
        || root_metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "client root must be resolved, owned and private",
        ));
    }
    if !root.is_absolute() || !destination.is_absolute() || !root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "installation requires absolute existing client root and manifest directory",
        ));
    }
    let valid = match browser {
        "chromium" => {
            extension_id.len() == 32 && extension_id.bytes().all(|b| (b'a'..=b'p').contains(&b))
        }
        "firefox" => {
            !extension_id.is_empty()
                && extension_id.len() <= 128
                && extension_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"@._-{}".contains(&b))
        }
        _ => false,
    };
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "explicit browser and extension id required",
        ));
    }
    let executable = std::env::current_exe()?;
    let wrapper_dir = root.join("native-messaging");
    match fs::DirBuilder::new().mode(0o700).create(&wrapper_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let meta = fs::symlink_metadata(&wrapper_dir)?;
            if !meta.is_dir()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.permissions().mode() & 0o077 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "native host directory must be private",
                ));
            }
        }
        Err(e) => return Err(e),
    }
    let wrapper = wrapper_dir.join(format!("{browser}-host"));
    let script = format!(
        "#!/bin/sh\nexec {} --root {} \"$@\"\n",
        quote(text(&executable)?),
        quote(text(root)?)
    );
    write_new(&wrapper, script.as_bytes(), 0o700)?;
    let mut manifest = serde_json::json!({"name":"com.rlyeh.zann", "description":"Zann authenticated local browser bridge", "path":text(&wrapper)?, "type":"stdio"});
    if browser == "chromium" {
        manifest["allowed_origins"] =
            serde_json::json!([format!("chrome-extension://{extension_id}/")]);
    } else {
        manifest["allowed_extensions"] = serde_json::json!([extension_id]);
    }
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(io::Error::other)?;
    write_new(&destination.join("com.rlyeh.zann.json"), &bytes, 0o600)?;
    fs::File::open(destination)?.sync_all()?;
    fs::File::open(wrapper_dir)?.sync_all()
}
