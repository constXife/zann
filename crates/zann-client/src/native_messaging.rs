//! Native-endian, length-prefixed byte frames shared by the host and daemon.
//! JSON/authentication belong above this framing layer. Both directions use
//! the stricter browser-bound size limit, before allocation.
use std::io::{self, Read, Write};

pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketPathError {
    InvalidRoot,
    TooLong,
}
impl std::fmt::Display for SocketPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidRoot => "local IPC root must be absolute and normalized",
            Self::TooLong => "local IPC socket path exceeds the operating-system limit",
        })
    }
}
impl std::error::Error for SocketPathError {}

/// One root/address contract used by bind, connect and manifest installation.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn socket_path(root: &std::path::Path) -> Result<std::path::PathBuf, SocketPathError> {
    if !root.is_absolute()
        || root
            .components()
            .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(SocketPathError::InvalidRoot);
    }
    let path = root.join("ipc/browser.sock");
    #[cfg(target_os = "macos")]
    const CAPACITY: usize = 104;
    #[cfg(target_os = "linux")]
    const CAPACITY: usize = 108;
    if path.as_os_str().as_encoded_bytes().len() >= CAPACITY {
        return Err(SocketPathError::TooLong);
    }
    Ok(path)
}

pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0; 4];
    match reader.read(&mut header[..1])? {
        0 => return Ok(None),
        1 => {}
        _ => unreachable!(),
    }
    reader.read_exact(&mut header[1..])?;
    let length = u32::from_ne_bytes(header) as usize;
    if length == 0 || length > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native message size bound",
        ));
    }
    let mut bytes = zeroize::Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes)?;
    Ok(Some(std::mem::take(&mut *bytes)))
}

pub fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native message size bound",
        ));
    }
    writer.write_all(&(bytes.len() as u32).to_ne_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}
