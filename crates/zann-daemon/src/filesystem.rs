//! One writer per private IPC directory, owner-only atomic identity/pairings.
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use zann_client::browser_ipc::decode_array;
use zann_crypto::ipc_signatures::IpcSigningKey;
use zann_crypto::ipc_transport::IpcTransportKey;
use zeroize::Zeroizing;

use crate::{settings::Pairing, DaemonError, Result};

const MAX_STATE: u64 = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u8,
    seed: Zeroizing<String>,
    transport_seed: Zeroizing<String>,
    pairings: Vec<Pairing>,
}

pub(crate) struct Directory {
    pub path: PathBuf,
    pub socket: PathBuf,
    lock: std::sync::Mutex<Option<File>>,
}

pub(crate) fn uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn check(metadata: &fs::Metadata, directory: bool) -> Result<()> {
    if metadata.uid() != uid()
        || metadata.mode() & 0o077 != 0
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file() || metadata.nlink() != 1
        }
    {
        return Err(DaemonError::Filesystem);
    }
    Ok(())
}

fn secure_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    check(&file.metadata()?, false)?;
    Ok(file)
}

impl Directory {
    pub fn open(root: &Path) -> Result<Self> {
        let socket = zann_client::native_messaging::socket_path(root)?;
        if !root.is_absolute() || root.components().any(|c| c == Component::ParentDir) {
            return Err(DaemonError::Filesystem);
        }
        check(&fs::symlink_metadata(root)?, true)?;
        let path = root.join("ipc");
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        check(&fs::symlink_metadata(&path)?, true)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path.join("owner.lock"))?;
        check(&lock.metadata()?, false)?;
        lock.try_lock().map_err(|e| match e {
            fs::TryLockError::WouldBlock => DaemonError::Limit,
            fs::TryLockError::Error(source) => source.into(),
        })?;
        Ok(Self {
            socket,
            path,
            lock: std::sync::Mutex::new(Some(lock)),
        })
    }

    pub fn release(&self) {
        self.lock.lock().expect("lock poisoned").take();
    }

    pub fn load(&self) -> Result<(IpcSigningKey, IpcTransportKey, Vec<Pairing>)> {
        let path = self.path.join("identity.json");
        match secure_file(&path) {
            Ok(file) => {
                if file.metadata()?.len() > MAX_STATE {
                    return Err(DaemonError::Limit);
                }
                let mut bytes = Zeroizing::new(Vec::new());
                file.take(MAX_STATE + 1).read_to_end(&mut bytes)?;
                if bytes.len() as u64 > MAX_STATE {
                    return Err(DaemonError::Limit);
                }
                let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
                if snapshot.version != 1 || snapshot.pairings.len() > 64 {
                    return Err(DaemonError::Protocol);
                }
                let mut keys = std::collections::HashSet::new();
                for pair in &snapshot.pairings {
                    decode_array::<32>(&pair.public_key)?;
                    super::settings::validate_name(&pair.name)?;
                    if !keys.insert(&pair.public_key) {
                        return Err(DaemonError::Protocol);
                    }
                }
                Ok((
                    IpcSigningKey::from_seed(decode_array(&snapshot.seed)?),
                    IpcTransportKey::from_seed(decode_array(&snapshot.transport_seed)?),
                    snapshot.pairings,
                ))
            }
            Err(DaemonError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = IpcSigningKey::generate();
                let transport = IpcTransportKey::generate();
                self.save(&key, &transport, &[])?;
                Ok((key, transport, Vec::new()))
            }
            Err(e) => Err(e),
        }
    }

    pub fn save(
        &self,
        key: &IpcSigningKey,
        transport: &IpcTransportKey,
        pairings: &[Pairing],
    ) -> Result<()> {
        let path = self.path.join("identity.json");
        match fs::symlink_metadata(&path) {
            Ok(metadata) => check(&metadata, false)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let bytes = Zeroizing::new(serde_json::to_vec(&Snapshot {
            version: 1,
            seed: Zeroizing::new(hex::encode(key.seed())),
            transport_seed: Zeroizing::new(hex::encode(transport.seed())),
            pairings: pairings.to_vec(),
        })?);
        if bytes.len() as u64 > MAX_STATE {
            return Err(DaemonError::Limit);
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&self.path)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&path)
            .map_err(|e| DaemonError::Io(e.error))?;
        File::open(&self.path)?.sync_all()?;
        Ok(())
    }
}
