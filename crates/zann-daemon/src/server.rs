use std::fs;
use std::os::unix::{
    fs::{FileTypeExt, MetadataExt, PermissionsExt},
    net::{UnixListener, UnixStream},
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use zann_client::app::{local::LocalVaultService, ClientPaths};
use zann_client::browser_ipc::{Hello, SignedRequest};
use zann_crypto::ipc_signatures::random_nonce;

use crate::{engine::Engine, filesystem::Directory, DaemonControl, DaemonError, Result};

pub struct Daemon {
    control: DaemonControl,
    worker: Option<JoinHandle<Result<()>>>,
}

impl Daemon {
    pub fn start(paths: ClientPaths, vault: Arc<dyn LocalVaultService>) -> Result<Self> {
        let directory = Directory::open(paths.root())?;
        match fs::symlink_metadata(&directory.socket) {
            Ok(meta) => {
                if !meta.file_type().is_socket() || meta.uid() != super::filesystem::uid() {
                    return Err(DaemonError::Filesystem);
                }
                match UnixStream::connect(&directory.socket) {
                    Ok(_) => return Err(DaemonError::Limit),
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                        fs::remove_file(&directory.socket)?
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(&directory.socket)?;
        fs::set_permissions(&directory.socket, fs::Permissions::from_mode(0o600))?;
        let engine = Arc::new(Engine::new(directory, vault)?);
        let control = DaemonControl {
            engine: engine.clone(),
        };
        let worker = thread::Builder::new()
            .name("zann-daemon".into())
            .spawn(move || serve(listener, engine))?;
        Ok(Self {
            control,
            worker: Some(worker),
        })
    }
    pub fn control(&self) -> DaemonControl {
        self.control.clone()
    }
    pub fn server_key(&self) -> String {
        self.control.engine.public_key()
    }
    pub fn shutdown(mut self) -> Result<()> {
        self.stop()
    }
    fn stop(&mut self) -> Result<()> {
        if let Some(worker) = self.worker.take() {
            self.control.engine.running.store(false, Ordering::Release);
            // Wakes the accept loop without a public shutdown command.
            let wake = if worker.is_finished() {
                Ok(None)
            } else {
                UnixStream::connect(&self.control.engine.directory.socket).map(Some)
            };
            let stopped = worker.join().map_err(|_| DaemonError::Closed)?;
            stopped?;
            wake?;
        }
        Ok(())
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("zann daemon shutdown: {error}");
        }
    }
}

fn serve(listener: UnixListener, engine: Arc<Engine>) -> Result<()> {
    let original = fs::symlink_metadata(&engine.directory.socket)?;
    let count = Arc::new(AtomicUsize::new(0));
    let mut workers: Vec<(JoinHandle<()>, UnixStream)> = Vec::new();
    let outcome = loop {
        let (stream, _) = match listener.accept() {
            Ok(v) => v,
            Err(e) => break Err(e.into()),
        };
        if !engine.running.load(Ordering::Acquire) {
            break Ok(());
        }
        if let Err(error) = crate::peer::check(&stream) {
            eprintln!("zann IPC peer check: {error}");
            continue;
        }
        if count.load(Ordering::Acquire) >= 16 {
            continue;
        }
        workers.retain(|(worker, _)| !worker.is_finished());
        let shutdown = match stream.try_clone() {
            Ok(socket) => socket,
            Err(error) => break Err(error.into()),
        };
        let engine = engine.clone();
        let count = count.clone();
        count.fetch_add(1, Ordering::AcqRel);
        workers.push((
            thread::spawn(move || {
                struct Slot(Arc<AtomicUsize>);
                impl Drop for Slot {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let _slot = Slot(count);
                let mut stream = stream;
                if let Err(error) = connection(&mut stream, &engine) {
                    eprintln!("zann local IPC connection: {error}");
                }
                if let Err(error) = stream.shutdown(std::net::Shutdown::Both) {
                    if error.kind() != std::io::ErrorKind::NotConnected {
                        eprintln!("zann IPC close: {error}");
                    }
                }
            }),
            shutdown,
        ));
    };
    engine.running.store(false, Ordering::Release);
    for (_, stream) in &workers {
        if let Err(error) = stream.shutdown(std::net::Shutdown::Both) {
            if error.kind() != std::io::ErrorKind::NotConnected {
                eprintln!("zann IPC shutdown: {error}");
            }
        }
    }
    for (worker, _) in workers {
        let _ = worker.join();
    }
    let cleanup = (|| -> Result<()> {
        let current = fs::symlink_metadata(&engine.directory.socket)?;
        if current.dev() == original.dev() && current.ino() == original.ino() {
            fs::remove_file(&engine.directory.socket)?;
        }
        Ok(())
    })();
    let _management = engine.state.lock().expect("lock poisoned");
    engine.directory.release();
    cleanup?;
    outcome
}

fn connection(stream: &mut UnixStream, engine: &Engine) -> Result<()> {
    let nonce = random_nonce();
    let hello = serde_json::to_vec(&Hello::new(
        &engine.key,
        engine.transport_key.public_key(),
        nonce,
    ))?;
    crate::transport::write(stream, &hello)?;
    let handshake = engine.transport_key.responder(&hello)?;
    let mut channel = crate::channel::Channel::accept(stream, handshake)?;
    let mut sequence = 0_u64;
    let mut client = None;
    let mut pairing = None;
    while let Some(bytes) = channel.read()? {
        let request: SignedRequest = serde_json::from_slice(&bytes)?;
        if request.sequence != sequence.checked_add(1).ok_or(DaemonError::Limit)? {
            return Err(DaemonError::Authentication);
        }
        if client
            .as_ref()
            .is_some_and(|key| key != &request.public_key)
        {
            return Err(DaemonError::Authentication);
        }
        client = Some(request.public_key.clone());
        sequence = request.sequence;
        engine.handle(request, &nonce, &mut channel, &mut pairing)?;
    }
    Ok(())
}
