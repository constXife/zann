#![cfg(unix)]
mod install;
pub use install::install;

use std::io;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use zann_client::native_messaging::{read_frame, write_frame};
use zeroize::Zeroizing;

pub fn relay(root: &Path) -> io::Result<()> {
    if !root.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "client root must be absolute",
        ));
    }
    let address = zann_client::native_messaging::socket_path(root)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut replies = UnixStream::connect(address)?;
    let mut requests = replies.try_clone()?;
    // The browser closing stdin shuts down the socket; a daemon disconnect
    // ends the process even if the browser is still holding stdin open.
    std::thread::spawn(move || {
        let outcome = (|| -> io::Result<()> {
            let mut input = io::stdin().lock();
            while let Some(bytes) = read_frame(&mut input)? {
                let bytes = Zeroizing::new(bytes);
                write_frame(&mut requests, &bytes)?;
            }
            Ok(())
        })();
        if let Err(error) = outcome {
            eprintln!("zann native host input: {error}");
        }
        if let Err(error) = requests.shutdown(Shutdown::Both) {
            eprintln!("zann native host shutdown: {error}");
        }
    });
    let mut output = io::stdout().lock();
    while let Some(bytes) = read_frame(&mut replies)? {
        let bytes = Zeroizing::new(bytes);
        write_frame(&mut output, &bytes)?;
    }
    Ok(())
}
