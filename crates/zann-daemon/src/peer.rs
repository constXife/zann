use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use crate::{DaemonError, Result};

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut credential = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credential.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer credential size",
        ));
    }
    Ok(unsafe { credential.assume_init() }.uid)
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let (mut uid, mut gid) = (0, 0);
    // Darwin's getpeereid retrieves the kernel LOCAL_PEERCRED identity.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

pub(crate) fn check(stream: &UnixStream) -> Result<()> {
    if peer_uid(stream)? != super::filesystem::uid() {
        return Err(DaemonError::Authentication);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn kernel_reports_peer_uid_for_real_socket() {
        let (a, _) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(
            super::peer_uid(&a).unwrap(),
            super::super::filesystem::uid()
        );
        super::check(&a).unwrap();
    }
}
