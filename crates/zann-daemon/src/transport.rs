//! Whole-frame deadlines, including partial reads/writes (not a timeout that
//! restarts whenever an adversarial peer sends another byte).
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
use zann_client::native_messaging;

const FRAME_DEADLINE: Duration = Duration::from_secs(5);

struct Deadline<'a> {
    stream: &'a mut UnixStream,
    end: Instant,
}
impl Deadline<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        self.end
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "local IPC frame deadline"))
    }
}
impl Read for Deadline<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for Deadline<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

pub(crate) fn read(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    native_messaging::read_frame(&mut Deadline {
        stream,
        end: Instant::now() + FRAME_DEADLINE,
    })
}
pub(crate) fn write(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    native_messaging::write_frame(
        &mut Deadline {
            stream,
            end: Instant::now() + FRAME_DEADLINE,
        },
        bytes,
    )
}
