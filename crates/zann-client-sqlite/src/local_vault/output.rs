//! One private output publisher for every session-bound streaming export.
use super::*;
use crate::maintenance::{private_output::PrivateOutput, BackupError};
use std::io::{self, Write};
pub(super) trait OutputLease {
    fn check_output(&self, core: &LocalVault) -> LocalResult<()>;
}
pub(super) struct CheckedOutput<'a, L: OutputLease> {
    core: &'a LocalVault,
    pub(super) lease: L,
    output: PrivateOutput,
}
impl<'a, L: OutputLease> CheckedOutput<'a, L> {
    pub(super) fn new(core: &'a LocalVault, lease: L, target: &Path) -> LocalResult<Self> {
        {
            let _context = core.context_gate.read().expect("context");
            lease.check_output(core)?;
        }
        Ok(Self {
            core,
            lease,
            output: PrivateOutput::create(target).map_err(BackupError::source)?,
        })
    }
    pub(super) fn publish(mut self) -> LocalResult<()> {
        self.output.seal().map_err(BackupError::source)?;
        let _context = self.core.context_gate.read().expect("context");
        self.lease.check_output(self.core)?;
        self.output.publish().map_err(BackupError::source)?;
        Ok(())
    }
}
impl<L: OutputLease> Write for CheckedOutput<'_, L> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let _context = self.core.context_gate.read().expect("context");
        self.lease
            .check_output(self.core)
            .map_err(io::Error::other)?;
        self.output.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        let _context = self.core.context_gate.read().expect("context");
        self.lease
            .check_output(self.core)
            .map_err(io::Error::other)?;
        self.output.flush()
    }
}
