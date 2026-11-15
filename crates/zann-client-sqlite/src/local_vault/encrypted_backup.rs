//! Native archive lifecycle and opaque operation-bound leases.
use super::*;
use crate::maintenance::backup::{BackupError, BackupInput};
use std::time::{Duration, Instant};
use zann_crypto::backup::{ArchiveHeader, RecipientDescriptor, RecipientKey};
mod output;
mod recipients;
mod restore;
#[cfg(test)]
mod tests;

pub(super) fn failure(error: BackupFailure) -> LocalError {
    BackupError::new(error.kind(), error.to_string()).into()
}
pub(super) fn crypto(error: zann_crypto::backup::ArchiveError) -> LocalError {
    BackupError::source(error).into()
}
#[derive(Clone)]
pub(super) struct ArchiveLease {
    root: std::sync::Weak<SecretKey>,
    generation: u64,
    expires: Instant,
    operation: Arc<SessionOperation>,
}
impl ArchiveLease {
    fn check(&self, core: &LocalVault) -> LocalResult<()> {
        if self.operation.is_cancelled() {
            return Err(LocalError::Cancelled);
        }
        if Instant::now() >= self.expires {
            return Err(LocalError::DeadlineExceeded);
        }
        if core.context_generation.load(Ordering::SeqCst) != self.generation
            || !std::sync::Weak::ptr_eq(&self.root, &Arc::downgrade(&core.root_key()?))
        {
            return Err(failure(BackupFailure::SessionChanged));
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(super) enum ArchiveContent {
    Prepared(Vec<Arc<RecipientKey>>),
    Opened(BackupInput),
}
pub(super) struct ArchiveWork {
    token: zeroize::Zeroizing<String>,
    lease: ArchiveLease,
    content: ArchiveContent,
}
impl ArchiveWork {
    pub(super) fn cancel(&self) {
        self.lease.operation.cancellation_handle().cancel();
    }
}
struct CompleteArchive(Arc<SessionOperation>);
impl Drop for CompleteArchive {
    fn drop(&mut self) {
        self.0.cancellation_handle().cancel();
    }
}
impl LocalVault {
    pub fn backup_capabilities(&self) -> LocalResult<BackupCapabilities> {
        let mut recipients = vec![BackupRecipientKind::Passphrase];
        if self.authenticator.supported() {
            recipients.push(BackupRecipientKind::Hardware);
        }
        if self.backup_keys.status().biometrics_available {
            recipients.push(BackupRecipientKind::Biometric);
        }
        Ok(BackupCapabilities {
            recipients,
            max_recipients: zann_crypto::backup::MAX_RECIPIENTS as u32,
        })
    }

    fn archive_lease(&self, operation: SessionOperation) -> LocalResult<ArchiveLease> {
        let _context = self.context_gate.read().expect("context");
        let lease = ArchiveLease {
            root: Arc::downgrade(&self.root_key()?),
            generation: self.context_generation.load(Ordering::SeqCst),
            expires: operation
                .deadline()
                .min(Instant::now() + Duration::from_secs(600)),
            operation: Arc::new(operation),
        };
        lease.check(self)?;
        Ok(lease)
    }
    fn save_archive(
        &self,
        lease: ArchiveLease,
        content: ArchiveContent,
    ) -> LocalResult<BackupHandle> {
        let _context = self.context_gate.read().expect("context");
        lease.check(self)?;
        let token = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            zann_crypto::ipc_signatures::random_nonce(),
        );
        let operation = lease.operation.clone();
        let expires = lease.expires;
        let registry = Arc::downgrade(&self.archive);
        let cleanup_token = zeroize::Zeroizing::new(token.clone());
        let work = ArchiveWork {
            token: zeroize::Zeroizing::new(token.clone()),
            lease,
            content,
        };
        if let Some(old) = self.archive.lock().expect("archive").replace(work) {
            old.cancel();
        }
        self.runtime.spawn(async move {
            tokio::select! {
                _=operation.cancelled()=>{},
                _=tokio::time::sleep_until(tokio::time::Instant::from_std(expires))=>{},
            }
            operation.cancellation_handle().cancel();
            if let Some(registry) = registry.upgrade() {
                let mut pending = registry.lock().expect("archive");
                if pending.as_ref().is_some_and(|w| {
                    zann_crypto::secret_bytes_equal(w.token.as_bytes(), cleanup_token.as_bytes())
                }) {
                    pending.take().expect("matched expired archive").cancel();
                }
            }
        });
        Ok(BackupHandle::from_token(token))
    }
    fn archive_snapshot(
        &self,
        handle: &BackupHandle,
    ) -> LocalResult<(ArchiveLease, ArchiveContent)> {
        let _context = self.context_gate.read().expect("context");
        let pending = self.archive.lock().expect("archive");
        let work = pending
            .as_ref()
            .filter(|w| {
                zann_crypto::secret_bytes_equal(w.token.as_bytes(), handle.token().as_bytes())
            })
            .ok_or_else(|| failure(BackupFailure::HandleInvalid))?;
        work.lease.check(self)?;
        Ok((work.lease.clone(), work.content.clone()))
    }
    fn take_archive(
        &self,
        handle: &BackupHandle,
    ) -> LocalResult<(ArchiveWork, in_flight::InFlightOperation<'_>)> {
        let _context = self.context_gate.read().expect("context");
        let mut pending = self.archive.lock().expect("archive");
        let work = pending
            .as_ref()
            .filter(|w| {
                zann_crypto::secret_bytes_equal(w.token.as_bytes(), handle.token().as_bytes())
            })
            .ok_or_else(|| failure(BackupFailure::HandleInvalid))?;
        work.lease.check(self)?;
        let active = self.syncs.register(
            work.lease.operation.operation_id(),
            work.lease.operation.cancellation_handle(),
        );
        Ok((pending.take().expect("matched archive"), active))
    }
    pub fn backup_begin(&self, operation: SessionOperation) -> LocalResult<BackupHandle> {
        self.save_archive(
            self.archive_lease(operation)?,
            ArchiveContent::Prepared(Vec::new()),
        )
    }
    pub fn backup_cancel(&self, handle: BackupHandle) -> LocalResult<()> {
        let mut pending = self.archive.lock().expect("archive");
        if pending.as_ref().is_some_and(|w| {
            zann_crypto::secret_bytes_equal(w.token.as_bytes(), handle.token().as_bytes())
        }) {
            pending.take().expect("matched archive").cancel();
        }
        Ok(())
    }
    pub fn backup_encrypted_recipients(
        &self,
        path: String,
    ) -> LocalResult<Vec<BackupRecipientSummary>> {
        let mut file = std::fs::File::open(path).map_err(BackupError::source)?;
        let header = ArchiveHeader::read(&mut file).map_err(crypto)?;
        Ok(header
            .recipients()
            .iter()
            .enumerate()
            .map(|(index, d)| summary(index, d))
            .collect())
    }
}
fn summary(index: usize, descriptor: &RecipientDescriptor) -> BackupRecipientSummary {
    BackupRecipientSummary {
        index: index as u32,
        kind: match descriptor {
            RecipientDescriptor::Argon2idPassphrase { .. } => BackupRecipientKind::Passphrase,
            RecipientDescriptor::Fido2HmacSecret { .. } => BackupRecipientKind::Hardware,
            RecipientDescriptor::DeviceBiometric { .. } => BackupRecipientKind::Biometric,
        },
    }
}
