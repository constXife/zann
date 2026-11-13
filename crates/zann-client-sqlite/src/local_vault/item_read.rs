//! Cancellable, read-only item loading for native presentation.
use super::*;

fn check_active(operation: &SessionOperation) -> LocalResult<()> {
    if operation.is_cancelled() {
        Err(LocalError::Cancelled)
    } else if std::time::Instant::now() >= operation.deadline() {
        Err(LocalError::DeadlineExceeded)
    } else {
        Ok(())
    }
}

impl LocalVault {
    pub fn item_read(
        &self,
        id: String,
        operation: SessionOperation,
    ) -> LocalResult<zann_core::ItemDetail> {
        check_active(&operation)?;
        let item_id = Uuid::parse_str(&id)
            .map_err(|_| LocalError::InvalidArgument("invalid item id".into()))?;
        // Only snapshot/registration holds the lease. Awaiting SQLite must not
        // block lock or selection from cancelling the operation and its key.
        let (storage_id, vault_id, generation, master_key, pool, _in_flight) = {
            let _context = self.context_gate.read().expect("lock poisoned");
            check_active(&operation)?;
            let in_flight = self
                .item_reads
                .register(operation.operation_id(), operation.cancellation_handle());
            (
                self.storage_id(),
                self.vault_id()?,
                self.context_generation.load(Ordering::SeqCst),
                self.master_key()?,
                self.pool(),
                in_flight,
            )
        };
        let services = LocalServices::new(&pool, master_key.as_ref());
        let item = self.runtime.block_on(async {
            tokio::select! {
                biased;
                _ = operation.cancelled() => Err(LocalError::Cancelled),
                _ = tokio::time::sleep_until(operation.deadline().into()) => Err(LocalError::DeadlineExceeded),
                result = services.get_item(storage_id, item_id) => result.map_err(LocalError::ItemRead),
            }
        })?;
        check_active(&operation)?;
        let _context = self.context_gate.read().expect("lock poisoned");
        self.check_context_generation(generation)?;
        if item.vault_id != vault_id {
            return Err(LocalError::InvalidArgument(
                "item is not in the current vault".into(),
            ));
        }
        Ok(item)
    }
}
