//! One local boundary crossing: decrypted payload -> canonical presentation.
use std::sync::Arc;

use crate::{CoreError, CoreFacade, CoreResult, ItemDetailFieldFfi, SessionOperationFfi};

#[derive(uniffi::Record)]
pub struct ItemDetailViewFfi {
    pub id: String,
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub fields: Vec<ItemDetailFieldFfi>,
}

impl std::fmt::Debug for ItemDetailViewFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemDetailViewFfi(<redacted>)")
    }
}

#[uniffi::export]
impl CoreFacade {
    pub fn item_detail(
        &self,
        id: String,
        operation: Arc<SessionOperationFfi>,
    ) -> CoreResult<ItemDetailViewFfi> {
        let operation = operation.take()?;
        let cancellation = operation.cancellation_handle();
        let deadline = operation.deadline();
        let item = self.inner.item_read(id, operation)?;
        if cancellation.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
        let fields = zann_ui_core::item_detail::project_payload_fields(item.payload)
            .into_iter()
            .map(Into::into)
            .collect();
        if cancellation.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
        if std::time::Instant::now() >= deadline {
            return Err(CoreError::DeadlineExceeded);
        }
        Ok(ItemDetailViewFfi {
            id: item.id.to_string(),
            title: item.name,
            path: item.path,
            type_id: item.type_id,
            fields,
        })
    }
}
