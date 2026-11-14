//! Replaceable native card reads using the core's cancellation/deadline port.
use zann_client::app::local::{SessionCancellationHandle, SessionOperation};

use super::*;

const DETAIL_TIMEOUT: Duration = Duration::from_secs(10);
const LOADING_DELAY: Duration = Duration::from_millis(150);

#[derive(Default)]
pub(super) struct Selection {
    pub id: Option<String>,
    pub request: u64,
    pub show_loading: bool,
    pub error: Option<String>,
    cancellation: Option<SessionCancellationHandle>,
}

impl Selection {
    pub fn loading(&self) -> bool {
        self.cancellation.is_some()
    }

    fn cancel(&mut self) {
        if let Some(cancellation) = self.cancellation.take() {
            cancellation.cancel();
        }
        self.request = crate::backend::next_view_request();
        self.show_loading = false;
        self.error = None;
    }
}

impl Drop for Selection {
    fn drop(&mut self) {
        self.cancel();
    }
}

// Dropping a UI task must also stop a blocking worker already inside SQLite.
struct CancelOnDrop(SessionCancellationHandle);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl State {
    pub fn selected_item_id(&self) -> Option<&str> {
        self.selection.id.as_deref()
    }

    pub fn detail_request_id(&self) -> u64 {
        self.selection.request
    }

    pub fn detail_ready(&self) -> bool {
        !self.selection.loading()
            && self.selection.error.is_none()
            && self
                .detail
                .as_ref()
                .is_some_and(|detail| self.selected_item_id() == Some(detail.id.as_str()))
    }

    pub(super) fn clear_selection(&mut self) {
        self.selection.cancel();
        self.selection.id = None;
        self.detail = None;
        self.reset_detail_interactions();
    }

    pub(super) fn reconcile_selection(&mut self) {
        if self
            .selected_item_id()
            .is_some_and(|id| !self.visible().iter().any(|item| item.id == id))
        {
            self.clear_selection();
        }
    }

    pub(super) fn install_detail(&mut self, detail: Detail) {
        self.selection.cancel();
        self.selection.id = Some(detail.id.clone());
        self.detail = Some(detail);
        self.reset_detail_interactions();
    }

    fn reset_detail_interactions(&mut self) {
        self.copy_generation = self.copy_generation.wrapping_add(1);
        self.reveal_generation = self.reveal_generation.wrapping_add(1);
        if let Some(detail) = self.detail.as_mut() {
            detail.reset_interactions();
        }
    }

    pub(super) fn load_detail(&mut self, id: String, session: &Session) -> Task<Message> {
        self.selection.cancel();
        self.selection.id = Some(id.clone());
        self.reset_detail_interactions();
        let request = self.selection.request;
        let (operation, cancellation) = SessionOperation::new(Instant::now() + DETAIL_TIMEOUT);
        let guard = CancelOnDrop(cancellation.clone());
        self.selection.cancellation = Some(cancellation);
        let facade = session.facade();
        let read = cosmic::task::future(async move {
            let _guard = guard;
            let result = off_thread(move || {
                facade
                    .item_read(id, operation)
                    .map_err(|err| err.to_string())
                    .and_then(Detail::from_item)
            })
            .await;
            Message::Loaded { request, result }
        });
        let hint = cosmic::task::future(async move {
            tokio::time::sleep(LOADING_DELAY).await;
            Message::DetailLoading(request)
        });
        Task::batch([read, hint])
    }

    pub(super) fn complete_detail(&mut self, request: u64, result: Result<Detail, String>) {
        if request != self.selection.request || !self.selection.loading() {
            return;
        }
        self.selection.cancellation = None;
        self.selection.show_loading = false;
        match result {
            Ok(detail) if self.selected_item_id() == Some(detail.id.as_str()) => {
                self.install_detail(detail);
            }
            Ok(_) => self.clear_selection(),
            Err(error) => {
                self.detail = None;
                self.selection.error = Some(error);
            }
        }
    }
}
