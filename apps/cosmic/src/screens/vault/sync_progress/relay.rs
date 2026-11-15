//! One coalesced metadata notice and one output slot per network operation.
use super::super::*;
use cosmic::iced::{futures::SinkExt, stream};

pub(in crate::screens::vault) fn sync_task(
    facade: local::Facade,
    ticket: AutoSyncTicket,
    storage_id: Option<String>,
    list_generation: u64,
    run: u64,
) -> Task<Message> {
    Task::stream(stream::channel(1, async move |mut output| {
        let (sender, mut receiver) = tokio::sync::watch::channel(None::<String>);
        let target = storage_id.clone();
        let work = off_thread(move || {
            Ok(local::sync_observed(
                &facade,
                target,
                Some(&move |notice| {
                    if let Some(id) = notice.storage_id() {
                        sender.send_replace(Some(id.to_string()));
                    }
                }),
            ))
        });
        tokio::pin!(work);
        let mut progress_open = true;
        let result = loop {
            tokio::select! {
                biased;
                result = &mut work => break result.unwrap_or_else(|e| Err(local::SyncFailure::Other(e))),
                changed = receiver.changed(), if progress_open => {
                    if changed.is_ok() {
                        let id = receiver.borrow_and_update().clone();
                        if let Some(storage_id) = id {
                            if output.send(Message::SyncCommitted { run, storage_id }).await.is_err() { return; }
                        }
                    } else { progress_open = false; }
                }
            }
        };
        // The last commit can arrive in the same poll as completion.
        let committed = receiver.borrow_and_update().clone();
        if let Some(storage_id) = &committed {
            let _ = output
                .send(Message::SyncCommitted {
                    run,
                    storage_id: storage_id.clone(),
                })
                .await;
        }
        let _ = output
            .send(Message::AutoSynced {
                ticket,
                storage_id: storage_id.or(committed),
                list_generation,
                result,
            })
            .await;
    }))
}
