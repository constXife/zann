use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::Mutex;
use uuid::Uuid;
use zann_core::ItemUsage;
use zann_db::repo::ItemUsageRepo;
use zann_db::PgPool;

#[derive(Clone)]
pub struct UsageTracker {
    pool: PgPool,
    buffer: Arc<Mutex<HashMap<Uuid, ItemUsage>>>,
    max_buffer: usize,
}

impl UsageTracker {
    #[must_use]
    pub fn new(pool: PgPool, max_buffer: usize) -> Self {
        Self {
            pool,
            buffer: Arc::new(Mutex::new(HashMap::new())),
            max_buffer,
        }
    }

    pub fn start_flush_loop(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let _ = self.flush().await;
            }
        });
    }

    pub async fn record_read(&self, item_id: Uuid, user_id: Uuid, device_id: Option<Uuid>) {
        let flush;
        {
            let mut buffer = self.buffer.lock().await;
            let entry = buffer.entry(item_id).or_insert(ItemUsage {
                item_id,
                last_read_at: Utc::now(),
                last_read_by_user_id: Some(user_id),
                last_read_by_device_id: device_id,
                read_count: 0,
            });
            entry.read_count += 1;
            entry.last_read_at = Utc::now();
            entry.last_read_by_user_id = Some(user_id);
            entry.last_read_by_device_id = device_id;
            flush = buffer.len() >= self.max_buffer;
        }

        if flush {
            let _ = self.flush().await;
        }
    }

    pub async fn flush(&self) -> Result<(), sqlx_core::Error> {
        let records = {
            let mut buffer = self.buffer.lock().await;
            if buffer.is_empty() {
                return Ok(());
            }
            buffer.drain().map(|(_, record)| record).collect()
        };
        let repo = ItemUsageRepo::new(&self.pool);
        repo.upsert_batch(records).await
    }
}
