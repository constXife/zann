//! Device-local MRU metadata, independent of vault records and synchronization.
//! The browser adapter serializes read/modify/write with identity changes.
use super::{decode_array, BrowserMatch, BrowserScope, IpcError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const MAX_USAGE_ENTRIES: usize = 4096;
pub const MAX_USAGE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    server_key: String,
    storage_id: String,
    vault_id: String,
    item_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserUsage {
    version: u8,
    // Most recently confirmed insertion first. No clock, frequency or URL log.
    entries: Vec<Entry>,
}
fn valid_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(IpcError::Protocol);
    }
    Ok(())
}
fn valid_scope(server: &str, scope: &BrowserScope) -> Result<()> {
    decode_array::<32>(server)?;
    valid_id(&scope.storage_id)?;
    valid_id(&scope.vault_id)
}
impl Entry {
    fn in_scope(&self, server: &str, scope: &BrowserScope) -> bool {
        self.server_key == server
            && self.storage_id == scope.storage_id
            && self.vault_id == scope.vault_id
    }
}
impl BrowserUsage {
    /// JSON null is an explicitly absent/new local store. Invalid/future data
    /// never becomes an empty history; resetting belongs to explicit Forget.
    pub fn from_json(bytes: &str) -> Result<Self> {
        if bytes.len() > MAX_USAGE_BYTES {
            return Err(IpcError::Limit);
        }
        let parsed: Option<Self> = serde_json::from_str(bytes)?;
        let store = match parsed {
            Some(store) => store,
            None => Self {
                version: 1,
                entries: Vec::new(),
            },
        };
        if store.version != 1 {
            return Err(IpcError::Protocol);
        }
        if store.entries.len() > MAX_USAGE_ENTRIES {
            return Err(IpcError::Limit);
        }
        let mut seen = HashSet::new();
        for entry in &store.entries {
            decode_array::<32>(&entry.server_key)?;
            valid_id(&entry.storage_id)?;
            valid_id(&entry.vault_id)?;
            valid_id(&entry.item_id)?;
            if !seen.insert((
                &entry.server_key,
                &entry.storage_id,
                &entry.vault_id,
                &entry.item_id,
            )) {
                return Err(IpcError::Protocol);
            }
        }
        Ok(store)
    }
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn record_success(&mut self, server: &str, scope: &BrowserScope, item: &str) -> Result<()> {
        valid_scope(server, scope)?;
        valid_id(item)?;
        self.entries
            .retain(|e| !(e.in_scope(server, scope) && e.item_id == item));
        self.entries.insert(
            0,
            Entry {
                server_key: server.into(),
                storage_id: scope.storage_id.clone(),
                vault_id: scope.vault_id.clone(),
                item_id: item.into(),
            },
        );
        self.entries.truncate(MAX_USAGE_ENTRIES);
        Ok(())
    }

    /// Match quality wins over recency. Stable ties preserve native ordering.
    /// Scope generation is deliberately excluded: locking does not erase usage.
    pub fn rank(
        &self,
        server: &str,
        scope: &BrowserScope,
        items: &mut [BrowserMatch],
    ) -> Result<()> {
        valid_scope(server, scope)?;
        if items.len() > super::search::SEARCH_MAX_MATCHES {
            return Err(IpcError::Limit);
        }
        let recent: HashMap<_, _> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.in_scope(server, scope))
            .map(|(index, e)| (e.item_id.as_str(), index))
            .collect();
        items.sort_by(|a, b| {
            a.match_quality.cmp(&b.match_quality).then_with(|| {
                match (
                    recent.get(a.item_id.as_str()),
                    recent.get(b.item_id.as_str()),
                ) {
                    (Some(a), Some(b)) => a.cmp(b),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
            })
        });
        Ok(())
    }
}
