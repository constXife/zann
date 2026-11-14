//! Non-secret item attributes shared by storage, sync and backups.
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ItemMetadata {
    pub tags: Option<Vec<String>>,
    pub favorite: bool,
}

impl ItemMetadata {
    pub fn validate(&self) -> bool {
        self.tags.as_ref().is_none_or(|tags| {
            tags.len() <= 64 && tags.iter().all(|tag| !tag.is_empty() && tag.len() <= 128)
        })
    }
}

impl std::fmt::Debug for ItemMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemMetadata(<redacted>)")
    }
}
