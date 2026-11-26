//! Inputs and safe match evidence for a search of one unlocked native vault.
use std::{collections::BTreeMap, fmt};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    item_policy::{ceremony_field_visible, field_label_key},
    EncryptedPayload, FieldKind,
};

#[derive(Clone)]
pub struct VaultQuery {
    terms: Zeroizing<Vec<String>>,
    // Field keys and their public, localized captions from the UI catalogue.
    labels: BTreeMap<String, String>,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum SearchMatch {
    Metadata,
    Fields(Vec<String>),
    Note,
}

impl fmt::Debug for SearchMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SearchMatch(<redacted>)")
    }
}

impl fmt::Debug for VaultQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultQuery(<redacted>)")
    }
}

impl VaultQuery {
    pub fn new(text: &str, labels: BTreeMap<String, String>) -> Option<Self> {
        let mut terms = Zeroizing::new(
            text.split_whitespace()
                .map(str::to_lowercase)
                .collect::<Vec<_>>(),
        );
        terms.sort_unstable();
        terms.dedup();
        (!terms.is_empty()).then_some(Self { terms, labels })
    }

    /// Literal FTS5 prefix terms for the existing title/path/type index.
    pub fn metadata_fts(&self) -> String {
        self.terms
            .iter()
            .map(|s| format!("\"{}\"*", s.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn payload_match(
        &self,
        title: &str,
        path: &str,
        type_id: &str,
        payload: &EncryptedPayload,
    ) -> Option<SearchMatch> {
        if payload.type_id != type_id {
            return None;
        }
        let mut covered = vec![false; self.terms.len()];
        for value in [title, path, type_id] {
            let value = value.to_lowercase();
            for (found, term) in covered.iter_mut().zip(self.terms.iter()) {
                *found |= value
                    .split(|c: char| !c.is_alphanumeric())
                    .any(|word| word.starts_with(term));
            }
        }

        // Keep one deterministic label per term, even when a short query
        // matches hundreds of custom fields. Prefer exact, then shorter labels.
        let mut evidence = vec![None; self.terms.len()];
        for (key, field) in &payload.fields {
            if !ceremony_field_visible(type_id, key) {
                continue;
            }
            let display_key = field_label_key(field.kind, key);
            let label = self
                .labels
                .get(display_key)
                .map_or(display_key, String::as_str)
                .to_lowercase();
            let entered = key.to_lowercase();
            for (index, term) in self.terms.iter().enumerate() {
                let candidate = if label.contains(term) {
                    (label != *term, label.len(), display_key)
                } else if entered.contains(term) {
                    (entered != *term, entered.len(), key.as_str())
                } else {
                    continue;
                };
                if evidence[index].is_none_or(|current| candidate < current) {
                    evidence[index] = Some(candidate);
                }
                covered[index] = true;
            }
        }
        if covered.iter().all(|found| *found) {
            let mut labels: Vec<_> = evidence
                .into_iter()
                .flatten()
                .map(|(_, _, key)| key.to_owned())
                .collect();
            labels.sort();
            labels.dedup();
            return (!labels.is_empty()).then_some(SearchMatch::Fields(labels));
        }

        // Notes are the only searchable values. Never inspect masked fields,
        // ceremony internals, arbitrary text values or payload.extra.
        for (key, field) in &payload.fields {
            if field.kind != FieldKind::Note
                || field.meta.as_ref().and_then(|m| m.masked) == Some(true)
                || !ceremony_field_visible(&payload.type_id, key)
            {
                continue;
            }
            let note = Zeroizing::new(field.value.to_lowercase());
            for (found, term) in covered.iter_mut().zip(self.terms.iter()) {
                if !*found && note.contains(term) {
                    *found = true;
                }
            }
            if covered.iter().all(|x| *x) {
                return Some(SearchMatch::Note);
            }
        }
        None
    }
}
