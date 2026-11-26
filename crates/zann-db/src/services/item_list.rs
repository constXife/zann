//! Local list projections. A search streams one vault in cursor order from a
//! single SQLite snapshot, retaining only the requested page and its counts.
use chrono::{DateTime, Utc};
use futures_util::TryStreamExt;
use sqlx_core::{from_row::FromRow, row::Row};
use uuid::Uuid;
use zann_core::{
    item_subtitle,
    vault_search::{SearchMatch, VaultQuery},
    EncryptedPayload, ItemCounts, ItemListParams, ItemPreview, ItemPreviewPage, ServiceError,
    ServiceResult,
};

use super::{LocalServices, VaultPayloadKeys};
use crate::local::{LocalItem, LocalItemRepo};

type Cursor = (DateTime<Utc>, Uuid);

fn parse_cursor(cursor: &str) -> Option<Cursor> {
    let (ts, id) = cursor.split_once('|')?;
    Some((
        DateTime::parse_from_rfc3339(ts).ok()?.with_timezone(&Utc),
        Uuid::parse_str(id).ok()?,
    ))
}

fn list_error(err: sqlx_core::Error) -> ServiceError {
    ServiceError::new("item_list_failed", err.to_string())
}

#[derive(Default)]
struct ListPage {
    items: Vec<ItemPreview>,
    hosts: Vec<Option<String>>,
    counts: ItemCounts,
    has_more: bool,
}

impl ListPage {
    fn push(
        &mut self,
        item: LocalItem,
        payload: Option<&EncryptedPayload>,
        reason: Option<SearchMatch>,
    ) {
        let subtitle = if reason.is_none() {
            payload.and_then(|p| item_subtitle(&item.type_id, p))
        } else {
            None
        };
        self.hosts.push(
            payload
                .and_then(|p| zann_autofill::LoginMatcher::login_site(p).ok())
                .map(|url| url.host().to_owned()),
        );
        self.items.push(ItemPreview {
            id: item.id,
            vault_id: item.vault_id,
            path: item.path,
            name: item.name,
            type_id: item.type_id,
            subtitle,
            search_match: reason,
            favicon_rgba: None,
            sync_status: item.sync_status,
            updated_at: item.updated_at,
            deleted_at: item.deleted_at,
        });
    }
}

impl LocalServices<'_> {
    pub(super) async fn list_page(
        &self,
        storage: Uuid,
        vault: Uuid,
        params: ItemListParams,
    ) -> ServiceResult<ItemPreviewPage> {
        let limit = params.limit.unwrap_or(200).clamp(1, 1000) as usize;
        let cursor = params
            .cursor
            .as_deref()
            .map(|s| {
                parse_cursor(s).ok_or_else(|| ServiceError::new("invalid_cursor", "invalid cursor"))
            })
            .transpose()?;
        let keys = self.vault_payload_keys(storage, vault).await?;
        let mut page = if let Some(query) = params.query {
            self.search_page(
                &keys,
                &query,
                params.updated,
                params.include_deleted,
                limit,
                cursor,
            )
            .await?
        } else {
            let repo = LocalItemRepo::new(self.pool);
            let mut page = ListPage {
                counts: repo
                    .list_counts(storage, vault, params.updated)
                    .await
                    .map_err(list_error)?,
                ..ListPage::default()
            };
            let items = repo
                .list_by_vault_paged(
                    storage,
                    vault,
                    params.updated,
                    params.include_deleted,
                    limit as i64 + 1,
                    cursor,
                )
                .await
                .map_err(list_error)?;
            page.has_more = items.len() > limit;
            for item in items.into_iter().take(limit) {
                // A damaged payload remains browsable by its public metadata.
                let payload = self.open_payload(&keys, item.id, &item.payload_enc).ok();
                page.push(item, payload.as_ref(), None);
            }
            page
        };
        let icons = self
            .read_site_icons(
                storage,
                vault,
                &keys.primary,
                page.hosts.iter().flatten().map(String::as_str),
            )
            .await
            .map_err(|err| ServiceError::new("site_icon_read", err.to_string()))?;
        for (item, host) in page.items.iter_mut().zip(page.hosts) {
            item.favicon_rgba = host.and_then(|h| icons.get(&h).cloned());
        }
        let next_cursor = page
            .items
            .last()
            .filter(|_| page.has_more)
            .map(|item| format!("{}|{}", item.updated_at.to_rfc3339(), item.id));
        Ok(ItemPreviewPage {
            items: page.items,
            next_cursor,
            total_count: page.counts.all
                + if params.include_deleted {
                    page.counts.trash
                } else {
                    0
                },
            counts: page.counts,
        })
    }

    async fn search_page(
        &self,
        keys: &VaultPayloadKeys,
        query: &VaultQuery,
        updated: Option<zann_core::UpdatedRange>,
        include_deleted: bool,
        limit: usize,
        cursor: Option<Cursor>,
    ) -> ServiceResult<ListPage> {
        let mut select = sqlx_core::query_builder::QueryBuilder::new(
            "SELECT i.*, EXISTS (SELECT 1 FROM items_cache_fts WHERE rowid = i.rowid AND items_cache_fts MATCH "
        );
        select
            .push_bind(query.metadata_fts())
            .push(") AS metadata_hit");
        let mut scoped =
            LocalItemRepo::scoped_list(select, keys.vault.storage_id, keys.vault.id, updated);
        LocalItemRepo::order_list(&mut scoped);
        let mut rows = scoped.build().fetch(self.pool);
        let mut page = ListPage::default();
        while let Some(row) = rows.try_next().await.map_err(list_error)? {
            let item = LocalItem::from_row(&row).map_err(list_error)?;
            let payload = self.open_payload(keys, item.id, &item.payload_enc).ok();
            let reason = if row.try_get::<bool, _>("metadata_hit").map_err(list_error)? {
                SearchMatch::Metadata
            } else if let Some(reason) = payload.as_ref().and_then(|payload| {
                query.payload_match(&item.name, &item.path, &item.type_id, payload)
            }) {
                reason
            } else {
                continue;
            };
            if item.deleted_at.is_some() {
                page.counts.trash += 1;
                if !include_deleted {
                    continue;
                }
            } else {
                page.counts.all += 1;
                *page.counts.by_type.entry(item.type_id.clone()).or_default() += 1;
            }
            if cursor.is_some_and(|c| (item.updated_at, item.id) >= c) {
                continue;
            }
            if page.items.len() == limit {
                page.has_more = true;
            } else {
                page.push(item, payload.as_ref(), Some(reason));
            }
        }
        Ok(page)
    }
}
