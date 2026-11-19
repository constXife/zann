//! Fixed 16×16 RGBA pixels. No URLs, image containers or decoder input on disk.
use std::collections::BTreeMap;

use super::{LocalServices, SecretKey, Uuid};
use sqlx_core::{query_as::query_as, query_builder::QueryBuilder};
use sqlx_sqlite::Sqlite;
use zann_crypto::{decrypt_blob, encrypt_blob, site_icon_tag, EncryptedBlob};

type Error = Box<dyn std::error::Error + Send + Sync>;
type Icons = BTreeMap<String, Vec<u8>>;

impl LocalServices<'_> {
    pub(super) async fn read_site_icons<'h>(
        &self,
        storage: Uuid,
        vault: Uuid,
        key: &SecretKey,
        hosts: impl Iterator<Item = &'h str>,
    ) -> Result<Icons, Error> {
        let tags: BTreeMap<_, _> = hosts
            .map(|host| (site_icon_tag(key, storage, vault, host), host))
            .collect();
        if tags.is_empty() {
            return Ok(Icons::new());
        }
        let rows: Vec<(String,Vec<u8>)> = query_as(
            "SELECT host_tag,pixels_enc FROM site_icons WHERE storage_id=? AND vault_id=? AND host_tag IN (SELECT value FROM json_each(?))"
        ).bind(storage).bind(vault).bind(serde_json::to_string(&tags.keys().collect::<Vec<_>>())?)
            .fetch_all(self.pool).await?;
        let mut icons = Icons::new();
        for (tag, enc) in rows {
            let pixels = decrypt_blob(key, &EncryptedBlob::from_bytes(&enc)?, tag.as_bytes())?;
            if pixels.len() != zann_core::SITE_ICON_RGBA_BYTES {
                return Err("invalid site icon dimensions".into());
            }
            icons.insert(tags[&tag].to_string(), pixels);
        }
        Ok(icons)
    }

    /// Only called for hosts admitted on one authenticated browser matches page.
    pub async fn browser_site_icons(
        &self,
        storage: Uuid,
        vault: Uuid,
        captures: BTreeMap<String, Option<Vec<u8>>>,
    ) -> Result<Icons, Error> {
        if captures.len() > zann_core::BROWSER_PAGE_LIMIT as usize
            || captures
                .values()
                .flatten()
                .any(|v| v.len() != zann_core::SITE_ICON_RGBA_BYTES)
        {
            return Err("invalid site icon page".into());
        }
        let key = self.vault_payload_keys(storage, vault).await?.primary;
        let mut icons = self
            .read_site_icons(storage, vault, &key, captures.keys().map(String::as_str))
            .await?;
        let mut changed = Vec::new();
        for (host, pixels) in captures {
            if let Some(pixels) = pixels {
                if icons.get(&host) == Some(&pixels) {
                    continue;
                }
                let tag = site_icon_tag(&key, storage, vault, &host);
                let enc = encrypt_blob(&key, &pixels, tag.as_bytes())?.to_bytes();
                changed.push((tag, enc));
                icons.insert(host, pixels);
            }
        }
        if !changed.is_empty() {
            let mut insert = QueryBuilder::<Sqlite>::new(
                "INSERT INTO site_icons(storage_id,vault_id,host_tag,pixels_enc) ",
            );
            insert.push_values(changed, |mut row, (tag, enc)| {
                row.push_bind(storage)
                    .push_bind(vault)
                    .push_bind(tag)
                    .push_bind(enc);
            });
            insert.push(" ON CONFLICT(storage_id,vault_id,host_tag) DO UPDATE SET pixels_enc=excluded.pixels_enc");
            insert.build().execute(self.pool).await?;
        }
        Ok(icons)
    }
}
