#[cfg(any(feature = "postgres", feature = "sqlite"))]
use sqlx_core::from_row::FromRow;
#[cfg(any(feature = "postgres", feature = "sqlite"))]
use sqlx_core::row::Row;
#[cfg(feature = "postgres")]
use sqlx_postgres::PgRow;
#[cfg(feature = "sqlite")]
use sqlx_sqlite::SqliteRow;

#[cfg(any(feature = "postgres", feature = "sqlite"))]
use super::*;

#[cfg(any(feature = "postgres", feature = "sqlite"))]
fn parse_enum<T: TryFrom<i32, Error = EnumParseError>>(value: i16) -> Result<T, sqlx_core::Error> {
    T::try_from(i32::from(value)).map_err(|err| sqlx_core::Error::Decode(Box::new(err)))
}

macro_rules! impl_from_row {
    ($ty:ty, $row:ident => $body:block) => {
        #[cfg(feature = "sqlite")]
        impl FromRow<'_, SqliteRow> for $ty {
            fn from_row($row: &SqliteRow) -> Result<Self, sqlx_core::Error> {
                $body
            }
        }

        #[cfg(feature = "postgres")]
        impl FromRow<'_, PgRow> for $ty {
            fn from_row($row: &PgRow) -> Result<Self, sqlx_core::Error> {
                $body
            }
        }
    };
}

impl_from_row!(User, row => {
        let status: i16 = row.try_get("status")?;
        Ok(Self {
            id: row.try_get("id")?,
            email: row.try_get("email")?,
            full_name: row.try_get("full_name")?,
            password_hash: row.try_get("password_hash")?,
            kdf_salt: row.try_get("kdf_salt")?,
            kdf_algorithm: row.try_get("kdf_algorithm")?,
            kdf_iterations: row.try_get("kdf_iterations")?,
            kdf_memory_kb: row.try_get("kdf_memory_kb")?,
            kdf_parallelism: row.try_get("kdf_parallelism")?,
            recovery_key_hash: row.try_get("recovery_key_hash")?,
            status: parse_enum(status)?,
            deleted_at: row.try_get("deleted_at")?,
            deleted_by_user_id: row.try_get("deleted_by_user_id")?,
            deleted_by_device_id: row.try_get("deleted_by_device_id")?,
            row_version: row.try_get("row_version")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            last_login_at: row.try_get("last_login_at")?,
        })
    }
);

impl_from_row!(OidcIdentity, row => {
        Ok(Self {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            issuer: row.try_get("issuer")?,
            subject: row.try_get("subject")?,
            created_at: row.try_get("created_at")?,
        })
    }
);

impl_from_row!(Group, row => {
        Ok(Self {
            id: row.try_get("id")?,
            slug: row.try_get("slug")?,
            name: row.try_get("name")?,
            created_at: row.try_get("created_at")?,
        })
    }
);

impl_from_row!(GroupMember, row => {
        Ok(Self {
            group_id: row.try_get("group_id")?,
            user_id: row.try_get("user_id")?,
            created_at: row.try_get("created_at")?,
        })
    }
);

impl_from_row!(OidcGroupMapping, row => {
        Ok(Self {
            id: row.try_get("id")?,
            issuer: row.try_get("issuer")?,
            oidc_group: row.try_get("oidc_group")?,
            internal_group_id: row.try_get("internal_group_id")?,
        })
    }
);

impl_from_row!(Device, row => {
        Ok(Self {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            name: row.try_get("name")?,
            fingerprint: row.try_get("fingerprint")?,
            os: row.try_get("os")?,
            os_version: row.try_get("os_version")?,
            app_version: row.try_get("app_version")?,
            last_seen_at: row.try_get("last_seen_at")?,
            last_ip: row.try_get("last_ip")?,
            revoked_at: row.try_get("revoked_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
);

impl_from_row!(ServiceAccount, row => {
        Ok(Self {
            id: row.try_get("id")?,
            owner_user_id: row.try_get("owner_user_id")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            token_hash: row.try_get("token_hash")?,
            token_prefix: row.try_get("token_prefix")?,
            scopes: row.try_get("scopes")?,
            allowed_ips: row.try_get("allowed_ips")?,
            expires_at: row.try_get("expires_at")?,
            last_used_at: row.try_get("last_used_at")?,
            last_used_ip: row.try_get("last_used_ip")?,
            last_used_user_agent: row.try_get("last_used_user_agent")?,
            use_count: row.try_get("use_count")?,
            created_at: row.try_get("created_at")?,
            revoked_at: row.try_get("revoked_at")?,
        })
    }
);

impl_from_row!(ServiceAccountSession, row => {
        Ok(Self {
            id: row.try_get("id")?,
            service_account_id: row.try_get("service_account_id")?,
            access_token_hash: row.try_get("access_token_hash")?,
            expires_at: row.try_get("expires_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
);

impl_from_row!(Session, row => {
        Ok(Self {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            device_id: row.try_get("device_id")?,
            access_token_hash: row.try_get("access_token_hash")?,
            access_expires_at: row.try_get("access_expires_at")?,
            refresh_token_hash: row.try_get("refresh_token_hash")?,
            expires_at: row.try_get("expires_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
);

impl_from_row!(Vault, row => {
        let kind: i16 = row.try_get("kind")?;
        let encryption_type: i16 = row.try_get("encryption_type")?;
        let cache_policy: i16 = row.try_get("cache_policy")?;
        Ok(Self {
            id: row.try_get("id")?,
            slug: row.try_get("slug")?,
            name: row.try_get("name")?,
            kind: parse_enum(kind)?,
            encryption_type: parse_enum(encryption_type)?,
            vault_key_enc: row.try_get("vault_key_enc")?,
            cache_policy: parse_enum(cache_policy)?,
            tags: row.try_get("tags")?,
            deleted_at: row.try_get("deleted_at")?,
            deleted_by_user_id: row.try_get("deleted_by_user_id")?,
            deleted_by_device_id: row.try_get("deleted_by_device_id")?,
            row_version: row.try_get("row_version")?,
            created_at: row.try_get("created_at")?,
        })
    }
);

impl_from_row!(VaultMember, row => {
        let role: i16 = row.try_get("role")?;
        Ok(Self {
            vault_id: row.try_get("vault_id")?,
            user_id: row.try_get("user_id")?,
            role: parse_enum(role)?,
            created_at: row.try_get("created_at")?,
        })
    }
);

impl_from_row!(Item, row => {
        let sync_status: i16 = row.try_get("sync_status")?;
        Ok(Self {
            id: row.try_get("id")?,
            vault_id: row.try_get("vault_id")?,
            path: row.try_get("path")?,
            name: row.try_get("name")?,
            type_id: row.try_get("type_id")?,
            tags: row.try_get("tags")?,
            favorite: row.try_get("favorite")?,
            payload_enc: row.try_get("payload_enc")?,
            checksum: row.try_get("checksum")?,
            version: row.try_get("version")?,
            row_version: row.try_get("row_version")?,
            device_id: row.try_get("device_id")?,
            sync_status: parse_enum(sync_status)?,
            deleted_at: row.try_get("deleted_at")?,
            deleted_by_user_id: row.try_get("deleted_by_user_id")?,
            deleted_by_device_id: row.try_get("deleted_by_device_id")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
);

impl_from_row!(ItemUsage, row => {
        Ok(Self {
            item_id: row.try_get("item_id")?,
            last_read_at: row.try_get("last_read_at")?,
            last_read_by_user_id: row.try_get("last_read_by_user_id")?,
            last_read_by_device_id: row.try_get("last_read_by_device_id")?,
            read_count: row.try_get("read_count")?,
        })
    }
);

impl_from_row!(ItemHistory, row => {
        let change_type: i16 = row.try_get("change_type")?;
        Ok(Self {
            id: row.try_get("id")?,
            item_id: row.try_get("item_id")?,
            payload_enc: row.try_get("payload_enc")?,
            checksum: row.try_get("checksum")?,
            version: row.try_get("version")?,
            change_type: parse_enum(change_type)?,
            fields_changed: row.try_get("fields_changed")?,
            changed_by_user_id: row.try_get("changed_by_user_id")?,
            changed_by_email: row.try_get("changed_by_email")?,
            changed_by_name: row.try_get("changed_by_name")?,
            changed_by_device_id: row.try_get("changed_by_device_id")?,
            changed_by_device_name: row.try_get("changed_by_device_name")?,
            created_at: row.try_get("created_at")?,
        })
    }
);

impl_from_row!(Attachment, row => {
        Ok(Self {
            id: row.try_get("id")?,
            item_id: row.try_get("item_id")?,
            filename: row.try_get("filename")?,
            size: row.try_get("size")?,
            mime_type: row.try_get("mime_type")?,
            enc_mode: row.try_get("enc_mode")?,
            content_enc: row.try_get("content_enc")?,
            checksum: row.try_get("checksum")?,
            storage_url: row.try_get("storage_url")?,
            created_at: row.try_get("created_at")?,
            deleted_at: row.try_get("deleted_at")?,
        })
    }
);

impl_from_row!(Change, row => {
        let op: i16 = row.try_get("op")?;
        Ok(Self {
            seq: row.try_get("seq")?,
            vault_id: row.try_get("vault_id")?,
            item_id: row.try_get("item_id")?,
            op: parse_enum(op)?,
            version: row.try_get("version")?,
            device_id: row.try_get("device_id")?,
            created_at: row.try_get("created_at")?,
        })
    }
);
