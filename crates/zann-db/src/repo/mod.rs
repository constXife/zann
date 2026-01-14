macro_rules! query {
    ($sql:expr $(, $arg:expr)* $(,)?) => {{
        #[allow(unused_mut)]
        let mut q = sqlx_core::query::query::<sqlx_postgres::Postgres>($sql);
        $(q = q.bind($arg);)*
        q
    }};
}

macro_rules! query_as {
    ($ty:ty, $sql:expr $(, $arg:expr)* $(,)?) => {{
        #[allow(unused_mut)]
        let mut q = sqlx_core::query_as::query_as::<sqlx_postgres::Postgres, $ty>($sql);
        $(q = q.bind($arg);)*
        q
    }};
}

pub(crate) mod prelude {
    pub(crate) use crate::PgPool;
    pub(crate) use chrono::{DateTime, Utc};
    pub(crate) use sqlx_core::row::Row;
    pub(crate) use uuid::Uuid;
    pub(crate) use zann_core::{
        Attachment, Change, Device, Group, GroupMember, Item, ItemHistory, ItemUsage,
        OidcGroupMapping, OidcIdentity, ServiceAccount, ServiceAccountSession, Session, User,
        UserStatus, Vault, VaultMember,
    };
}

mod changes;
mod devices;
mod groups;
mod items;
mod sessions;
mod users;
mod vaults;

pub use changes::ChangeRepo;
pub use devices::{DeviceRepo, ServiceAccountRepo, ServiceAccountSessionRepo};
pub use groups::{GroupMemberRepo, GroupRepo, OidcGroupMappingRepo};
pub use items::{AttachmentRepo, ItemHistoryRepo, ItemRepo, ItemUsageRepo};
pub use sessions::SessionRepo;
pub use users::{OidcIdentityRepo, UserRepo};
pub use vaults::{VaultMemberRepo, VaultRepo};
