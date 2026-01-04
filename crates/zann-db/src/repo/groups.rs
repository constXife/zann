use super::prelude::*;

pub struct GroupRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> GroupRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, group: &Group) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO groups (id, slug, name, created_at)
            VALUES ($1, $2, $3, $4)
            "#,
            group.id,
            group.slug.as_str(),
            group.name.as_str(),
            group.created_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get_by_slug(&self, slug: &str) -> Result<Option<Group>, sqlx_core::Error> {
        query_as!(
            Group,
            r#"
            SELECT
                id as "id",
                slug,
                name,
                created_at as "created_at"
            FROM groups
            WHERE slug = $1
            "#,
            slug
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<Group>, sqlx_core::Error> {
        query_as!(
            Group,
            r#"
            SELECT
                id as "id",
                slug,
                name,
                created_at as "created_at"
            FROM groups
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn list(
        &self,
        limit: i64,
        offset: i64,
        sort: &str,
    ) -> Result<Vec<Group>, sqlx_core::Error> {
        let order_by = if sort.eq_ignore_ascii_case("asc") {
            "ASC"
        } else {
            "DESC"
        };
        let query = format!(
            r#"
            SELECT
                id as "id",
                slug,
                name,
                created_at as "created_at"
            FROM groups
            ORDER BY created_at {}
            LIMIT $1 OFFSET $2
            "#,
            order_by
        );
        query_as!(Group, &query, limit, offset)
            .fetch_all(self.pool)
            .await
    }

    pub async fn update(
        &self,
        group_id: Uuid,
        slug: &str,
        name: &str,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE groups
            SET slug = $2, name = $3
            WHERE id = $1
            "#,
            group_id,
            slug,
            name
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn delete_by_id(&self, id: Uuid) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            DELETE FROM groups
            WHERE id = $1
            "#,
            id
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}

pub struct GroupMemberRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> GroupMemberRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, member: &GroupMember) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO group_members (group_id, user_id, created_at)
            VALUES ($1, $2, $3)
            "#,
            member.group_id,
            member.user_id,
            member.created_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<GroupMember>, sqlx_core::Error> {
        query_as!(
            GroupMember,
            r#"
            SELECT
                group_id as "group_id",
                user_id as "user_id",
                created_at as "created_at"
            FROM group_members
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_all(self.pool)
        .await
    }

    pub async fn list_by_group(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<GroupMember>, sqlx_core::Error> {
        query_as!(
            GroupMember,
            r#"
            SELECT
                group_id as "group_id",
                user_id as "user_id",
                created_at as "created_at"
            FROM group_members
            WHERE group_id = $1
            "#,
            group_id
        )
        .fetch_all(self.pool)
        .await
    }

    pub async fn get(
        &self,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<GroupMember>, sqlx_core::Error> {
        query_as!(
            GroupMember,
            r#"
            SELECT
                group_id as "group_id",
                user_id as "user_id",
                created_at as "created_at"
            FROM group_members
            WHERE group_id = $1 AND user_id = $2
            "#,
            group_id,
            user_id
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn delete(&self, group_id: Uuid, user_id: Uuid) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            DELETE FROM group_members
            WHERE group_id = $1 AND user_id = $2
            "#,
            group_id,
            user_id
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}

pub struct OidcGroupMappingRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> OidcGroupMappingRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, mapping: &OidcGroupMapping) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO oidc_group_mappings (id, issuer, oidc_group, internal_group_id)
            VALUES ($1, $2, $3, $4)
            "#,
            mapping.id,
            mapping.issuer.as_str(),
            mapping.oidc_group.as_str(),
            mapping.internal_group_id
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get_by_issuer_group(
        &self,
        issuer: &str,
        oidc_group: &str,
    ) -> Result<Option<OidcGroupMapping>, sqlx_core::Error> {
        query_as!(
            OidcGroupMapping,
            r#"
            SELECT
                id as "id",
                issuer,
                oidc_group,
                internal_group_id as "internal_group_id"
            FROM oidc_group_mappings
            WHERE issuer = $1 AND oidc_group = $2
            "#,
            issuer,
            oidc_group
        )
        .fetch_optional(self.pool)
        .await
    }
}
