use super::*;
impl GroupRepo<'_> {
    pub async fn create_in<'e, E>(executor: E, group: &Group) -> Result<(), sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
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
        .execute(executor)
        .await
        .map(|_| ())
    }
    pub async fn update_in<'e, E>(
        executor: E,
        group_id: Uuid,
        slug: &str,
        name: &str,
    ) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
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
        .execute(executor)
        .await
        .map(|result| result.rows_affected())
    }
    pub async fn delete_by_id_in<'e, E>(executor: E, id: Uuid) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query!(
            r#"
            DELETE FROM groups
            WHERE id = $1
            "#,
            id
        )
        .execute(executor)
        .await
        .map(|result| result.rows_affected())
    }
}

impl GroupMemberRepo<'_> {
    pub async fn create_in<'e, E>(executor: E, member: &GroupMember) -> Result<(), sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query!(
            r#"
            INSERT INTO group_members (group_id, user_id, created_at)
            VALUES ($1, $2, $3)
            "#,
            member.group_id,
            member.user_id,
            member.created_at
        )
        .execute(executor)
        .await
        .map(|_| ())
    }
    pub async fn delete_in<'e, E>(
        executor: E,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query!(
            r#"
            DELETE FROM group_members
            WHERE group_id = $1 AND user_id = $2
            "#,
            group_id,
            user_id
        )
        .execute(executor)
        .await
        .map(|result| result.rows_affected())
    }
}
