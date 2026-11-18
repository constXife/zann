use super::*;
impl UserRepo<'_> {
    pub async fn create_in<'e, E>(executor: E, user: &User) -> Result<(), sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query!(
            r#"
            INSERT INTO users (
                id,
                email,
                full_name,
                password_hash,
                kdf_salt,
                kdf_algorithm,
                kdf_iterations,
                kdf_memory_kb,
                kdf_parallelism,
                recovery_key_hash,
                status,
                deleted_at,
                deleted_by_user_id,
                deleted_by_device_id,
                row_version,
                created_at,
                updated_at,
                last_login_at, auth_epoch, active_recovery_id
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
            )
            "#,
            user.id,
            user.email.as_str(),
            user.full_name.as_deref(),
            user.password_hash.as_deref(),
            user.kdf_salt.as_str(),
            user.kdf_algorithm.as_str(),
            user.kdf_iterations,
            user.kdf_memory_kb,
            user.kdf_parallelism,
            user.recovery_key_hash.as_deref(),
            user.status.as_i32(),
            user.deleted_at,
            user.deleted_by_user_id,
            user.deleted_by_device_id,
            user.row_version,
            user.created_at,
            user.updated_at,
            user.last_login_at,
            user.auth_epoch,
            user.active_recovery_id
        )
        .execute(executor)
        .await
        .map(|_| ())
    }
    pub async fn update_full_name_in<'e, E>(
        executor: E,
        user_id: Uuid,
        row_version: i64,
        full_name: Option<&str>,
    ) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query!(
            r#"
            UPDATE users
            SET full_name = $3,
                row_version = row_version + 1,
                updated_at = $4
            WHERE id = $1 AND row_version = $2
            "#,
            user_id,
            row_version,
            full_name,
            Utc::now()
        )
        .execute(executor)
        .await
        .map(|result| result.rows_affected())
    }
    pub async fn update_status_in<'e, E>(
        executor: E,
        user_id: Uuid,
        row_version: i64,
        status: UserStatus,
    ) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query!(
            r#"
            UPDATE users
            SET status = $3,
                row_version = row_version + 1,
                updated_at = $4
            WHERE id = $1 AND row_version = $2
            "#,
            user_id,
            row_version,
            status.as_i32(),
            Utc::now()
        )
        .execute(executor)
        .await
        .map(|result| result.rows_affected())
    }
    pub async fn delete_by_id_in<'e, E>(
        executor: E,
        user_id: Uuid,
        row_version: i64,
        deleted_at: DateTime<Utc>,
        deleted_by_user_id: Uuid,
        deleted_by_device_id: Option<Uuid>,
    ) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query!(
            r#"
            UPDATE users
            SET deleted_at = $3,
                deleted_by_user_id = $4,
                deleted_by_device_id = $5,
                row_version = row_version + 1,
                updated_at = $6
            WHERE id = $1 AND row_version = $2
            "#,
            user_id,
            row_version,
            deleted_at,
            deleted_by_user_id,
            deleted_by_device_id,
            deleted_at
        )
        .execute(executor)
        .await
        .map(|result| result.rows_affected())
    }
    pub async fn update_password_hash_in<'e, E>(
        executor: E,
        user_id: Uuid,
        row_version: i64,
        password_hash: Option<&str>,
    ) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query!(
            r#"
            UPDATE users
            SET password_hash = $3,
                row_version = row_version + 1,
                updated_at = $4
            WHERE id = $1 AND row_version = $2
            "#,
            user_id,
            row_version,
            password_hash,
            Utc::now()
        )
        .execute(executor)
        .await
        .map(|result| result.rows_affected())
    }
}
