use super::prelude::*;

pub struct UserRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> UserRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, user: &User) -> Result<(), sqlx_core::Error> {
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
                last_login_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
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
            user.last_login_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<User>, sqlx_core::Error> {
        query_as!(
            User,
            r#"
            SELECT
                id as "id",
                email,
                full_name,
                password_hash,
                kdf_salt,
                kdf_algorithm,
                kdf_iterations,
                kdf_memory_kb,
                kdf_parallelism,
                recovery_key_hash,
                status as "status",
                deleted_at as "deleted_at",
                deleted_by_user_id as "deleted_by_user_id",
                deleted_by_device_id as "deleted_by_device_id",
                row_version as "row_version",
                created_at as "created_at",
                updated_at as "updated_at",
                last_login_at as "last_login_at"
            FROM users
            WHERE id = $1 AND deleted_at IS NULL
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn get_by_email(&self, email: &str) -> Result<Option<User>, sqlx_core::Error> {
        query_as!(
            User,
            r#"
            SELECT
                id as "id",
                email,
                full_name,
                password_hash,
                kdf_salt,
                kdf_algorithm,
                kdf_iterations,
                kdf_memory_kb,
                kdf_parallelism,
                recovery_key_hash,
                status as "status",
                deleted_at as "deleted_at",
                deleted_by_user_id as "deleted_by_user_id",
                deleted_by_device_id as "deleted_by_device_id",
                row_version as "row_version",
                created_at as "created_at",
                updated_at as "updated_at",
                last_login_at as "last_login_at"
            FROM users
            WHERE email = $1 AND deleted_at IS NULL
            "#,
            email
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn update_last_login(
        &self,
        user_id: Uuid,
        row_version: i64,
        last_login_at: DateTime<Utc>,
    ) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            UPDATE users
            SET last_login_at = $3,
                row_version = row_version + 1,
                updated_at = $4
            WHERE id = $1 AND row_version = $2
            "#,
            user_id,
            row_version,
            last_login_at,
            last_login_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn update_full_name(
        &self,
        user_id: Uuid,
        row_version: i64,
        full_name: Option<&str>,
    ) -> Result<u64, sqlx_core::Error> {
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
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn list(
        &self,
        limit: i64,
        offset: i64,
        sort: &str,
        status: Option<UserStatus>,
    ) -> Result<Vec<User>, sqlx_core::Error> {
        let order_by = if sort.eq_ignore_ascii_case("asc") {
            "ASC"
        } else {
            "DESC"
        };
        let where_clause = if status.is_some() {
            "WHERE status = $3 AND status != 3 AND deleted_at IS NULL"
        } else {
            "WHERE status != 3 AND deleted_at IS NULL"
        };
        let query = format!(
            r#"
            SELECT
                id as "id",
                email,
                full_name,
                password_hash,
                kdf_salt,
                kdf_algorithm,
                kdf_iterations,
                kdf_memory_kb,
                kdf_parallelism,
                recovery_key_hash,
                status as "status",
                deleted_at as "deleted_at",
                deleted_by_user_id as "deleted_by_user_id",
                deleted_by_device_id as "deleted_by_device_id",
                row_version as "row_version",
                created_at as "created_at",
                updated_at as "updated_at",
                last_login_at as "last_login_at"
            FROM users
            {where_clause}
            ORDER BY created_at {}
            LIMIT $1 OFFSET $2
            "#,
            order_by,
            where_clause = where_clause
        );
        let mut query = query_as!(User, &query, limit, offset);
        if let Some(status) = status {
            query = query.bind(status.as_i32());
        }
        query.fetch_all(self.pool).await
    }

    pub async fn update_status(
        &self,
        user_id: Uuid,
        row_version: i64,
        status: UserStatus,
    ) -> Result<u64, sqlx_core::Error> {
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
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn delete_by_id(
        &self,
        user_id: Uuid,
        row_version: i64,
        deleted_at: DateTime<Utc>,
        deleted_by_user_id: Uuid,
        deleted_by_device_id: Option<Uuid>,
    ) -> Result<u64, sqlx_core::Error> {
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
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn update_password_hash(
        &self,
        user_id: Uuid,
        row_version: i64,
        password_hash: Option<&str>,
    ) -> Result<u64, sqlx_core::Error> {
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
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn update_recovery_key_hash(
        &self,
        user_id: Uuid,
        row_version: i64,
        recovery_key_hash: &str,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE users
            SET recovery_key_hash = $3,
                row_version = row_version + 1,
                updated_at = $4
            WHERE id = $1 AND row_version = $2
            "#,
            user_id,
            row_version,
            recovery_key_hash,
            Utc::now()
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}

pub struct OidcIdentityRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> OidcIdentityRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, identity: &OidcIdentity) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO oidc_identities (id, user_id, issuer, subject, created_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            identity.id,
            identity.user_id,
            identity.issuer.as_str(),
            identity.subject.as_str(),
            identity.created_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get_by_issuer_subject(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<OidcIdentity>, sqlx_core::Error> {
        query_as!(
            OidcIdentity,
            r#"
            SELECT
                id as "id",
                user_id as "user_id",
                issuer,
                subject,
                created_at as "created_at"
            FROM oidc_identities
            WHERE issuer = $1 AND subject = $2
            "#,
            issuer,
            subject
        )
        .fetch_optional(self.pool)
        .await
    }
}
