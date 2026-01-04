use zann_db::PgPool;

pub async fn prune_item_history_ttl(pool: &PgPool, ttl_days: i64) -> Result<u64, sqlx_core::Error> {
    if ttl_days <= 0 {
        return Ok(0);
    }
    let result = sqlx_core::query::query::<sqlx_postgres::Postgres>(
        r#"
        DELETE FROM item_history
        WHERE created_at < NOW() - ($1 * INTERVAL '1 day')
        "#,
    )
    .bind(ttl_days)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn prune_rotation_candidates(pool: &PgPool) -> Result<u64, sqlx_core::Error> {
    let result = sqlx_core::query::query::<sqlx_postgres::Postgres>(
        r#"
        UPDATE items
        SET rotation_state = NULL,
            rotation_candidate_enc = NULL,
            rotation_started_at = NULL,
            rotation_started_by = NULL,
            rotation_expires_at = NULL,
            rotation_recover_until = NULL,
            rotation_aborted_reason = NULL
        WHERE rotation_recover_until IS NOT NULL
          AND rotation_recover_until < NOW()
        "#,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
