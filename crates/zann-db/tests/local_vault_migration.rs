#![cfg(feature = "sqlite")]

use sqlx_core::raw_sql::raw_sql;
use sqlx_core::row::Row;
use sqlx_sqlite::Sqlite;
use uuid::Uuid;
use zann_db::{connect_sqlite_with_max, SqlitePool};

async fn legacy_pool() -> SqlitePool {
    let path = std::env::temp_dir().join(format!(
        "zann-local-vault-migration-{}.sqlite",
        Uuid::now_v7().simple()
    ));
    let url = format!("sqlite://{}", path.display());
    let pool = connect_sqlite_with_max(&url, 1)
        .await
        .expect("connect legacy sqlite");
    raw_sql(include_str!("../migrations/0001_init.sql"))
        .execute(&pool)
        .await
        .expect("apply legacy schema");
    pool
}

async fn insert_legacy_vault(pool: &SqlitePool, id: Uuid, name: &str, envelope: &[u8]) {
    sqlx_core::query::query::<Sqlite>(
        r#"
        INSERT INTO local_vaults (
            id, storage_id, name, kind, is_default, vault_key_enc, key_wrap_type,
            last_synced_at
        )
        VALUES (?1, ?2, ?3, 1, 1, ?4, 1, NULL)
        "#,
    )
    .bind(id)
    .bind(Uuid::nil())
    .bind(name)
    .bind(envelope)
    .execute(pool)
    .await
    .expect("insert legacy vault");
}

#[tokio::test]
async fn migration_backfills_deterministic_lowercase_slug_and_preserves_vault_bytes() {
    let pool = legacy_pool().await;
    let vault_id = Uuid::parse_str("0198b502-4b6c-7def-8123-aabbccddeeff").expect("fixed vault id");
    let envelope = [0_u8, 1, 2, 255];
    insert_legacy_vault(&pool, vault_id, "Legacy Vault", &envelope).await;

    let mut tx = pool.begin().await.expect("begin migration transaction");
    raw_sql(include_str!("../migrations/0002_sync_cursor_last_seq.sql"))
        .execute(&mut *tx)
        .await
        .expect("apply v2 migration");
    tx.commit().await.expect("commit v2 migration");

    let row = sqlx_core::query::query::<Sqlite>(
        r#"
        SELECT slug, name, vault_key_enc, cache_key_fp
        FROM local_vaults
        WHERE id = ?1
        "#,
    )
    .bind(vault_id)
    .fetch_one(&pool)
    .await
    .expect("read migrated vault");
    assert_eq!(
        row.try_get::<String, _>("slug").expect("decode slug"),
        "local::0198b5024b6c7def8123aabbccddeeff"
    );
    assert_eq!(
        row.try_get::<String, _>("name").expect("decode name"),
        "Legacy Vault"
    );
    assert_eq!(
        row.try_get::<Vec<u8>, _>("vault_key_enc")
            .expect("decode envelope"),
        envelope
    );
    assert_eq!(
        row.try_get::<Option<String>, _>("cache_key_fp")
            .expect("decode fingerprint"),
        None
    );
}

async fn assert_invalid_legacy_row_aborts_migration(name: &str, envelope: &[u8]) {
    let pool = legacy_pool().await;
    insert_legacy_vault(&pool, Uuid::now_v7(), name, envelope).await;

    let mut tx = pool.begin().await.expect("begin migration transaction");
    assert!(
        raw_sql(include_str!("../migrations/0002_sync_cursor_last_seq.sql"))
            .execute(&mut *tx)
            .await
            .is_err(),
        "invalid legacy rows must abort migration"
    );
    tx.rollback().await.expect("rollback failed migration");

    let last_seq_columns: i64 = sqlx_core::query::query::<Sqlite>(
        r#"
        SELECT COUNT(*) AS count
        FROM pragma_table_info('sync_cursors')
        WHERE name = 'last_seq'
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("inspect rolled-back schema")
    .try_get("count")
    .expect("decode schema count");
    assert_eq!(last_seq_columns, 0, "migration must be transactional");
}

#[tokio::test]
async fn migration_rejects_a_legacy_storage_above_the_catalog_cap() {
    let pool = legacy_pool().await;
    for index in 0..201 {
        insert_legacy_vault(
            &pool,
            Uuid::now_v7(),
            &format!("Legacy Vault {index:03}"),
            &[1, 2, 3],
        )
        .await;
    }

    let mut tx = pool.begin().await.expect("begin migration transaction");
    assert!(
        raw_sql(include_str!("../migrations/0002_sync_cursor_last_seq.sql"))
            .execute(&mut *tx)
            .await
            .is_err(),
        "an already-poisoned legacy catalog must fail migration without truncation"
    );
    tx.rollback().await.expect("rollback failed migration");
    let legacy_rows: i64 = sqlx_core::query::query::<Sqlite>(
        "SELECT COUNT(*) AS count FROM local_vaults WHERE storage_id = ?1",
    )
    .bind(Uuid::nil())
    .fetch_one(&pool)
    .await
    .expect("count preserved legacy vaults")
    .try_get("count")
    .expect("decode legacy count");
    assert_eq!(legacy_rows, 201, "failed migration must not delete vaults");
}

#[tokio::test]
async fn migration_rejects_invalid_legacy_name_without_truncation() {
    assert_invalid_legacy_row_aborts_migration(&"é".repeat(101), &[1, 2, 3]).await;
}

#[tokio::test]
async fn migration_rejects_sqlite_generated_oversized_legacy_name_without_decoding_it() {
    let pool = legacy_pool().await;
    sqlx_core::query::query::<Sqlite>(
        r#"
        INSERT INTO local_vaults (
            id, storage_id, name, kind, is_default, vault_key_enc, key_wrap_type,
            last_synced_at
        )
        VALUES (?1, ?2, printf('%.*c', 1048576, 'x'), 1, 1, zeroblob(3), 1, NULL)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(Uuid::nil())
    .execute(&pool)
    .await
    .expect("install oversized legacy name inside SQLite");

    let mut tx = pool
        .begin()
        .await
        .expect("begin bounded migration transaction");
    assert!(
        raw_sql(include_str!("../migrations/0002_sync_cursor_last_seq.sql"))
            .execute(&mut *tx)
            .await
            .is_err(),
        "oversized legacy name must fail the metadata-only migration guard"
    );
    tx.rollback().await.expect("rollback failed migration");
    let name_bytes = sqlx_core::query::query::<Sqlite>(
        "SELECT octet_length(name) AS name_bytes FROM local_vaults LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("read legacy name byte length")
    .try_get::<i64, _>("name_bytes")
    .expect("decode legacy name byte length");
    assert_eq!(name_bytes, 1_048_576);
}

#[tokio::test]
async fn migration_rejects_sqlite_generated_oversized_legacy_identifiers_before_group_or_hex() {
    for column in ["id", "storage_id"] {
        let pool = legacy_pool().await;
        insert_legacy_vault(
            &pool,
            Uuid::now_v7(),
            "Legacy corrupt identifier",
            &[1, 2, 3],
        )
        .await;
        sqlx_core::query::query::<Sqlite>("PRAGMA ignore_check_constraints = ON")
            .execute(&pool)
            .await
            .expect("allow legacy identifier corruption fixture");
        let sql = format!(
            "UPDATE local_vaults SET {column} = zeroblob(1048576) \
             WHERE name = 'Legacy corrupt identifier'"
        );
        sqlx_core::query::query::<Sqlite>(&sql)
            .execute(&pool)
            .await
            .expect("install oversized legacy identifier inside SQLite");
        sqlx_core::query::query::<Sqlite>("PRAGMA ignore_check_constraints = OFF")
            .execute(&pool)
            .await
            .expect("restore legacy constraint enforcement");

        let mut tx = pool
            .begin()
            .await
            .expect("begin identifier-bounded migration transaction");
        assert!(
            raw_sql(include_str!("../migrations/0002_sync_cursor_last_seq.sql"))
                .execute(&mut *tx)
                .await
                .is_err(),
            "oversized legacy {column} must fail before GROUP BY/hex"
        );
        tx.rollback().await.expect("rollback failed migration");
        let length_sql =
            format!("SELECT octet_length({column}) AS bytes FROM local_vaults LIMIT 1");
        let bytes = sqlx_core::query::query::<Sqlite>(&length_sql)
            .fetch_one(&pool)
            .await
            .expect("read corrupt identifier metadata")
            .try_get::<i64, _>("bytes")
            .expect("decode corrupt identifier length");
        assert_eq!(bytes, 1_048_576);
    }
}

#[tokio::test]
async fn migration_rejects_sqlite_generated_oversized_legacy_envelope_without_decoding_it() {
    let pool = legacy_pool().await;
    insert_legacy_vault(
        &pool,
        Uuid::now_v7(),
        "Legacy oversized envelope",
        &[1, 2, 3],
    )
    .await;
    sqlx_core::query::query::<Sqlite>(
        "UPDATE local_vaults SET vault_key_enc = zeroblob(1048576) \
         WHERE name = 'Legacy oversized envelope'",
    )
    .execute(&pool)
    .await
    .expect("install oversized legacy envelope inside SQLite");

    let mut tx = pool
        .begin()
        .await
        .expect("begin envelope-bounded migration transaction");
    assert!(
        raw_sql(include_str!("../migrations/0002_sync_cursor_last_seq.sql"))
            .execute(&mut *tx)
            .await
            .is_err(),
        "oversized legacy envelope must fail the lazy metadata guard"
    );
    tx.rollback().await.expect("rollback failed migration");
    let bytes = sqlx_core::query::query::<Sqlite>(
        "SELECT length(vault_key_enc) AS bytes FROM local_vaults LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("read legacy envelope byte length")
    .try_get::<i64, _>("bytes")
    .expect("decode legacy envelope byte length");
    assert_eq!(bytes, 1_048_576);
}

#[tokio::test]
async fn migration_rejects_oversized_legacy_envelope_without_truncation() {
    assert_invalid_legacy_row_aborts_migration("Legacy Vault", &vec![0; 65_537]).await;
}

#[tokio::test]
async fn migrated_schema_rejects_invalid_future_vault_writes() {
    let pool = legacy_pool().await;
    let vault_id = Uuid::now_v7();
    insert_legacy_vault(&pool, vault_id, "Legacy Vault", &[1, 2, 3]).await;
    let mut tx = pool.begin().await.expect("begin migration transaction");
    raw_sql(include_str!("../migrations/0002_sync_cursor_last_seq.sql"))
        .execute(&mut *tx)
        .await
        .expect("apply v2 migration");
    tx.commit().await.expect("commit v2 migration");

    for invalid_text_update in [
        "UPDATE local_vaults SET slug = 'local::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' WHERE id = ?1",
        "UPDATE local_vaults SET cache_key_fp = '001122AABBCC' WHERE id = ?1",
        "UPDATE local_vaults SET name = '' WHERE id = ?1",
        "UPDATE local_vaults SET id = zeroblob(1048576) WHERE id = ?1",
        "UPDATE local_vaults SET storage_id = zeroblob(1048576) WHERE id = ?1",
        "UPDATE local_vaults SET kind = zeroblob(1048576) WHERE id = ?1",
        "UPDATE local_vaults SET vault_key_enc = printf('%.*c', 1048576, 'x') WHERE id = ?1",
    ] {
        assert!(
            sqlx_core::query::query::<Sqlite>(invalid_text_update)
                .bind(vault_id)
                .execute(&pool)
                .await
                .is_err(),
            "future invalid text update must be rejected"
        );
    }
    for (column, invalid_value) in [("slug", "valid\0."), ("cache_key_fp", "001122\0abbcc")] {
        let sql = format!("UPDATE local_vaults SET {column} = ?2 WHERE id = ?1");
        assert!(
            sqlx_core::query::query::<Sqlite>(&sql)
                .bind(vault_id)
                .bind(invalid_value)
                .execute(&pool)
                .await
                .is_err(),
            "embedded NUL must not bypass ASCII grammar"
        );
    }
    assert!(
        sqlx_core::query::query::<Sqlite>(
            r#"UPDATE local_vaults SET vault_key_enc = ?2 WHERE id = ?1"#,
        )
        .bind(vault_id)
        .bind(vec![0_u8; 65_537])
        .execute(&pool)
        .await
        .is_err(),
        "future oversized envelope must be rejected"
    );
    for (id_expression, storage_expression) in
        [("zeroblob(1048576)", "?1"), ("?1", "zeroblob(1048576)")]
    {
        let sql = format!(
            r#"
            INSERT INTO local_vaults (
                id, storage_id, slug, name, kind, is_default, vault_key_enc,
                key_wrap_type, cache_key_fp, last_synced_at
            )
            VALUES (
                {id_expression}, {storage_expression}, ?2, 'Invalid identifier',
                1, 0, zeroblob(3), 1, NULL, NULL
            )
            "#
        );
        assert!(
            sqlx_core::query::query::<Sqlite>(&sql)
                .bind(Uuid::now_v7())
                .bind(format!("invalid-{}", Uuid::now_v7().simple()))
                .execute(&pool)
                .await
                .is_err(),
            "future oversized identifier insert must be rejected before catalog count"
        );
    }

    let row = sqlx_core::query::query::<Sqlite>(
        r#"SELECT slug, name, vault_key_enc, cache_key_fp FROM local_vaults WHERE id = ?1"#,
    )
    .bind(vault_id)
    .fetch_one(&pool)
    .await
    .expect("read unchanged vault");
    assert_eq!(
        row.try_get::<String, _>("slug").expect("decode slug"),
        format!("local::{}", vault_id.simple())
    );
    assert_eq!(
        row.try_get::<String, _>("name").expect("decode name"),
        "Legacy Vault"
    );
    assert_eq!(
        row.try_get::<Vec<u8>, _>("vault_key_enc")
            .expect("decode envelope"),
        vec![1, 2, 3]
    );
    assert_eq!(
        row.try_get::<Option<String>, _>("cache_key_fp")
            .expect("decode fingerprint"),
        None
    );
}

#[tokio::test]
async fn migrated_schema_trigger_rejects_the_201st_raw_vault_insert() {
    let pool = legacy_pool().await;
    let mut tx = pool.begin().await.expect("begin migration transaction");
    raw_sql(include_str!("../migrations/0002_sync_cursor_last_seq.sql"))
        .execute(&mut *tx)
        .await
        .expect("apply v2 migration");
    tx.commit().await.expect("commit v2 migration");

    for index in 0..200 {
        let id = Uuid::now_v7();
        sqlx_core::query::query::<Sqlite>(
            r#"
            INSERT INTO local_vaults (
                id, storage_id, slug, name, kind, is_default, vault_key_enc,
                key_wrap_type, cache_key_fp, last_synced_at
            )
            VALUES (?1, ?2, ?3, ?4, 1, 0, ?5, 1, NULL, NULL)
            "#,
        )
        .bind(id)
        .bind(Uuid::nil())
        .bind(format!("raw_{index:03}"))
        .bind("Duplicate display name")
        .bind(vec![1_u8, 2, 3])
        .execute(&pool)
        .await
        .expect("insert within raw catalog cap");
    }

    let overflow_id = Uuid::now_v7();
    let error = sqlx_core::query::query::<Sqlite>(
        r#"
        INSERT INTO local_vaults (
            id, storage_id, slug, name, kind, is_default, vault_key_enc,
            key_wrap_type, cache_key_fp, last_synced_at
        )
        VALUES (?1, ?2, 'raw_overflow', 'Overflow', 1, 0, ?3, 1, NULL, NULL)
        "#,
    )
    .bind(overflow_id)
    .bind(Uuid::nil())
    .bind(vec![1_u8, 2, 3])
    .execute(&pool)
    .await
    .expect_err("raw 201st insert must fail");
    assert!(error
        .to_string()
        .contains("local vault count exceeds the supported range"));
}

#[tokio::test]
async fn migrated_schema_trigger_rejects_storage_update_into_a_full_catalog() {
    let pool = legacy_pool().await;
    let mut tx = pool.begin().await.expect("begin migration transaction");
    raw_sql(include_str!("../migrations/0002_sync_cursor_last_seq.sql"))
        .execute(&mut *tx)
        .await
        .expect("apply v2 migration");
    tx.commit().await.expect("commit v2 migration");

    let target_storage = Uuid::nil();
    let mut first_target_id = None;
    for index in 0..200 {
        let id = Uuid::now_v7();
        first_target_id.get_or_insert(id);
        sqlx_core::query::query::<Sqlite>(
            r#"
            INSERT INTO local_vaults (
                id, storage_id, slug, name, kind, is_default, vault_key_enc,
                key_wrap_type, cache_key_fp, last_synced_at
            )
            VALUES (?1, ?2, ?3, 'Target catalog', 1, 0, zeroblob(3), 1, NULL, NULL)
            "#,
        )
        .bind(id)
        .bind(target_storage)
        .bind(format!("target_{index:03}"))
        .execute(&pool)
        .await
        .expect("fill target catalog to its cap");
    }

    let source_storage = Uuid::now_v7();
    let source_id = Uuid::now_v7();
    sqlx_core::query::query::<Sqlite>(
        r#"
        INSERT INTO local_vaults (
            id, storage_id, slug, name, kind, is_default, vault_key_enc,
            key_wrap_type, cache_key_fp, last_synced_at
        )
        VALUES (?1, ?2, 'source_vault', 'Source catalog', 1, 0, zeroblob(3), 1, NULL, NULL)
        "#,
    )
    .bind(source_id)
    .bind(source_storage)
    .execute(&pool)
    .await
    .expect("insert source catalog row");

    sqlx_core::query::query::<Sqlite>("UPDATE local_vaults SET storage_id = ?2 WHERE id = ?1")
        .bind(first_target_id.expect("first target id"))
        .bind(target_storage)
        .execute(&pool)
        .await
        .expect("same-storage update at cap remains a no-op");

    let error =
        sqlx_core::query::query::<Sqlite>("UPDATE local_vaults SET storage_id = ?2 WHERE id = ?1")
            .bind(source_id)
            .bind(target_storage)
            .execute(&pool)
            .await
            .expect_err("moving a 201st row into a full catalog must fail");
    assert!(error
        .to_string()
        .contains("local vault count exceeds the supported range"));

    for (storage_id, expected) in [(target_storage, 200_i64), (source_storage, 1_i64)] {
        let count = sqlx_core::query::query::<Sqlite>(
            "SELECT COUNT(*) AS count FROM local_vaults WHERE storage_id = ?1",
        )
        .bind(storage_id)
        .fetch_one(&pool)
        .await
        .expect("count catalog after rejected storage move")
        .try_get::<i64, _>("count")
        .expect("decode catalog count");
        assert_eq!(count, expected);
    }
}
