#![cfg(feature = "sqlite")]
use zann_db::local::MetadataRepo;

#[tokio::test]
async fn metadata_cas_never_overwrites_an_unobserved_generation() {
    let root = tempfile::tempdir().expect("root");
    let pool = zann_db::connect_sqlite_with_max(
        &format!("sqlite://{}", root.path().join("db.sqlite").display()),
        1,
    )
    .await
    .expect("database");
    zann_db::migrate_local(&pool).await.expect("schema");
    let repo = MetadataRepo::new(&pool);
    assert!(repo
        .compare_exchange_value("keyring", None, "original")
        .await
        .expect("initialize"));
    assert!(!repo
        .compare_exchange_value("keyring", None, "late initializer")
        .await
        .expect("stale initializer"));
    assert!(repo
        .compare_exchange_value("keyring", Some("original"), "replacement")
        .await
        .expect("replace"));
    assert!(!repo
        .compare_exchange_value("keyring", Some("original"), "stale replacement")
        .await
        .expect("stale writer"));
    assert_eq!(
        repo.get_value("keyring").await.expect("read"),
        Some("replacement".into())
    );
    assert!(repo.get_value_bounded("keyring", 4).await.is_err());
    assert_eq!(
        repo.get_value_bounded("keyring", 11)
            .await
            .expect("bounded read"),
        Some("replacement".into())
    );
    pool.close().await;
}
