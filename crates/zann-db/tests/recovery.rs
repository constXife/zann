#![cfg(feature = "postgres")]
mod support;
use chrono::Utc;
use sqlx_core::{query::query, row::Row};
use sqlx_postgres::Postgres;
use support::{setup_db, test_user};
use uuid::Uuid;
use zann_core::recovery::RecoveryState;
use zann_core::{Device, Session};
use zann_db::{
    repo::{
        AccountAccessRepo, AccountAccessStoreError, AccountAuthState, DeviceRepo, RecoveryMutation,
        RecoveryRepo, RecoveryStart, RecoveryStoreError, SessionRepo, SessionWriteError, UserRepo,
    },
    PgPool,
};

async fn account(pool: &PgPool) -> (Uuid, Session) {
    let now = Utc::now();
    let user = test_user(now, "recovery@example.test", None);
    let users = UserRepo::new(pool);
    users.create(&user).await.unwrap();
    // Fixture state only: production writers are recovery start and code activation.
    query::<Postgres>("UPDATE users SET recovery_key_hash = $2, recovery_key_version = recovery_key_version + 1, security_revision = security_revision + 1, row_version = row_version + 1 WHERE id = $1")
        .bind(user.id)
        .bind("test-old-verifier")
        .execute(pool)
        .await
        .unwrap();
    let device = Device {
        id: Uuid::new_v4(),
        user_id: user.id,
        name: "test".into(),
        fingerprint: "test".into(),
        os: None,
        os_version: None,
        app_version: None,
        last_seen_at: None,
        last_ip: None,
        revoked_at: None,
        created_at: now,
    };
    DeviceRepo::new(pool).create(&device).await.unwrap();
    let session = Session {
        id: Uuid::new_v4(),
        user_id: user.id,
        device_id: device.id,
        auth_epoch: 1,
        passkey_credential_id: None,
        passkey_session_epoch: None,
        access_token_hash: "test-access".into(),
        access_expires_at: now + chrono::Duration::hours(1),
        refresh_token_hash: "test-refresh".into(),
        expires_at: now + chrono::Duration::days(1),
        created_at: now,
    };
    SessionRepo::new(pool).create(&session).await.unwrap();
    (user.id, session)
}
fn start(user: Uuid, op: Uuid, state: &AccountAuthState, digest: u8) -> RecoveryStart<'static> {
    RecoveryStart {
        user_id: user,
        operation_id: op,
        expected_auth_epoch: state.auth_epoch,
        expected_security_revision: state.security_revision,
        expected_code_version: state.recovery_key_version,
        expected_code_hash: "test-old-verifier",
        successor_code_hash: "test-next-verifier",
        resume_token_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        consume_digest: [digest; 32],
        account_key_epoch: Some(1),
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn consume_race_invalidates_access_refresh_and_new_issuance() {
    let pool = setup_db().await;
    let (user, session) = account(&pool).await;
    let repo = RecoveryRepo::new(&pool);
    let state = repo.account_state(user).await.unwrap().unwrap();
    assert_eq!(state.recovery_key_version, 1);
    let a = start(user, Uuid::new_v4(), &state, 1);
    let b = start(user, Uuid::new_v4(), &state, 2);
    let (a, b) = tokio::join!(repo.start(a), repo.start(b));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let status = a.ok().or_else(|| b.ok()).unwrap();
    assert_eq!(status.auth_epoch, 2);
    let sessions = SessionRepo::new(&pool);
    assert!(sessions
        .get_by_access_token_hash(&session.access_token_hash)
        .await
        .unwrap()
        .is_none());
    assert!(sessions
        .get_by_refresh_token_hash(&session.refresh_token_hash)
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        sessions.create(&session).await,
        Err(SessionWriteError::Invalidated)
    ));
    assert!(matches!(
        sessions
            .update_refresh_token(
                &session,
                "next-access",
                session.access_expires_at,
                "next-refresh",
                session.expires_at
            )
            .await,
        Err(SessionWriteError::Invalidated)
    ));
    let count: i64 = query::<Postgres>("SELECT count(*) AS n FROM sessions WHERE user_id=$1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("n");
    assert_eq!(
        count, 1,
        "epoch invalidates without scanning/deleting sessions"
    );
    let fetched = UserRepo::new(&pool).get_by_id(user).await.unwrap().unwrap();
    assert_eq!(
        fetched.recovery_key_hash.as_deref(),
        Some("test-next-verifier")
    );
    assert_eq!(fetched.active_recovery_id, Some(status.operation_id));
    let mut conn = pool.acquire().await.unwrap();
    let revision: i64 = query::<Postgres>("SELECT security_revision FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&mut *conn)
        .await
        .unwrap()
        .get("security_revision");
    assert!(matches!(
        AccountAccessRepo::activate_code_in(
            &mut conn,
            user,
            revision,
            Uuid::new_v4(),
            &"r".repeat(44),
            false,
        )
        .await,
        Err(AccountAccessStoreError::Conflict)
    ));
    drop(conn);
    assert_eq!(
        UserRepo::new(&pool)
            .get_by_id(user)
            .await
            .unwrap()
            .unwrap()
            .recovery_key_hash
            .as_deref(),
        Some("test-next-verifier")
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn receipts_are_exact_and_abandon_preserves_the_successor() {
    let pool = setup_db().await;
    let (user, _) = account(&pool).await;
    let repo = RecoveryRepo::new(&pool);
    let state = repo.account_state(user).await.unwrap().unwrap();
    let id = Uuid::new_v4();
    let first = repo.start(start(user, id, &state, 3)).await.unwrap();
    assert_eq!(repo.start(start(user, id, &state, 3)).await.unwrap(), first);
    assert!(matches!(
        repo.start(start(user, id, &state, 4)).await,
        Err(RecoveryStoreError::Conflict)
    ));
    let mutation = Uuid::new_v4();
    let step = || RecoveryMutation {
        user_id: user,
        operation_id: id,
        mutation_id: mutation,
        expected_revision: 1,
        request_digest: [5; 32],
    };
    let (a, b) = tokio::join!(repo.record_step(step()), repo.record_step(step()));
    assert_eq!(a.unwrap(), b.unwrap());
    let receipt = repo.record_step(step()).await.unwrap();
    assert_eq!(receipt.revision, 2);
    let mut wrong = step();
    wrong.request_digest = [6; 32];
    assert!(matches!(
        repo.record_step(wrong).await,
        Err(RecoveryStoreError::Conflict)
    ));
    repo.end(user, id, 2, RecoveryState::Abandoned)
        .await
        .unwrap();
    let state = repo.account_state(user).await.unwrap().unwrap();
    assert!(state.active_recovery_id.is_none());
    assert_eq!(state.auth_epoch, 2);
    let mut successor = start(user, Uuid::new_v4(), &state, 7);
    successor.expected_code_hash = "test-next-verifier";
    successor.successor_code_hash = "test-third-verifier";
    assert_eq!(repo.start(successor).await.unwrap().auth_epoch, 3);
    let counts =
        query::<Postgres>("SELECT active_count,retained_count FROM account_recovery_quota")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(counts.get::<i32, _>("active_count"), 1);
    assert_eq!(counts.get::<i32, _>("retained_count"), 2);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn quota_failure_rolls_back_supersession_and_authority() {
    let pool = setup_db().await;
    let (user, _) = account(&pool).await;
    let repo = RecoveryRepo::new(&pool);
    let state = repo.account_state(user).await.unwrap().unwrap();
    let id = Uuid::new_v4();
    repo.start(start(user, id, &state, 1)).await.unwrap();
    query::<Postgres>("UPDATE account_recovery_quota SET retained_count=8192 WHERE singleton")
        .execute(&pool)
        .await
        .unwrap();
    let state = repo.account_state(user).await.unwrap().unwrap();
    let mut next = start(user, Uuid::new_v4(), &state, 2);
    next.expected_code_hash = "test-next-verifier";
    next.successor_code_hash = "test-third-verifier";
    assert!(matches!(
        repo.start(next).await,
        Err(RecoveryStoreError::Capacity)
    ));
    assert_eq!(repo.account_state(user).await.unwrap().unwrap(), state);
    assert_eq!(
        repo.get(id).await.unwrap().unwrap().status.state,
        RecoveryState::Consumed
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn refresh_is_single_use_even_without_recovery() {
    let pool = setup_db().await;
    let (_, session) = account(&pool).await;
    let repo = SessionRepo::new(&pool);
    let (a, b) = tokio::join!(
        repo.update_refresh_token(
            &session,
            "a",
            session.access_expires_at,
            "ra",
            session.expires_at
        ),
        repo.update_refresh_token(
            &session,
            "b",
            session.access_expires_at,
            "rb",
            session.expires_at
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let loser = if a.is_err() { a } else { b };
    assert!(matches!(loser, Err(SessionWriteError::Invalidated)));
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn expiry_and_retention_are_bounded_and_preserve_the_live_code() {
    let pool = setup_db().await;
    let (user, _) = account(&pool).await;
    let repo = RecoveryRepo::new(&pool);
    let state = repo.account_state(user).await.unwrap().unwrap();
    let id = Uuid::new_v4();
    repo.start(start(user, id, &state, 8)).await.unwrap();
    query::<Postgres>("UPDATE account_recovery_operations SET created_at=CURRENT_TIMESTAMP-INTERVAL '25 hours', expires_at=CURRENT_TIMESTAMP-INTERVAL '1 hour' WHERE id=$1").bind(id).execute(&pool).await.unwrap();
    assert_eq!(repo.maintain().await.unwrap(), 0);
    assert_eq!(
        repo.get(id).await.unwrap().unwrap().status.state,
        RecoveryState::Expired
    );
    let state = repo.account_state(user).await.unwrap().unwrap();
    assert_eq!(state.auth_epoch, 2);
    assert!(state.active_recovery_id.is_none());
    assert_eq!(
        UserRepo::new(&pool)
            .get_by_id(user)
            .await
            .unwrap()
            .unwrap()
            .recovery_key_hash
            .as_deref(),
        Some("test-next-verifier")
    );
    query::<Postgres>("UPDATE account_recovery_operations SET updated_at=CURRENT_TIMESTAMP-INTERVAL '8 days' WHERE id=$1").bind(id).execute(&pool).await.unwrap();
    assert_eq!(repo.maintain().await.unwrap(), 1);
    assert!(repo.get(id).await.unwrap().is_none());
    let quota = query::<Postgres>("SELECT active_count,retained_count FROM account_recovery_quota")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(quota.get::<i32, _>("active_count"), 0);
    assert_eq!(quota.get::<i32, _>("retained_count"), 0);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn forward_migration_preserves_existing_credentials_and_ciphertext() {
    let pool = support::setup_empty_db().await;
    for sql in [
        include_str!("../../zann-server/migrations/0001_init.sql"),
        include_str!("../../zann-server/migrations/0002_changes_current_generation.sql"),
        include_str!("../../zann-server/migrations/0003_scoped_item_type_retype.sql"),
    ] {
        sqlx_core::raw_sql::raw_sql(sql)
            .execute(&pool)
            .await
            .unwrap();
    }
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let session = Uuid::new_v4();
    let vault = Uuid::new_v4();
    query::<Postgres>("INSERT INTO users (id,email,kdf_salt,recovery_key_hash,created_at,updated_at) VALUES ($1,'legacy@example.test','test-salt','legacy-code-verifier',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
        .bind(user).execute(&pool).await.unwrap();
    query::<Postgres>("INSERT INTO devices (id,user_id,name,fingerprint,created_at) VALUES ($1,$2,'legacy','test',CURRENT_TIMESTAMP)").bind(device).bind(user).execute(&pool).await.unwrap();
    query::<Postgres>("INSERT INTO sessions (id,user_id,device_id,access_token_hash,access_expires_at,refresh_token_hash,expires_at,created_at) VALUES ($1,$2,$3,'legacy-access',CURRENT_TIMESTAMP+INTERVAL '1 hour','legacy-refresh',CURRENT_TIMESTAMP+INTERVAL '1 day',CURRENT_TIMESTAMP)")
        .bind(session).bind(user).bind(device).execute(&pool).await.unwrap();
    query::<Postgres>("INSERT INTO vaults (id,slug,name,kind,encryption_type,vault_key_enc,cache_policy,created_at) VALUES ($1,'legacy','legacy',1,1,$2,1,CURRENT_TIMESTAMP)")
        .bind(vault).bind(b"opaque-personal-v1".as_slice()).execute(&pool).await.unwrap();
    sqlx_core::raw_sql::raw_sql(include_str!(
        "../../zann-server/migrations/0004_account_recovery.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx_core::raw_sql::raw_sql(include_str!(
        "../../zann-server/migrations/0005_account_passkeys.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();

    let state = RecoveryRepo::new(&pool)
        .account_state(user)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.auth_epoch, 1);
    assert_eq!(state.recovery_key_version, 1);
    assert!(SessionRepo::new(&pool)
        .get_by_access_token_hash("legacy-access")
        .await
        .unwrap()
        .is_some());
    let ciphertext: Vec<u8> = query::<Postgres>("SELECT vault_key_enc FROM vaults WHERE id=$1")
        .bind(vault)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("vault_key_enc");
    assert_eq!(ciphertext, b"opaque-personal-v1");
}
