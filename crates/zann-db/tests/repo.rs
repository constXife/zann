#![cfg(feature = "postgres")]

use chrono::Utc;
use sqlx_core::pool::PoolOptions;
use sqlx_core::types::Json as SqlxJson;
use sqlx_postgres::{PgConnectOptions, Postgres};
use std::env;
use std::str::FromStr;
use uuid::Uuid;
use zann_core::{
    CachePolicy, Device, Group, GroupMember, Item, ServiceAccount, ServiceAccountSession, User,
    UserStatus, Vault, VaultKind,
};
use zann_db::repo::{
    ChangeRepo, DeviceRepo, GroupMemberRepo, GroupRepo, ItemRepo, ServiceAccountRepo,
    ServiceAccountSessionRepo, UserRepo, VaultMemberRepo, VaultRepo,
};
use zann_db::{migrate, PgPool};

async fn setup_db() -> PgPool {
    let db_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set for Postgres tests");
    let schema = format!("zann_db_test_{}", Uuid::now_v7().simple());
    let admin_options =
        PgConnectOptions::from_str(&db_url).expect("failed to parse TEST_DATABASE_URL");
    let admin_pool = PoolOptions::new()
        .max_connections(1)
        .connect_with(admin_options.clone())
        .await
        .expect("connect admin pool");
    sqlx_core::query::query::<Postgres>(&format!("CREATE SCHEMA \"{}\"", schema))
        .execute(&admin_pool)
        .await
        .expect("create schema");
    let options = admin_options.options([("search_path", schema.as_str())]);
    let pool = PoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("connect test pool");
    migrate(&pool).await.expect("migrate");
    pool
}

fn test_user(now: chrono::DateTime<Utc>, email: &str, full_name: Option<&str>) -> User {
    User {
        id: Uuid::now_v7(),
        email: email.to_string(),
        full_name: full_name.map(|value| value.to_string()),
        password_hash: None,
        kdf_salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        kdf_algorithm: "argon2id".to_string(),
        kdf_iterations: 3,
        kdf_memory_kb: 65536,
        kdf_parallelism: 4,
        recovery_key_hash: None,
        status: UserStatus::Active,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        row_version: 1,
        created_at: now,
        updated_at: now,
        last_login_at: None,
    }
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn user_repo_crud_and_list() {
    let pool = setup_db().await;
    let repo = UserRepo::new(&pool);

    let now = Utc::now();
    let user_a = test_user(now, "alpha@example.com", Some("Alpha"));
    let user_b = test_user(now, "beta@example.com", None);

    repo.create(&user_a).await.expect("create user_a");
    repo.create(&user_b).await.expect("create user_b");

    repo.update_full_name(user_a.id, user_a.row_version, Some("Alpha Updated"))
        .await
        .expect("update full name");
    let updated = repo
        .get_by_id(user_a.id)
        .await
        .expect("get_by_id")
        .expect("user exists");
    assert_eq!(updated.full_name.as_deref(), Some("Alpha Updated"));

    let fetched = repo
        .get_by_email("alpha@example.com")
        .await
        .expect("get_by_email")
        .expect("user exists");
    assert_eq!(fetched.id, user_a.id);

    let user_b_db = repo
        .get_by_id(user_b.id)
        .await
        .expect("get_by_id")
        .expect("user exists");
    let affected = repo
        .update_status(user_b.id, user_b_db.row_version, UserStatus::Disabled)
        .await
        .expect("update status");
    assert_eq!(affected, 1);

    let active = repo
        .list(10, 0, "asc", Some(UserStatus::Active))
        .await
        .expect("list active");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, user_a.id);

    let disabled = repo
        .list(10, 0, "asc", Some(UserStatus::Disabled))
        .await
        .expect("list disabled");
    assert_eq!(disabled.len(), 1);
    assert_eq!(disabled[0].id, user_b.id);

    let user_b_db = repo
        .get_by_id(user_b.id)
        .await
        .expect("get_by_id")
        .expect("user exists");
    let affected = repo
        .delete_by_id(user_b.id, user_b_db.row_version, now, user_a.id, None)
        .await
        .expect("delete user_b");
    assert_eq!(affected, 1);
    let remaining = repo.list(10, 0, "asc", None).await.expect("list");
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, user_a.id);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn group_repo_crud_and_members() {
    let pool = setup_db().await;
    let group_repo = GroupRepo::new(&pool);
    let member_repo = GroupMemberRepo::new(&pool);
    let user_repo = UserRepo::new(&pool);

    let now = Utc::now();
    let group = Group {
        id: Uuid::now_v7(),
        slug: "devs".to_string(),
        name: "Developers".to_string(),
        created_at: now,
    };
    group_repo.create(&group).await.expect("create group");

    let fetched = group_repo
        .get_by_slug("devs")
        .await
        .expect("get_by_slug")
        .expect("group exists");
    assert_eq!(fetched.id, group.id);

    let updated = group_repo
        .update(group.id, "developers", "Dev Team")
        .await
        .expect("update group");
    assert_eq!(updated, 1);

    let renamed = group_repo
        .get_by_slug("developers")
        .await
        .expect("get_by_slug")
        .expect("group exists");
    assert_eq!(renamed.name, "Dev Team");

    let list = group_repo.list(10, 0, "asc").await.expect("list");
    assert_eq!(list.len(), 1);

    let user = test_user(now, "member@example.com", None);
    user_repo.create(&user).await.expect("create user");

    let member = GroupMember {
        group_id: renamed.id,
        user_id: user.id,
        created_at: now,
    };
    member_repo.create(&member).await.expect("create member");

    let members = member_repo
        .list_by_group(renamed.id)
        .await
        .expect("list_by_group");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].user_id, user.id);

    let deleted = member_repo
        .delete(renamed.id, user.id)
        .await
        .expect("delete member");
    assert_eq!(deleted, 1);

    let deleted_group = group_repo
        .delete_by_id(renamed.id)
        .await
        .expect("delete group");
    assert_eq!(deleted_group, 1);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn device_repo_crud_and_revoke() {
    let pool = setup_db().await;
    let user_repo = UserRepo::new(&pool);
    let device_repo = DeviceRepo::new(&pool);

    let now = Utc::now();
    let user = test_user(now, "device@example.com", None);
    user_repo.create(&user).await.expect("create user");

    let device = Device {
        id: Uuid::now_v7(),
        user_id: user.id,
        name: "ci-runner".to_string(),
        fingerprint: "sha256:test".to_string(),
        os: Some("linux".to_string()),
        os_version: Some("6.1".to_string()),
        app_version: Some("0.1.0".to_string()),
        last_seen_at: None,
        last_ip: None,
        revoked_at: None,
        created_at: now,
    };
    device_repo.create(&device).await.expect("create device");

    let fetched = device_repo
        .get_by_id(device.id)
        .await
        .expect("get_by_id")
        .expect("device exists");
    assert_eq!(fetched.id, device.id);

    let list = device_repo
        .list_by_user(user.id, 10, 0, "asc")
        .await
        .expect("list_by_user");
    assert_eq!(list.len(), 1);

    let revoked = device_repo
        .revoke(device.id, Utc::now())
        .await
        .expect("revoke");
    assert_eq!(revoked, 1);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn service_account_repo_crud() {
    let pool = setup_db().await;
    let user_repo = UserRepo::new(&pool);
    let sa_repo = ServiceAccountRepo::new(&pool);
    let sa_session_repo = ServiceAccountSessionRepo::new(&pool);

    let now = Utc::now();
    let user = test_user(now, "sa@example.com", None);
    user_repo.create(&user).await.expect("create user");

    let account = ServiceAccount {
        id: Uuid::now_v7(),
        owner_user_id: user.id,
        name: "ci".to_string(),
        description: Some("CI token".to_string()),
        token_hash: "hash".to_string(),
        token_prefix: "zann_sa_abc".to_string(),
        scopes: SqlxJson(vec!["vault:read".to_string()]),
        allowed_ips: Some(SqlxJson(vec!["10.0.0.0/8".to_string()])),
        expires_at: None,
        last_used_at: None,
        last_used_ip: None,
        last_used_user_agent: None,
        use_count: 0,
        created_at: now,
        revoked_at: None,
    };
    sa_repo
        .create(&account)
        .await
        .expect("create service account");

    let fetched = sa_repo
        .get_by_id(account.id)
        .await
        .expect("get_by_id")
        .expect("account exists");
    assert_eq!(fetched.name, account.name);

    let by_prefix = sa_repo
        .list_by_prefix(&account.token_prefix)
        .await
        .expect("list_by_prefix");
    assert_eq!(by_prefix.len(), 1);

    let list = sa_repo
        .list_by_owner(user.id, 10, 0, "asc")
        .await
        .expect("list_by_owner");
    assert_eq!(list.len(), 1);

    let updated = sa_repo
        .update_usage(account.id, now, Some("10.0.0.1"), Some("tests"), 1)
        .await
        .expect("update_usage");
    assert_eq!(updated, 1);

    let updated = sa_repo
        .update_token(account.id, "new_hash", "zann_sa_new")
        .await
        .expect("update_token");
    assert_eq!(updated, 1);

    let session = ServiceAccountSession {
        id: Uuid::now_v7(),
        service_account_id: account.id,
        access_token_hash: "access".to_string(),
        expires_at: now + chrono::Duration::hours(1),
        created_at: now,
    };
    sa_session_repo
        .create(&session)
        .await
        .expect("create session");

    let fetched_session = sa_session_repo
        .get_by_access_token_hash("access")
        .await
        .expect("get_by_access_token_hash")
        .expect("session exists");
    assert_eq!(fetched_session.id, session.id);

    let deleted = sa_session_repo
        .revoke_by_service_account(account.id)
        .await
        .expect("revoke_by_service_account");
    assert_eq!(deleted, 1);

    let revoked = sa_repo
        .revoke(account.id, Utc::now())
        .await
        .expect("revoke");
    assert_eq!(revoked, 1);
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn vault_and_item_repos_workflow() {
    let pool = setup_db().await;
    let user_repo = UserRepo::new(&pool);
    let device_repo = DeviceRepo::new(&pool);
    let vault_repo = VaultRepo::new(&pool);
    let vault_member_repo = VaultMemberRepo::new(&pool);
    let item_repo = ItemRepo::new(&pool);
    let change_repo = ChangeRepo::new(&pool);

    let now = Utc::now();
    let user = test_user(now, "vault@example.com", None);
    user_repo.create(&user).await.expect("create user");

    let device = Device {
        id: Uuid::now_v7(),
        user_id: user.id,
        name: "device".to_string(),
        fingerprint: "sha256:test".to_string(),
        os: Some("linux".to_string()),
        os_version: None,
        app_version: None,
        last_seen_at: None,
        last_ip: None,
        revoked_at: None,
        created_at: now,
    };
    device_repo.create(&device).await.expect("create device");

    let vault = Vault {
        id: Uuid::now_v7(),
        slug: "personal".to_string(),
        name: "Personal".to_string(),
        kind: VaultKind::Personal,
        encryption_type: zann_core::VaultEncryptionType::Client,
        vault_key_enc: vec![1, 2, 3],
        cache_policy: CachePolicy::Full,
        tags: None,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        row_version: 1,
        created_at: now,
    };
    vault_repo.create(&vault).await.expect("create vault");

    let member = zann_core::VaultMember {
        vault_id: vault.id,
        user_id: user.id,
        role: zann_core::VaultMemberRole::Admin,
        created_at: now,
    };
    vault_member_repo
        .create(&member)
        .await
        .expect("create member");

    let list = vault_repo
        .list_by_user(user.id, 10, 0, "asc")
        .await
        .expect("list_by_user");
    assert_eq!(list.len(), 1);

    let item = Item {
        id: Uuid::now_v7(),
        vault_id: vault.id,
        path: "db/postgres".to_string(),
        name: "postgres".to_string(),
        type_id: "secret".to_string(),
        tags: Some(SqlxJson(vec!["db".to_string()])),
        favorite: false,
        payload_enc: vec![9, 9, 9],
        checksum: "checksum".to_string(),
        version: 1,
        row_version: 1,
        device_id: device.id,
        sync_status: zann_core::SyncStatus::Active,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        created_at: now,
        updated_at: now,
    };
    item_repo.create(&item).await.expect("create item");

    let list_items = item_repo
        .list_by_vault(vault.id, false)
        .await
        .expect("list_by_vault");
    assert_eq!(list_items.len(), 1);

    let mut updated_item = item.clone();
    updated_item.version = 2;
    updated_item.payload_enc = vec![8, 8, 8];
    updated_item.checksum = "checksum-updated".to_string();
    updated_item.updated_at = Utc::now();
    let updated = item_repo.update(&updated_item).await.expect("update item");
    assert_eq!(updated, 1);

    let change = zann_core::Change {
        seq: 0,
        vault_id: vault.id,
        item_id: item.id,
        op: zann_core::ChangeOp::Update,
        version: updated_item.version,
        device_id: device.id,
        created_at: updated_item.updated_at,
    };
    change_repo.create(&change).await.expect("create change");

    let last_seq = change_repo
        .last_seq_for_vault(vault.id)
        .await
        .expect("last_seq");
    assert!(last_seq >= 1);
}
