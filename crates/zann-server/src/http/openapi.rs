use aide::axum::{
    routing::{delete, get, post, put},
    ApiRouter,
};
use aide::openapi::{Info, OpenApi};
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;
use schemars::JsonSchema;
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;
use zann_core::api::auth::{
    LoginRequest, LoginResponse, LogoutRequest, OidcConfigResponse, OidcLoginRequest,
    PreloginResponse, RefreshRequest, RegisterRequest,
};
use zann_core::api::vaults::VaultListResponse;
use zann_core::{AuthSource, ChangeType, CachePolicy, Identity, UserStatus, VaultEncryptionType, VaultKind};

use crate::app::AppState;
use crate::domains::access_control::http_admin::ReloadResponse;
use crate::domains::auth::http::v1::types::{
    PreloginQuery, ServiceAccountLoginRequest, ServiceAccountLoginResponse,
};
use crate::domains::devices::http::v1::{DeviceListResponse, DeviceResponse, ListDevicesQuery};
use crate::domains::groups::http::v1::{
    AddMemberRequest, CreateGroupRequest, GroupListResponse, GroupMemberResponse, GroupResponse,
    ListGroupsQuery, UpdateGroupRequest,
};
use crate::domains::items::http::v1::items_models::{
    CreateItemRequest, FileUploadResponse, HistoryListQuery, ItemHistoryDetailResponse,
    ItemHistoryListResponse, ItemResponse, ItemsResponse, UpdateItemRequest,
};
use crate::domains::members::http::v1::MembersResponse;
use crate::domains::secrets::http::v1::{
    BatchEnsureRequest, BatchGetRequest, BatchResult, SecretRequest, SecretResponse,
};
use crate::domains::sync::http::v1::types::{
    SyncPullRequest, SyncPullResponse, SyncPushRequest, SyncPushResponse, SyncSharedPullRequest,
    SyncSharedPullResponse, SyncSharedPushRequest,
};
use crate::domains::system::http::v1::{SecurityProfilesResponse, SystemInfoResponse};
use crate::domains::users::http::v1::types::{
    ChangePasswordRequest, CreateUserRequest, ListUsersQuery, RecoveryKitResponse,
    ResetPasswordRequest, ResetPasswordResponse, UpdateMeRequest, UserListResponse, UserResponse,
};
use crate::domains::vaults::http::v1::shared::types::{
    ItemHistoryDetailResponse as SharedHistoryDetailResponse,
    ItemHistoryListResponse as SharedHistoryListResponse, RotateAbortRequest, RotateStartRequest,
    RotationCandidateResponse, RotationCommitResponse, RotationStatusResponse, SharedItemResponse,
    SharedItemsQuery, SharedItemsResponse,
};
use crate::domains::vaults::http::v1::{
    CreateVaultRequest, ListVaultsQuery, UpdateVaultKeyRequest, VaultResponse,
};
use crate::http::routes::health::HealthResponse;

pub fn build_openapi() -> OpenApi {
    let mut api = OpenApi {
        info: Info {
            title: "zann-server".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let _ = doc_router().finish_api(&mut api);
    api
}

fn doc_router() -> ApiRouter<AppState> {
    ApiRouter::new()
        .api_route("/health", get(health))
        .api_route("/admin/policies/reload", post(admin_reload))
        .api_route("/v1/auth/register", post(auth_register))
        .api_route("/v1/auth/prelogin", get(auth_prelogin))
        .api_route("/v1/auth/login", post(auth_login))
        .api_route("/v1/auth/login/oidc", post(auth_login_oidc))
        .api_route("/v1/auth/service-account", post(auth_service_account))
        .api_route("/v1/auth/refresh", post(auth_refresh))
        .api_route("/v1/auth/logout", post(auth_logout))
        .api_route("/v1/auth/oidc/config", get(auth_oidc_config))
        .api_route("/v1/system/info", get(system_info))
        .api_route(
            "/v1/system/security-profiles",
            get(system_security_profiles),
        )
        .api_route("/v1/devices", get(devices_list))
        .api_route("/v1/devices/current", get(devices_current))
        .api_route("/v1/devices/:id", delete(devices_revoke))
        .api_route("/v1/groups", get(groups_list).post(groups_create))
        .api_route(
            "/v1/groups/:slug",
            get(groups_get).put(groups_update).delete(groups_delete),
        )
        .api_route("/v1/groups/:slug/members", post(groups_add_member))
        .api_route(
            "/v1/groups/:slug/members/:user_id",
            delete(groups_remove_member),
        )
        .api_route("/v1/vaults", get(vaults_list).post(vaults_create))
        .api_route(
            "/v1/vaults/:vault_id",
            get(vaults_get).delete(vaults_delete),
        )
        .api_route("/v1/vaults/:vault_id/key", put(vaults_update_key))
        .api_route("/v1/shared/items", get(shared_items_list))
        .api_route("/v1/shared/items/:item_id", get(shared_items_get))
        .api_route(
            "/v1/shared/items/:item_id/rotate/start",
            post(shared_rotate_start),
        )
        .api_route(
            "/v1/shared/items/:item_id/rotate/status",
            get(shared_rotate_status),
        )
        .api_route(
            "/v1/shared/items/:item_id/rotate/candidate",
            post(shared_rotate_candidate),
        )
        .api_route(
            "/v1/shared/items/:item_id/rotate/recover",
            post(shared_rotate_recover),
        )
        .api_route(
            "/v1/shared/items/:item_id/rotate/commit",
            post(shared_rotate_commit),
        )
        .api_route(
            "/v1/shared/items/:item_id/rotate/abort",
            post(shared_rotate_abort),
        )
        .api_route(
            "/v1/shared/items/:item_id/history",
            get(shared_history_list),
        )
        .api_route(
            "/v1/shared/items/:item_id/history/:version",
            get(shared_history_get),
        )
        .api_route(
            "/v1/vaults/:vault_id/items",
            get(items_list).post(items_create),
        )
        .api_route(
            "/v1/vaults/:vault_id/items/:item_id",
            get(items_get).put(items_update).delete(items_delete),
        )
        .api_route(
            "/v1/vaults/:vault_id/items/:item_id/file",
            get(items_file_download).post(items_file_upload),
        )
        .api_route(
            "/v1/vaults/:vault_id/items/:item_id/versions",
            get(items_history_list),
        )
        .api_route(
            "/v1/vaults/:vault_id/items/:item_id/versions/:version",
            get(items_history_get),
        )
        .api_route(
            "/v1/vaults/:vault_id/items/:item_id/versions/:version/restore",
            post(items_history_restore),
        )
        .api_route("/v1/vaults/:vault_id/members", get(members_list))
        .api_route("/v1/vaults/:vault_id/secrets/*path", get(secrets_get))
        .api_route("/v1/vaults/:vault_id/secrets/ensure", post(secrets_ensure))
        .api_route("/v1/vaults/:vault_id/secrets/rotate", post(secrets_rotate))
        .api_route(
            "/v1/vaults/:vault_id/secrets/batch/ensure",
            post(secrets_batch_ensure),
        )
        .api_route(
            "/v1/vaults/:vault_id/secrets/batch/get",
            post(secrets_batch_get),
        )
        .api_route("/v1/sync/pull", post(sync_pull))
        .api_route("/v1/sync/push", post(sync_push))
        .api_route("/v1/sync/shared/pull", post(sync_shared_pull))
        .api_route("/v1/sync/shared/push", post(sync_shared_push))
        .api_route("/v1/users/me", get(users_me).put(users_update_me))
        .api_route("/v1/users/me/password", post(users_change_password))
        .api_route("/v1/users/me/recovery-kit", post(users_recovery_kit))
        .api_route("/v1/users", get(users_list).post(users_create))
        .api_route("/v1/users/:id", get(users_get).delete(users_delete))
        .api_route("/v1/users/:id/block", post(users_block))
        .api_route("/v1/users/:id/unblock", post(users_unblock))
        .api_route("/v1/users/:id/reset-password", post(users_reset_password))
}

fn not_implemented<T>(body: T) -> (StatusCode, Json<T>) {
    (StatusCode::NOT_IMPLEMENTED, Json(body))
}

async fn health() -> (StatusCode, Json<HealthResponse>) {
    not_implemented(HealthResponse {
        status: "not_implemented",
        version: "0.0.0",
        build_commit: None,
        uptime_seconds: 0,
        components: HashMap::new(),
    })
}

async fn admin_reload() -> (StatusCode, Json<ReloadResponse>) {
    not_implemented(ReloadResponse {
        status: "not_implemented",
    })
}

async fn auth_register(Json(_payload): Json<RegisterRequest>) -> (StatusCode, Json<LoginResponse>) {
    not_implemented(LoginResponse {
        access_token: String::new(),
        refresh_token: String::new(),
        expires_in: 0,
    })
}

async fn auth_prelogin(
    Query(_query): Query<PreloginQuery>,
) -> (StatusCode, Json<PreloginResponse>) {
    not_implemented(PreloginResponse {
        kdf_salt: String::new(),
        kdf_params: zann_core::api::auth::KdfParams {
            algorithm: String::new(),
            iterations: 0,
            memory_kb: 0,
            parallelism: 0,
        },
        salt_fingerprint: String::new(),
    })
}

async fn auth_login(Json(_payload): Json<LoginRequest>) -> (StatusCode, Json<LoginResponse>) {
    not_implemented(LoginResponse {
        access_token: String::new(),
        refresh_token: String::new(),
        expires_in: 0,
    })
}

async fn auth_login_oidc(
    Json(_payload): Json<OidcLoginRequest>,
) -> (StatusCode, Json<LoginResponse>) {
    not_implemented(LoginResponse {
        access_token: String::new(),
        refresh_token: String::new(),
        expires_in: 0,
    })
}

async fn auth_service_account(
    Json(_payload): Json<ServiceAccountLoginRequest>,
) -> (StatusCode, Json<ServiceAccountLoginResponse>) {
    not_implemented(ServiceAccountLoginResponse {
        service_account_id: String::new(),
        owner_user_id: String::new(),
        access_token: String::new(),
        expires_in: 0,
        vault_keys: Vec::new(),
    })
}

async fn auth_refresh(Json(_payload): Json<RefreshRequest>) -> (StatusCode, Json<LoginResponse>) {
    not_implemented(LoginResponse {
        access_token: String::new(),
        refresh_token: String::new(),
        expires_in: 0,
    })
}

async fn auth_logout(Json(_payload): Json<LogoutRequest>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

async fn auth_oidc_config() -> (StatusCode, Json<OidcConfigResponse>) {
    not_implemented(OidcConfigResponse {
        issuer: String::new(),
        client_id: String::new(),
        audience: None,
        scopes: Vec::new(),
    })
}

async fn system_info() -> (StatusCode, Json<SystemInfoResponse>) {
    not_implemented(SystemInfoResponse {
        version: "0.0.0",
        build_commit: None,
        server_id: String::new(),
        identity: crate::domains::system::http::v1::SystemIdentity {
            public_key: String::new(),
            timestamp: 0,
            signature: String::new(),
        },
        server_name: None,
        server_fingerprint: String::new(),
        auth_methods: Vec::new(),
        personal_vaults_enabled: false,
    })
}

async fn system_security_profiles() -> (StatusCode, Json<SecurityProfilesResponse>) {
    not_implemented(SecurityProfilesResponse {
        profiles: HashMap::new(),
    })
}

async fn devices_list(
    Query(_query): Query<ListDevicesQuery>,
) -> (StatusCode, Json<DeviceListResponse>) {
    not_implemented(DeviceListResponse {
        devices: Vec::new(),
    })
}

async fn devices_current() -> (StatusCode, Json<DeviceResponse>) {
    not_implemented(DeviceResponse {
        id: String::new(),
        name: String::new(),
        fingerprint: String::new(),
        os: None,
        os_version: None,
        app_version: None,
        last_seen_at: None,
        last_ip: None,
        revoked_at: None,
        created_at: String::new(),
    })
}

async fn devices_revoke(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

async fn groups_list(
    Query(_query): Query<ListGroupsQuery>,
) -> (StatusCode, Json<GroupListResponse>) {
    not_implemented(GroupListResponse { groups: Vec::new() })
}

async fn groups_create(
    Json(_payload): Json<CreateGroupRequest>,
) -> (StatusCode, Json<GroupResponse>) {
    not_implemented(GroupResponse {
        id: String::new(),
        slug: String::new(),
        name: String::new(),
        created_at: String::new(),
    })
}

async fn groups_get(Path(_slug): Path<String>) -> (StatusCode, Json<GroupResponse>) {
    not_implemented(GroupResponse {
        id: String::new(),
        slug: String::new(),
        name: String::new(),
        created_at: String::new(),
    })
}

async fn groups_update(
    Path(_slug): Path<String>,
    Json(_payload): Json<UpdateGroupRequest>,
) -> (StatusCode, Json<GroupResponse>) {
    not_implemented(GroupResponse {
        id: String::new(),
        slug: String::new(),
        name: String::new(),
        created_at: String::new(),
    })
}

async fn groups_delete(Path(_slug): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

async fn groups_add_member(
    Path(_slug): Path<String>,
    Json(_payload): Json<AddMemberRequest>,
) -> (StatusCode, Json<GroupMemberResponse>) {
    not_implemented(GroupMemberResponse {
        group_id: String::new(),
        user_id: String::new(),
        created_at: String::new(),
    })
}

async fn groups_remove_member(Path((_slug, _user_id)): Path<(String, String)>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

async fn vaults_list(
    Query(_query): Query<ListVaultsQuery>,
) -> (StatusCode, Json<VaultListResponse>) {
    not_implemented(VaultListResponse { vaults: Vec::new() })
}

async fn vaults_create(
    Json(_payload): Json<CreateVaultRequest>,
) -> (StatusCode, Json<VaultResponse>) {
    not_implemented(VaultResponse {
        id: String::new(),
        slug: String::new(),
        name: String::new(),
        kind: VaultKind::Personal,
        cache_policy: CachePolicy::Full,
        vault_key_enc: Vec::new(),
        encryption_type: VaultEncryptionType::Client,
        tags: None,
        created_at: String::new(),
    })
}

async fn vaults_get(Path(_vault_id): Path<String>) -> (StatusCode, Json<VaultResponse>) {
    not_implemented(VaultResponse {
        id: String::new(),
        slug: String::new(),
        name: String::new(),
        kind: VaultKind::Personal,
        cache_policy: CachePolicy::Full,
        vault_key_enc: Vec::new(),
        encryption_type: VaultEncryptionType::Client,
        tags: None,
        created_at: String::new(),
    })
}

async fn vaults_delete(Path(_vault_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

async fn vaults_update_key(
    Path(_vault_id): Path<String>,
    Json(_payload): Json<UpdateVaultKeyRequest>,
) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

async fn shared_items_list(
    Query(_query): Query<SharedItemsQuery>,
) -> (StatusCode, Json<SharedItemsResponse>) {
    not_implemented(SharedItemsResponse {
        items: Vec::new(),
        next_cursor: None,
    })
}

async fn shared_items_get(Path(_item_id): Path<String>) -> (StatusCode, Json<SharedItemResponse>) {
    not_implemented(SharedItemResponse {
        id: String::new(),
        vault_id: String::new(),
        path: String::new(),
        name: String::new(),
        type_id: String::new(),
        tags: None,
        favorite: false,
        payload: json!({}),
        checksum: String::new(),
        version: 0,
        deleted_at: None,
        updated_at: String::new(),
    })
}

async fn shared_rotate_start(
    Path(_item_id): Path<String>,
    Json(_payload): Json<RotateStartRequest>,
) -> (StatusCode, Json<RotationStatusResponse>) {
    not_implemented(RotationStatusResponse {
        state: String::new(),
        started_at: None,
        started_by: None,
        expires_at: None,
        recover_until: None,
        aborted_reason: None,
    })
}

async fn shared_rotate_status(
    Path(_item_id): Path<String>,
) -> (StatusCode, Json<RotationStatusResponse>) {
    not_implemented(RotationStatusResponse {
        state: String::new(),
        started_at: None,
        started_by: None,
        expires_at: None,
        recover_until: None,
        aborted_reason: None,
    })
}

async fn shared_rotate_candidate(
    Path(_item_id): Path<String>,
) -> (StatusCode, Json<RotationCandidateResponse>) {
    not_implemented(RotationCandidateResponse {
        state: String::new(),
        candidate: String::new(),
        expires_at: None,
        recover_until: None,
    })
}

async fn shared_rotate_recover(
    Path(_item_id): Path<String>,
) -> (StatusCode, Json<RotationStatusResponse>) {
    not_implemented(RotationStatusResponse {
        state: String::new(),
        started_at: None,
        started_by: None,
        expires_at: None,
        recover_until: None,
        aborted_reason: None,
    })
}

async fn shared_rotate_commit(
    Path(_item_id): Path<String>,
) -> (StatusCode, Json<RotationCommitResponse>) {
    not_implemented(RotationCommitResponse {
        status: "not_implemented",
        version: 0,
    })
}

async fn shared_rotate_abort(
    Path(_item_id): Path<String>,
    Json(_payload): Json<RotateAbortRequest>,
) -> (StatusCode, Json<RotationStatusResponse>) {
    not_implemented(RotationStatusResponse {
        state: String::new(),
        started_at: None,
        started_by: None,
        expires_at: None,
        recover_until: None,
        aborted_reason: None,
    })
}

async fn shared_history_list(
    Path(_item_id): Path<String>,
) -> (StatusCode, Json<SharedHistoryListResponse>) {
    not_implemented(SharedHistoryListResponse {
        versions: Vec::new(),
    })
}

async fn shared_history_get(
    Path((_item_id, _version)): Path<(String, String)>,
) -> (StatusCode, Json<SharedHistoryDetailResponse>) {
    not_implemented(SharedHistoryDetailResponse {
        version: 0,
        checksum: String::new(),
        payload: json!({}),
        change_type: ChangeType::Update,
        created_at: String::new(),
    })
}

async fn items_list(Path(_vault_id): Path<String>) -> (StatusCode, Json<ItemsResponse>) {
    not_implemented(ItemsResponse { items: Vec::new() })
}

async fn items_create(
    Path(_vault_id): Path<String>,
    Json(_payload): Json<CreateItemRequest>,
) -> (StatusCode, Json<ItemResponse>) {
    not_implemented(ItemResponse {
        id: String::new(),
        vault_id: String::new(),
        path: String::new(),
        name: String::new(),
        type_id: String::new(),
        tags: None,
        favorite: false,
        payload_enc: Vec::new(),
        checksum: String::new(),
        version: 0,
        deleted_at: None,
        updated_at: String::new(),
    })
}

async fn items_get(
    Path((_vault_id, _item_id)): Path<(String, String)>,
) -> (StatusCode, Json<ItemResponse>) {
    not_implemented(ItemResponse {
        id: String::new(),
        vault_id: String::new(),
        path: String::new(),
        name: String::new(),
        type_id: String::new(),
        tags: None,
        favorite: false,
        payload_enc: Vec::new(),
        checksum: String::new(),
        version: 0,
        deleted_at: None,
        updated_at: String::new(),
    })
}

async fn items_update(
    Path((_vault_id, _item_id)): Path<(String, String)>,
    Json(_payload): Json<UpdateItemRequest>,
) -> (StatusCode, Json<ItemResponse>) {
    not_implemented(ItemResponse {
        id: String::new(),
        vault_id: String::new(),
        path: String::new(),
        name: String::new(),
        type_id: String::new(),
        tags: None,
        favorite: false,
        payload_enc: Vec::new(),
        checksum: String::new(),
        version: 0,
        deleted_at: None,
        updated_at: String::new(),
    })
}

async fn items_delete(Path((_vault_id, _item_id)): Path<(String, String)>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

async fn items_history_list(
    Path((_vault_id, _item_id)): Path<(String, String)>,
    Query(_query): Query<HistoryListQuery>,
) -> (StatusCode, Json<ItemHistoryListResponse>) {
    not_implemented(ItemHistoryListResponse {
        versions: Vec::new(),
    })
}

async fn items_history_get(
    Path((_vault_id, _item_id, _version)): Path<(String, String, String)>,
) -> (StatusCode, Json<ItemHistoryDetailResponse>) {
    not_implemented(ItemHistoryDetailResponse {
        version: 0,
        checksum: String::new(),
        payload_enc: Vec::new(),
        change_type: ChangeType::Update,
        created_at: String::new(),
    })
}

async fn items_history_restore(
    Path((_vault_id, _item_id, _version)): Path<(String, String, String)>,
) -> (StatusCode, Json<ItemResponse>) {
    not_implemented(ItemResponse {
        id: String::new(),
        vault_id: String::new(),
        path: String::new(),
        name: String::new(),
        type_id: String::new(),
        tags: None,
        favorite: false,
        payload_enc: Vec::new(),
        checksum: String::new(),
        version: 0,
        deleted_at: None,
        updated_at: String::new(),
    })
}

#[derive(serde::Deserialize, JsonSchema)]
#[allow(dead_code)]
struct FileUploadQuery {
    #[schemars(
        description = "plain = server decryptable (shared vaults), opaque = encrypted by client"
    )]
    representation: Option<String>,
    #[schemars(
        description = "Client-provided UUID for idempotent uploads; shared vaults must match item payload extra.file_id and upload_state=pending"
    )]
    file_id: Option<String>,
    #[schemars(description = "Optional filename metadata")]
    filename: Option<String>,
    #[schemars(description = "Optional MIME type override (otherwise Content-Type is used)")]
    mime: Option<String>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[allow(dead_code)]
struct FileDownloadQuery {
    #[schemars(
        description = "plain = server decryptable (shared vaults), opaque = ciphertext; shared vaults use payload extra.file_id when set"
    )]
    representation: Option<String>,
}

async fn items_file_upload(
    Path((_vault_id, _item_id)): Path<(String, String)>,
    Query(_query): Query<FileUploadQuery>,
) -> (StatusCode, Json<FileUploadResponse>) {
    not_implemented(FileUploadResponse {
        file_id: String::new(),
        upload_state: String::new(),
    })
}

async fn items_file_download(
    Path((_vault_id, _item_id)): Path<(String, String)>,
    Query(_query): Query<FileDownloadQuery>,
) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

async fn members_list(Path(_vault_id): Path<String>) -> (StatusCode, Json<MembersResponse>) {
    not_implemented(MembersResponse {
        members: Vec::new(),
    })
}

async fn secrets_get(
    Path((_vault_id, _path)): Path<(String, String)>,
) -> (StatusCode, Json<SecretResponse>) {
    not_implemented(SecretResponse {
        path: String::new(),
        vault_id: String::new(),
        value: String::new(),
        policy: String::new(),
        meta: None,
        version: 0,
        previous_version: None,
        created: None,
    })
}

async fn secrets_ensure(
    Path(_vault_id): Path<String>,
    Json(_payload): Json<SecretRequest>,
) -> (StatusCode, Json<SecretResponse>) {
    not_implemented(SecretResponse {
        path: String::new(),
        vault_id: String::new(),
        value: String::new(),
        policy: String::new(),
        meta: None,
        version: 0,
        previous_version: None,
        created: None,
    })
}

async fn secrets_rotate(
    Path(_vault_id): Path<String>,
    Json(_payload): Json<SecretRequest>,
) -> (StatusCode, Json<SecretResponse>) {
    not_implemented(SecretResponse {
        path: String::new(),
        vault_id: String::new(),
        value: String::new(),
        policy: String::new(),
        meta: None,
        version: 0,
        previous_version: None,
        created: None,
    })
}

async fn secrets_batch_ensure(
    Path(_vault_id): Path<String>,
    Json(_payload): Json<BatchEnsureRequest>,
) -> (StatusCode, Json<Vec<BatchResult>>) {
    not_implemented(Vec::new())
}

async fn secrets_batch_get(
    Path(_vault_id): Path<String>,
    Json(_payload): Json<BatchGetRequest>,
) -> (StatusCode, Json<Vec<BatchResult>>) {
    not_implemented(Vec::new())
}

async fn sync_pull(Json(_payload): Json<SyncPullRequest>) -> (StatusCode, Json<SyncPullResponse>) {
    not_implemented(SyncPullResponse {
        changes: Vec::new(),
        next_cursor: String::new(),
        has_more: false,
        push_available: false,
    })
}

async fn sync_push(Json(_payload): Json<SyncPushRequest>) -> (StatusCode, Json<SyncPushResponse>) {
    not_implemented(SyncPushResponse {
        applied: Vec::new(),
        applied_changes: Vec::new(),
        conflicts: Vec::new(),
        new_cursor: String::new(),
    })
}

async fn sync_shared_pull(
    Json(_payload): Json<SyncSharedPullRequest>,
) -> (StatusCode, Json<SyncSharedPullResponse>) {
    not_implemented(SyncSharedPullResponse {
        changes: Vec::new(),
        next_cursor: String::new(),
        has_more: false,
        push_available: false,
    })
}

async fn sync_shared_push(
    Json(_payload): Json<SyncSharedPushRequest>,
) -> (StatusCode, Json<SyncPushResponse>) {
    not_implemented(SyncPushResponse {
        applied: Vec::new(),
        applied_changes: Vec::new(),
        conflicts: Vec::new(),
        new_cursor: String::new(),
    })
}

async fn users_me() -> (StatusCode, Json<Identity>) {
    not_implemented(Identity {
        user_id: Uuid::nil(),
        email: String::new(),
        display_name: String::new(),
        avatar_url: None,
        avatar_initials: String::new(),
        groups: Vec::new(),
        source: AuthSource::Internal,
        device_id: None,
        service_account_id: None,
    })
}

async fn users_update_me(
    Json(_payload): Json<UpdateMeRequest>,
) -> (StatusCode, Json<UserResponse>) {
    not_implemented(UserResponse {
        id: String::new(),
        email: String::new(),
        full_name: None,
        display_name: String::new(),
        avatar_url: None,
        avatar_initials: String::new(),
        status: UserStatus::Active.as_i32(),
        created_at: String::new(),
        last_login_at: None,
    })
}

async fn users_change_password(Json(_payload): Json<ChangePasswordRequest>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

async fn users_recovery_kit() -> (StatusCode, Json<RecoveryKitResponse>) {
    not_implemented(RecoveryKitResponse {
        recovery_key: String::new(),
    })
}

async fn users_list(Query(_query): Query<ListUsersQuery>) -> (StatusCode, Json<UserListResponse>) {
    not_implemented(UserListResponse { users: Vec::new() })
}

async fn users_create(Json(_payload): Json<CreateUserRequest>) -> (StatusCode, Json<UserResponse>) {
    not_implemented(UserResponse {
        id: String::new(),
        email: String::new(),
        full_name: None,
        display_name: String::new(),
        avatar_url: None,
        avatar_initials: String::new(),
        status: UserStatus::Active.as_i32(),
        created_at: String::new(),
        last_login_at: None,
    })
}

async fn users_get(Path(_id): Path<String>) -> (StatusCode, Json<UserResponse>) {
    not_implemented(UserResponse {
        id: String::new(),
        email: String::new(),
        full_name: None,
        display_name: String::new(),
        avatar_url: None,
        avatar_initials: String::new(),
        status: UserStatus::Active.as_i32(),
        created_at: String::new(),
        last_login_at: None,
    })
}

async fn users_delete(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

async fn users_block(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

async fn users_unblock(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

async fn users_reset_password(
    Path(_id): Path<String>,
    Json(_payload): Json<ResetPasswordRequest>,
) -> (StatusCode, Json<ResetPasswordResponse>) {
    not_implemented(ResetPasswordResponse {
        password: String::new(),
    })
}
