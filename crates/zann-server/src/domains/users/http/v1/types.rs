use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, JsonSchema)]
pub(crate) struct ErrorResponse {
    pub(crate) error: &'static str,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct ListUsersQuery {
    #[serde(default)]
    pub(crate) status: Option<i32>,
    #[serde(default)]
    pub(crate) sort: Option<String>,
    #[serde(default)]
    pub(crate) limit: Option<i64>,
    #[serde(default)]
    pub(crate) offset: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct CreateUserRequest {
    pub(crate) email: String,
    pub(crate) password: String,
    #[serde(default)]
    pub(crate) full_name: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct ResetPasswordRequest {
    #[serde(default)]
    pub(crate) password: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct UpdateMeRequest {
    #[serde(default)]
    pub(crate) full_name: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct ChangePasswordRequest {
    pub(crate) current_password: String,
    pub(crate) new_password: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct RecoveryKitResponse {
    pub(crate) recovery_key: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct UserResponse {
    pub(crate) id: String,
    pub(crate) email: String,
    pub(crate) full_name: Option<String>,
    pub(crate) display_name: String,
    pub(crate) avatar_url: Option<String>,
    pub(crate) avatar_initials: String,
    pub(crate) status: i32,
    pub(crate) created_at: String,
    pub(crate) last_login_at: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct UserListResponse {
    pub(crate) users: Vec<UserResponse>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ResetPasswordResponse {
    pub(crate) password: String,
}
