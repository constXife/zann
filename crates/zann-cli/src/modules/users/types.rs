use serde::Serialize;

#[derive(Serialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
}

#[derive(Serialize)]
pub struct ResetPasswordRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}
