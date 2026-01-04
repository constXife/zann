use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
pub struct CreateGroupRequest {
    pub slug: String,
    pub name: String,
}

#[derive(Serialize)]
pub struct UpdateGroupRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct AddMemberRequest {
    pub user_id: Uuid,
}
