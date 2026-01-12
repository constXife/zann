use zann_core::User;

use crate::infra::user_display::{avatar_initials_for_user, display_name_for_user};

use super::super::types::UserResponse;

pub(crate) fn user_response(user: User) -> UserResponse {
    let email = user.email.clone();
    let full_name = user.full_name.clone();
    let display_name = display_name_for_user(full_name.as_deref(), &email);
    let avatar_initials = avatar_initials_for_user(full_name.as_deref(), &email);
    UserResponse {
        id: user.id.to_string(),
        email,
        full_name,
        display_name,
        avatar_url: None,
        avatar_initials,
        status: user.status.as_i32(),
        created_at: user.created_at.to_rfc3339(),
        last_login_at: user.last_login_at.map(|value| value.to_rfc3339()),
    }
}
