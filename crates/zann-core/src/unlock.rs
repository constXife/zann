//! Password creation policy shared by local custody and presentation.
use crate::passwords::normalized_password_length;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NewPasswordError {
    TooShort,
    EdgeWhitespace,
}
impl NewPasswordError {
    pub fn code(self) -> &'static str {
        match self {
            Self::TooShort => "new_password_too_short",
            Self::EdgeWhitespace => "new_password_edge_whitespace",
        }
    }
    pub fn message_key(self) -> &'static str {
        match self {
            Self::TooShort => "errors.new_password_too_short",
            Self::EdgeWhitespace => "errors.new_password_edge_whitespace",
        }
    }
}
impl std::fmt::Display for NewPasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooShort => "password must be at least 8 characters",
            Self::EdgeWhitespace => "password must not start or end with whitespace",
        })
    }
}
impl std::error::Error for NewPasswordError {}

pub fn validate_new_password(password: &str) -> Result<(), NewPasswordError> {
    if normalized_password_length(password) < 8 {
        return Err(NewPasswordError::TooShort);
    }
    if password.starts_with(char::is_whitespace) || password.ends_with(char::is_whitespace) {
        return Err(NewPasswordError::EdgeWhitespace);
    }
    Ok(())
}
