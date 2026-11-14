//! Value-free password creation feedback. This does not estimate crack times.
use zann_core::unlock::validate_new_password;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordFeedback {
    pub strength_key: Option<&'static str>,
    pub validation_key: Option<&'static str>,
}

pub fn password_feedback(password: &str) -> PasswordFeedback {
    if password.is_empty() {
        return PasswordFeedback {
            strength_key: None,
            validation_key: None,
        };
    }
    let score = zxcvbn::zxcvbn(password, &[]).score();
    let strength_key = match score {
        zxcvbn::Score::Zero | zxcvbn::Score::One | zxcvbn::Score::Two => {
            Some("wizard.strength.weak")
        }
        zxcvbn::Score::Three => Some("wizard.strength.medium"),
        zxcvbn::Score::Four => Some("wizard.strength.strong"),
        _ => None,
    };
    PasswordFeedback {
        strength_key,
        validation_key: validate_new_password(password)
            .err()
            .map(|e| e.message_key()),
    }
}

#[cfg(test)]
mod tests;
