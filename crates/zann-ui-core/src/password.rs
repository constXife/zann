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
mod tests {
    use super::*;
    #[test]
    fn unicode_policy_and_feedback_do_not_change_existing_input() {
        assert_eq!(password_feedback("").strength_key, None);
        assert_eq!(
            password_feedback(" words with spaces").validation_key,
            Some("errors.new_password_edge_whitespace")
        );
        assert_eq!(password_feedback("words with spaces").validation_key, None);
        assert_eq!(
            password_feedback("aaaaaaaaaaaaaaaaaaaaaaaa").strength_key,
            Some("wizard.strength.weak")
        );
        assert_eq!(
            password_feedback("several separate long words").strength_key,
            Some("wizard.strength.strong")
        );
        assert_eq!(
            password_feedback("ééééééé").validation_key,
            password_feedback("e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}")
                .validation_key
        );
    }
}

#[cfg(test)]
mod translation_tests {
    use super::*;
    #[test]
    fn all_creation_feedback_keys_exist_in_both_catalogues() {
        for language in ["en", "ru"] {
            let catalogue = crate::Catalogue::new(language);
            for value in [
                "a",
                " short password ",
                "aaaaaaaaaaaaaaaaaaaaaaaa",
                "several separate long words",
            ] {
                let feedback = password_feedback(value);
                for key in [feedback.strength_key, feedback.validation_key]
                    .into_iter()
                    .flatten()
                {
                    assert_ne!(catalogue.get(key), key, "{language}: {key}");
                }
            }
        }
    }
}
