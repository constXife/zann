use zann_core::SecurityProfileRegistry;

const SECURITY_PROFILES_YAML: &str = include_str!("../../../../schemas/security_profiles.yaml");

pub fn load_security_profiles() -> SecurityProfileRegistry {
    SecurityProfileRegistry::from_yaml(SECURITY_PROFILES_YAML).unwrap_or_else(|err| {
        tracing::warn!(event = "security_profiles_parse_failed", error = %err);
        SecurityProfileRegistry::from_yaml("profiles: {}").expect("empty security profile registry")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::secrets::service::{SECRET_TYPE_ID, SECRET_VALUE_FIELD};

    /// The schemas cover only the types they name; `zann-ui-core` checks that
    /// every named type has a category, so the server's own type must be named.
    #[test]
    fn server_secret_type_has_a_schema_profile() {
        let registry = SecurityProfileRegistry::from_yaml(SECURITY_PROFILES_YAML)
            .expect("security profiles parse");
        let profile = registry
            .profile(SECRET_TYPE_ID)
            .expect("secret security profile");
        assert_eq!(profile.ui.masked_by_default, [SECRET_VALUE_FIELD]);
        assert_eq!(profile.never_log_fields, [SECRET_VALUE_FIELD]);
    }
}
