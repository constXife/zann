use zann_core::SecurityProfileRegistry;

const SECURITY_PROFILES_YAML: &str = include_str!("../../../../schemas/security_profiles.yaml");

pub fn load_security_profiles() -> SecurityProfileRegistry {
    SecurityProfileRegistry::from_yaml(SECURITY_PROFILES_YAML).unwrap_or_else(|err| {
        tracing::warn!(event = "security_profiles_parse_failed", error = %err);
        SecurityProfileRegistry::from_yaml("profiles: {}").expect("empty security profile registry")
    })
}
