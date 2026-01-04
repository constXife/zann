use zann_core::SecurityProfileRegistry;

const SECURITY_PROFILES_YAML: &str = include_str!("../../../schemas/security_profiles.yaml");

pub fn load_security_profiles() -> SecurityProfileRegistry {
    SecurityProfileRegistry::from_yaml(SECURITY_PROFILES_YAML)
        .expect("failed to parse security profiles")
}
