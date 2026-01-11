use glob::Pattern;
use serde::{Deserialize, Serialize};
use zann_core::Identity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub subject_type: SubjectType,
    pub subject_id: Option<String>,
    pub effect: Effect,
    pub actions: Vec<String>,
    pub resource: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    User,
    Group,
    Device,
    ServiceAccount,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct PolicySet {
    rules: Vec<PolicyRule>,
    default_allow: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    NoMatch,
}

impl PolicySet {
    #[allow(dead_code)]
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            rules: Vec::new(),
            default_allow: true,
        }
    }

    #[must_use]
    pub fn from_rules(rules: Vec<PolicyRule>) -> Self {
        Self {
            rules,
            default_allow: false,
        }
    }

    #[must_use]
    pub fn is_allowed(&self, identity: &Identity, action: &str, resource: &str) -> bool {
        matches!(
            self.evaluate(identity, action, resource),
            PolicyDecision::Allow
        )
    }

    #[must_use]
    pub fn evaluate(&self, identity: &Identity, action: &str, resource: &str) -> PolicyDecision {
        let mut any_allow = false;
        for rule in &self.rules {
            if !matches_subject(identity, rule) {
                continue;
            }
            if !matches_action(&rule.actions, action) {
                continue;
            }
            if !matches_pattern(&rule.resource, resource) {
                continue;
            }

            match rule.effect {
                Effect::Deny => return PolicyDecision::Deny,
                Effect::Allow => any_allow = true,
            }
        }

        if any_allow || self.default_allow {
            return PolicyDecision::Allow;
        }

        PolicyDecision::NoMatch
    }
}

fn matches_subject(identity: &Identity, rule: &PolicyRule) -> bool {
    match rule.subject_type {
        SubjectType::Any => true,
        SubjectType::User => rule
            .subject_id
            .as_deref()
            .is_some_and(|id| id == identity.user_id.to_string()),
        SubjectType::Group => rule
            .subject_id
            .as_deref()
            .is_some_and(|id| identity.groups.iter().any(|g| g == id)),
        SubjectType::Device => rule
            .subject_id
            .as_deref()
            .and_then(|id| identity.device_id.map(|dev| dev.to_string() == id))
            .unwrap_or(false),
        SubjectType::ServiceAccount => rule
            .subject_id
            .as_deref()
            .and_then(|id| identity.service_account_id.map(|sa| sa.to_string() == id))
            .unwrap_or(false),
    }
}

fn matches_action(actions: &[String], action: &str) -> bool {
    actions
        .iter()
        .any(|pattern| matches_pattern(pattern, action))
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    Pattern::new(pattern)
        .map(|compiled| compiled.matches(value))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{matches_pattern, PolicyDecision, PolicySet};
    use zann_core::{AuthSource, Identity};

    fn test_identity() -> Identity {
        Identity {
            user_id: uuid::Uuid::new_v4(),
            email: "test@example.com".to_string(),
            display_name: "Test".to_string(),
            avatar_url: None,
            avatar_initials: "T".to_string(),
            groups: Vec::new(),
            source: AuthSource::Internal,
            device_id: None,
            service_account_id: None,
        }
    }

    #[test]
    fn matches_pattern_allows_wildcards() {
        assert!(matches_pattern("*", "anything"));
        assert!(matches_pattern("vault/*", "vault/abc"));
        assert!(matches_pattern("vault/**", "vault/a/b"));
        assert!(matches_pattern("*a*b", "cab"));
    }

    #[test]
    fn matches_pattern_rejects_non_matching() {
        assert!(!matches_pattern("vault/*", "vault"));
        assert!(!matches_pattern("*a*b", "ba"));
        assert!(!matches_pattern("read", "write"));
    }

    #[test]
    fn empty_policy_set_denies_by_default() {
        let identity = test_identity();
        let policies = PolicySet::from_rules(Vec::new());
        assert!(!policies.is_allowed(&identity, "read", "vault/abc"));
    }

    #[test]
    fn allow_all_policy_set_allows() {
        let identity = test_identity();
        let policies = PolicySet::allow_all();
        assert_eq!(
            policies.evaluate(&identity, "read", "vault/abc"),
            PolicyDecision::Allow
        );
    }
}
