use regex::Regex;
use zann_core::secrets::{EncryptedPayload, FieldKind};

use crate::{data, AutofillError, MatchRules, SiteUrl, MATCH_RULES_KEY};

/// Presentation priority among already admitted matches. Never grants access.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum MatchQuality {
    Exact,
    Origin,
    Domain,
    Equivalent,
    Pattern,
}

/// Compile once per candidate, then evaluate bounded browser-supplied URLs.
/// Carries no password, TOTP, master key or payload reference.
pub struct LoginMatcher {
    site: SiteUrl,
    rules: MatchRules,
    regex: Option<Regex>,
}

impl LoginMatcher {
    pub fn new(site: SiteUrl, rules: MatchRules) -> Result<Self, AutofillError> {
        let regex = rules.compile_regex()?;
        Ok(Self { site, rules, regex })
    }

    pub fn from_payload(payload: &EncryptedPayload) -> Result<Self, AutofillError> {
        if payload.type_id != "login" {
            return Err(AutofillError::Login);
        }
        let rules = MatchRules::from_field(payload.fields.get(MATCH_RULES_KEY))?;
        let field = payload.fields.get("url").ok_or(AutofillError::Login)?;
        if field.kind != FieldKind::Url {
            return Err(AutofillError::Login);
        }
        Self::new(SiteUrl::parse(&field.value)?, rules)
    }

    pub fn matches(&self, target: &SiteUrl) -> bool {
        if !self.site.same_transport(target) {
            return false;
        }
        match &self.rules {
            MatchRules::Never => false,
            MatchRules::Exact => self.site == *target,
            MatchRules::Host => self.site.same_origin(target),
            MatchRules::Regex { .. } => self
                .regex
                .as_ref()
                .is_some_and(|r| r.is_match(target.as_str())),
            MatchRules::RegistrableDomain => {
                match (self.site.registrable_domain(), target.registrable_domain()) {
                    (Some(a), Some(b)) => a == b || data::equivalent(a, b),
                    // An explicit origin identity is safe for IPs and localhost;
                    // bare public suffixes must never match as credential sites.
                    (None, None) => data::local_host(&self.site) && self.site.same_origin(target),
                    _ => false,
                }
            }
        }
    }

    pub fn match_quality(&self, target: &SiteUrl) -> Option<MatchQuality> {
        if !self.matches(target) {
            return None;
        }
        Some(if self.site == *target {
            MatchQuality::Exact
        } else if self.site.same_origin(target) {
            MatchQuality::Origin
        } else {
            match (self.site.registrable_domain(), target.registrable_domain()) {
                (Some(a), Some(b)) if a == b => MatchQuality::Domain,
                (Some(a), Some(b)) if data::equivalent(a, b) => MatchQuality::Equivalent,
                _ => MatchQuality::Pattern,
            }
        })
    }
}
