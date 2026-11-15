//! WebAuthn RP IDs share the pinned PSL and canonical URL parser with autofill.
use crate::{authorize_credential_context, AutofillError, SiteUrl};

/// Evidence from the browser's Permissions Policy / OS provider, never a page
/// message. It is intentionally neither serializable nor inferred from a URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossOriginPermission {
    Denied,
    GrantedByBrowser,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RpId(String);

impl std::fmt::Debug for RpId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RpId(<redacted>)")
    }
}

impl RpId {
    /// Canonical ASCII domain only: no scheme, path, port, IP or public suffix.
    pub fn parse(value: &str) -> Result<Self, AutofillError> {
        if value.is_empty() || value.len() > 253 {
            return Err(AutofillError::RpId);
        }
        let site = SiteUrl::parse(&format!("https://{value}/"))?;
        if site.host() != value
            || site.as_str() != format!("https://{value}/")
            || (site.registrable_domain().is_none() && value != "localhost")
        {
            return Err(AutofillError::RpId);
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Inputs MUST come from a trusted browser/OS adapter, never a page claim.
    pub fn authorize(
        &self,
        top: &SiteUrl,
        frame: &SiteUrl,
        permission: CrossOriginPermission,
    ) -> Result<(), AutofillError> {
        if top.same_origin(frame) || permission == CrossOriginPermission::Denied {
            authorize_credential_context(top, frame).map_err(AutofillError::RpContext)?;
        } else if !top.https() || !frame.https() {
            return Err(AutofillError::RpContext(
                crate::FillDenied::InsecureTransport,
            ));
        }
        let host = frame.host();
        if host != self.0 && !host.strip_suffix(&self.0).is_some_and(|s| s.ends_with('.')) {
            return Err(AutofillError::RpId);
        }
        Ok(())
    }
}
