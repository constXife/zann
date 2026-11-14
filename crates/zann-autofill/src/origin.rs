use publicsuffix::Psl;
use url::{Host, Url};

use crate::{data, AutofillError};

pub const MAX_URL_BYTES: usize = 8192;

/// A canonical, credential-free HTTP(S) URL, including path/query for exact
/// matching. Fragments are discarded; origins include scheme and effective port.
#[derive(Clone, Eq, PartialEq)]
pub struct SiteUrl(Url);

impl std::fmt::Debug for SiteUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SiteUrl(<redacted>)")
    }
}

impl SiteUrl {
    pub fn parse(input: &str) -> Result<Self, AutofillError> {
        if input.len() > MAX_URL_BYTES {
            return Err(AutofillError::UrlSize);
        }
        let lower = input.to_ascii_lowercase();
        if !(lower.starts_with("https://") || lower.starts_with("http://"))
            || input.chars().any(|c| c.is_control() || c.is_whitespace())
            || input.contains('\\')
        {
            return Err(AutofillError::UrlPolicy);
        }
        let authority = input
            .split_once("://")
            .expect("scheme checked")
            .1
            .split(['/', '?', '#'])
            .next()
            .expect("split has a first element");
        if authority.is_empty() || authority.contains('@') {
            return Err(AutofillError::UrlPolicy);
        }
        let mut url = Url::parse(input).map_err(AutofillError::Url)?;
        if !url.username().is_empty() || url.password().is_some() || !url.has_host() {
            return Err(AutofillError::UrlPolicy);
        }
        if let Some(Host::Domain(host)) = url.host() {
            // Reject trailing dots/empty labels instead of creating DNS aliases
            // which a caller might interpret differently from the browser.
            if host.len() > 253
                || host.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                })
            {
                return Err(AutofillError::UrlPolicy);
            }
        }
        url.set_fragment(None);
        Ok(Self(url))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// A save target never retains URL path, query tokens or fragments.
    pub fn origin_url(&self) -> String {
        format!("{}/", self.0.origin().ascii_serialization())
    }

    pub fn host(&self) -> &str {
        self.0.host_str().expect("SiteUrl has a host")
    }

    /// Includes PRIVATE suffixes (e.g. github.io), wildcard and exception rules.
    /// IPs, single-label names and bare public suffixes have no registrable domain.
    pub fn registrable_domain(&self) -> Option<&str> {
        let Host::Domain(host) = self.0.host()? else {
            return None;
        };
        let domain = data::suffixes().domain(host.as_bytes())?;
        std::str::from_utf8(domain.as_bytes()).ok()
    }

    pub fn same_origin(&self, other: &Self) -> bool {
        self.0.origin() == other.0.origin()
    }

    pub(crate) fn same_transport(&self, other: &Self) -> bool {
        self.0.scheme() == other.0.scheme()
            && self.0.port_or_known_default() == other.0.port_or_known_default()
    }

    pub(crate) fn https(&self) -> bool {
        self.0.scheme() == "https"
    }
}
