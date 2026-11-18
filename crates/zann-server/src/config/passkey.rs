use serde::{Deserialize, Serialize};
use url::Url;

/// An explicit RP identity/origin allowlist. Never inferred from Host/forwarded headers.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub origins: Vec<String>,
}

impl PasskeyConfig {
    pub fn validate(&self) -> Result<Vec<Url>, &'static str> {
        zann_autofill::RpId::parse(&self.rp_id).map_err(|_| "invalid passkey RP ID")?;
        if self.rp_name.is_empty()
            || self.rp_name.len() > 128
            || self.rp_name.chars().any(char::is_control)
            || self.origins.is_empty()
            || self.origins.len() > 16
        {
            return Err("invalid passkey RP configuration");
        }
        let mut origins = Vec::new();
        for origin in &self.origins {
            let url = Url::parse(origin).map_err(|_| "invalid passkey origin")?;
            if !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || !matches!(url.path(), "" | "/")
            {
                return Err("invalid passkey origin");
            }
            let host = url.host_str().ok_or("missing passkey origin host")?;
            match url.scheme() {
                "https" | "http" => {
                    if url.scheme() == "http" && (self.rp_id != "localhost" || host != "localhost")
                    {
                        return Err("passkey origin requires HTTPS");
                    }
                    if host != self.rp_id
                        && !host
                            .strip_suffix(&self.rp_id)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                    {
                        return Err("passkey origin is outside RP");
                    }
                }
                "chrome-extension" => {
                    if host.len() != 32
                        || !host.bytes().all(|b| (b'a'..=b'p').contains(&b))
                        || url.port().is_some()
                    {
                        return Err("invalid passkey extension origin");
                    }
                }
                _ => return Err("unsupported passkey origin"),
            }
            if origins.contains(&url) {
                return Err("duplicate passkey origin");
            }
            origins.push(url);
        }
        Ok(origins)
    }
}
