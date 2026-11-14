use super::{IpcError, Result};
use serde::{Deserialize, Serialize};
use zann_autofill::SiteUrl;

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserContext {
    pub top_level_url: String,
    pub frame_url: String,
}

impl BrowserContext {
    pub fn credential_context(&self) -> Result<(SiteUrl, SiteUrl)> {
        let (top, frame) = self.checked()?;
        zann_autofill::authorize_credential_context(&top, &frame).map_err(IpcError::Context)?;
        Ok((top, frame))
    }

    pub fn checked(&self) -> Result<(SiteUrl, SiteUrl)> {
        let parse = |url: &str| SiteUrl::parse(url).map_err(IpcError::Policy);
        let top = parse(&self.top_level_url)?;
        let frame = parse(&self.frame_url)?;
        zann_autofill::validate_frame_context(&top, &frame).map_err(IpcError::Context)?;
        Ok((top, frame))
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserMatch {
    pub item_id: String,
    pub title: String,
    pub username: Option<String>,
    pub match_quality: zann_autofill::MatchQuality,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserScope {
    pub storage_id: String,
    pub vault_id: String,
    pub generation: u64,
}

/// Only an explicit save confirmation may send this bounded typed input.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedLogin {
    pub title: String,
    pub username: String,
    pub password: String,
}
impl Drop for CapturedLogin {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}
impl CapturedLogin {
    pub fn validate(&self) -> Result<()> {
        if self.title.trim().is_empty()
            || self.title.len() > 200
            || self
                .title
                .chars()
                .any(|c| c.is_control() || c == '/' || c == '\\')
            || self.username.len() > 256
            || self.password.is_empty()
            || self.password.len() > 4096
        {
            return Err(IpcError::Protocol);
        }
        Ok(())
    }
}
