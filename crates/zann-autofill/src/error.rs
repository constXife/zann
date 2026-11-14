use std::fmt;

#[derive(thiserror::Error)]
pub enum AutofillError {
    #[error("URL exceeds the autofill size bound")]
    UrlSize,
    #[error("invalid autofill URL")]
    Url(#[source] url::ParseError),
    #[error("autofill requires an HTTP(S) URL without credentials or ambiguous syntax")]
    UrlPolicy,
    #[error("invalid login match rules")]
    Rules(#[source] serde_json::Error),
    #[error("invalid match-rules field kind or size")]
    RulesField,
    #[error("invalid autofill regular expression")]
    Regex(#[source] regex::Error),
    #[error("autofill regular expression exceeds the size bound")]
    RegexSize,
    #[error("autofill requires a login payload and a typed website URL")]
    Login,
}

// Dependency errors can echo an entire URL or expression. Preserve them through
// Error::source for diagnosis, but keep ordinary Display/Debug value-free.
impl fmt::Debug for AutofillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
