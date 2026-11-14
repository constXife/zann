//! Pure origin matching and fill admission. No network, storage, session or UI.
//! Callers must supply URLs obtained from the browser/OS, never page messages.
mod data;
mod error;
mod matcher;
mod origin;
mod policy;
mod rules;

pub use error::AutofillError;
pub use matcher::{LoginMatcher, MatchQuality};
pub use origin::SiteUrl;
pub use policy::{
    authorize_credential_context, authorize_fill, validate_frame_context, FillContext, FillDenied,
    UserGesture,
};
pub use rules::{MatchMode, MatchRules, MATCH_RULES_KEY};
