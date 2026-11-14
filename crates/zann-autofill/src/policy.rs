use crate::{LoginMatcher, SiteUrl};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserGesture {
    Absent,
    Explicit,
}

pub struct FillContext<'a> {
    /// Browser/OS-observed URLs; a content-script claim is not authentication.
    pub top_level: &'a SiteUrl,
    pub frame: &'a SiteUrl,
    pub gesture: UserGesture,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FillDenied {
    #[error("an explicit user gesture is required")]
    Gesture,
    #[error("cross-origin frames cannot receive credentials")]
    CrossOriginFrame,
    #[error("credentials cannot be filled over insecure HTTP")]
    InsecureTransport,
    #[error("the item does not match the frame URL")]
    NoMatch,
}

/// Admission only. The future daemon must authenticate the browser context and
/// bind a single-use gesture to the selected item/frame before releasing data.
pub fn authorize_fill(matcher: &LoginMatcher, context: &FillContext<'_>) -> Result<(), FillDenied> {
    if context.gesture != UserGesture::Explicit {
        return Err(FillDenied::Gesture);
    }
    authorize_credential_context(context.top_level, context.frame)?;
    if !matcher.matches(context.frame) {
        return Err(FillDenied::NoMatch);
    }
    Ok(())
}

/// Shared admission for browser fill, save and generator insertion.
pub fn validate_frame_context(top: &SiteUrl, frame: &SiteUrl) -> Result<(), FillDenied> {
    if !top.same_origin(frame) {
        return Err(FillDenied::CrossOriginFrame);
    }
    Ok(())
}
pub fn authorize_credential_context(top: &SiteUrl, frame: &SiteUrl) -> Result<(), FillDenied> {
    validate_frame_context(top, frame)?;
    if !frame.https() {
        return Err(FillDenied::InsecureTransport);
    }
    Ok(())
}
