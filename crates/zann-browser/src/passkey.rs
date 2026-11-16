use wasm_bindgen::prelude::*;
use zann_client::browser_ipc::{passkey_request, BrowserContext};
#[wasm_bindgen]
pub fn checked_passkey_request(
    top: &str,
    frame: &str,
    kind: &str,
    options: &str,
) -> Result<String, JsError> {
    let request = passkey_request(
        BrowserContext {
            top_level_url: top.into(),
            frame_url: frame.into(),
        },
        kind,
        options,
    )?;
    Ok(serde_json::to_string(&request)?)
}
