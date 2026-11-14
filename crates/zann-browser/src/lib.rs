//! Thin WASM projection. Protocol state and crypto remain in canonical owners.
use wasm_bindgen::prelude::*;
use zann_client::browser_ipc::{BrowserClient, BrowserContext, Request};
use zann_crypto::ipc_signatures::IpcSigningKey;
use zeroize::Zeroizing;

pub(crate) const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;

#[wasm_bindgen]
pub fn create_identity() -> JsValue {
    let seed = Zeroizing::new(hex::encode(IpcSigningKey::generate().seed()));
    JsValue::from_str(&seed)
}

#[wasm_bindgen]
pub fn generate_password(length: u32, symbols: bool) -> Result<JsValue, JsError> {
    let options = zann_ui_core::generator::PasswordOptions {
        length,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols,
        avoid_ambiguous: false,
    };
    let value = zann_ui_core::generator::generate_password(&options)?;
    Ok(JsValue::from_str(value.as_str()))
}

#[wasm_bindgen]
pub fn checked_context(top: &str, frame: &str) -> Result<String, JsError> {
    let context = BrowserContext {
        top_level_url: top.into(),
        frame_url: frame.into(),
    };
    context
        .credential_context()
        .map_err(|error| JsError::new(&error.to_string()))?;
    Ok(serde_json::to_string(&context)?)
}

#[wasm_bindgen]
pub struct NativeClient(BrowserClient);
#[wasm_bindgen]
impl NativeClient {
    #[wasm_bindgen(constructor)]
    pub fn new(seed: String, pinned_server: &str) -> Result<Self, JsError> {
        let seed = Zeroizing::new(seed);
        Ok(Self(BrowserClient::new(&seed, pinned_server)?))
    }
    pub fn public_key(&self) -> String {
        self.0.public_key()
    }
    pub fn connect(&mut self, hello: &str) -> Result<String, JsError> {
        Ok(String::from_utf8(self.0.connect(hello.as_bytes())?)?)
    }
    pub fn finish(&mut self, packet: &str) -> Result<(), JsError> {
        Ok(self.0.finish(packet.as_bytes())?)
    }
    pub fn request(&mut self, request: String) -> Result<String, JsError> {
        let bytes = Zeroizing::new(request);
        let request: Request = serde_json::from_str(&bytes)?;
        Ok(String::from_utf8(self.0.request(&request)?)?)
    }
    pub fn reply(&mut self, packet: &str) -> Result<JsValue, JsError> {
        let bytes = Zeroizing::new(serde_json::to_string(&self.0.reply(packet.as_bytes())?)?);
        Ok(JsValue::from_str(&bytes))
    }
}

mod search;
pub use search::NativeLoginSearch;
mod pairing;
pub use pairing::NativePairing;
mod usage;
pub use usage::NativeBrowserUsage;
mod login_list;
pub use login_list::NativeLoginList;
