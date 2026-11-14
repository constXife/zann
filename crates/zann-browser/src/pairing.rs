//! No generic application requests or provisional server-pin export.
use wasm_bindgen::prelude::*;
use zann_client::browser_ipc::BrowserPairingClient;
use zeroize::Zeroizing;

#[wasm_bindgen]
pub struct NativePairing(BrowserPairingClient);
#[wasm_bindgen]
impl NativePairing {
    #[wasm_bindgen(constructor)]
    pub fn new(seed: String, code: String, name: String) -> Result<Self, JsError> {
        let seed = Zeroizing::new(seed);
        Ok(Self(BrowserPairingClient::new(&seed, code, name)?))
    }
    pub fn connect(&mut self, hello: &str) -> Result<String, JsError> {
        Ok(String::from_utf8(self.0.connect(hello.as_bytes())?)?)
    }
    pub fn finish(&mut self, packet: &str) -> Result<(), JsError> {
        Ok(self.0.finish(packet.as_bytes())?)
    }
    pub fn begin(&mut self) -> Result<String, JsError> {
        Ok(String::from_utf8(self.0.begin()?)?)
    }
    pub fn confirm(&mut self, packet: &str) -> Result<String, JsError> {
        Ok(String::from_utf8(self.0.confirm(packet.as_bytes())?)?)
    }
    pub fn complete(&mut self, packet: &str) -> Result<String, JsError> {
        Ok(self.0.complete(packet.as_bytes())?)
    }
}
