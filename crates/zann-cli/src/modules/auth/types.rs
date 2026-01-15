use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct ServiceAccountAuthRequest {
    pub token: String,
}

#[derive(Deserialize)]
pub struct ServiceAccountAuthResponse {
    pub access_token: String,
    pub expires_in: u64,
}
