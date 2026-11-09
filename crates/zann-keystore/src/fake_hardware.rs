//! Deterministic test double, opt-in via `test-support`. Never a production backend.
use std::sync::Mutex;

use crate::{AuthenticatorInfo, FidoError, HardwareAuthenticator, HardwareCredential};

pub struct FakeHardwareAuthenticator {
    state: Mutex<State>,
}

struct State {
    token: Option<u64>,
    next_credential: u64,
    credentials: Vec<(u64, Vec<u8>)>,
    next_create_error: Option<FidoError>,
    next_derive_error: Option<FidoError>,
    touches: usize,
}

impl FakeHardwareAuthenticator {
    /// Token IDs are public test identities, not cryptographic secrets.
    pub fn new(token: u64) -> Self {
        Self {
            state: Mutex::new(State {
                token: Some(token),
                next_credential: 0,
                credentials: Vec::new(),
                next_create_error: None,
                next_derive_error: None,
                touches: 0,
            }),
        }
    }

    pub fn connect(&self, token: u64) {
        self.state.lock().expect("fake state poisoned").token = Some(token);
    }

    pub fn disconnect(&self) {
        self.state.lock().expect("fake state poisoned").token = None;
    }

    pub fn fail_next_create(&self, error: FidoError) {
        self.state
            .lock()
            .expect("fake state poisoned")
            .next_create_error = Some(error);
    }

    pub fn fail_next_derive(&self, error: FidoError) {
        self.state
            .lock()
            .expect("fake state poisoned")
            .next_derive_error = Some(error);
    }

    pub fn touch_requests(&self) -> usize {
        self.state.lock().expect("fake state poisoned").touches
    }
}

impl HardwareAuthenticator for FakeHardwareAuthenticator {
    fn supported(&self) -> bool {
        true
    }

    fn status(&self) -> Result<AuthenticatorInfo, FidoError> {
        let token = self
            .state
            .lock()
            .expect("fake state poisoned")
            .token
            .ok_or(FidoError::NoDevice)?;
        Ok(AuthenticatorInfo {
            product_name: Some(format!("Fake token {token}")),
            hmac_secret: true,
        })
    }

    fn create_credential(&self, salt: [u8; 32]) -> Result<HardwareCredential, FidoError> {
        let mut state = self.state.lock().expect("fake state poisoned");
        let token = state.token.ok_or(FidoError::NoDevice)?;
        state.touches += 1;
        if let Some(error) = state.next_create_error.take() {
            return Err(error);
        }
        state.next_credential += 1;
        let id = [token.to_be_bytes(), state.next_credential.to_be_bytes()].concat();
        state.credentials.push((token, id.clone()));
        Ok(HardwareCredential {
            credential_id: id,
            salt,
        })
    }

    fn derive_dwk(&self, credential: &HardwareCredential) -> Result<[u8; 32], FidoError> {
        let mut state = self.state.lock().expect("fake state poisoned");
        let token = state.token.ok_or(FidoError::NoDevice)?;
        if !state
            .credentials
            .iter()
            .any(|(owner, id)| *owner == token && *id == credential.credential_id)
        {
            return Err(FidoError::NotEnrolled);
        }
        state.touches += 1;
        if let Some(error) = state.next_derive_error.take() {
            return Err(error);
        }
        // Reproducible test bytes only; this does not simulate a secure token.
        let input = [credential.credential_id.as_slice(), &credential.salt].concat();
        Ok(blake3::derive_key(
            "zann fake authenticator TEST ONLY",
            &input,
        ))
    }

    fn is_present(&self, credential: &HardwareCredential) -> bool {
        let state = self.state.lock().expect("fake state poisoned");
        state
            .credentials
            .iter()
            .any(|(owner, id)| Some(*owner) == state.token && *id == credential.credential_id)
    }
}
