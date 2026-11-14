//! This capability can only be obtained by the process embedding the daemon.
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zann_client::browser_ipc::decode_array;

use crate::{engine::Engine, DaemonError, Result};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pairing {
    pub public_key: String,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct PairingSettings {
    pub paired: Vec<Pairing>,
    pub active_code_id: Option<String>,
}

/// Native UI only. Debug never reveals the code; it is not persisted.
#[derive(Clone)]
pub struct PairingCode {
    pub id: String,
    pub value: zeroize::Zeroizing<String>,
    pub expires_in_seconds: u32,
}
impl std::fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingCode([REDACTED])")
    }
}

pub(crate) struct PairingWindow {
    pub code: zeroize::Zeroizing<String>,
    pub generation: [u8; 32],
    pub expires: Instant,
    pub remaining: u8,
}

#[derive(Clone)]
pub struct DaemonControl {
    pub(crate) engine: Arc<Engine>,
}

pub(crate) fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
    {
        return Err(DaemonError::Protocol);
    }
    Ok(())
}

impl DaemonControl {
    pub fn settings(&self) -> Result<PairingSettings> {
        let mut state = self.engine.state.lock().expect("lock poisoned");
        self.engine.check_running()?;
        if state
            .pairing
            .as_ref()
            .is_some_and(|p| p.expires <= Instant::now())
        {
            state.pairing = None;
        }
        Ok(PairingSettings {
            paired: state.pairings.clone(),
            active_code_id: state.pairing.as_ref().map(|p| hex::encode(p.generation)),
        })
    }

    /// Only a native user action opens a code window. Replacing the window
    /// invalidates every incomplete exchange, including ones on live sockets.
    pub fn begin_pairing(&self) -> Result<PairingCode> {
        let mut state = self.engine.state.lock().expect("lock poisoned");
        self.engine.check_running()?;
        let code = zann_crypto::ipc_pairing::generate_code();
        let generation = zann_crypto::ipc_signatures::random_nonce();
        state.pairing = Some(PairingWindow {
            code: code.clone(),
            generation,
            expires: Instant::now() + PAIRING_TTL,
            remaining: 5,
        });
        Ok(PairingCode {
            id: hex::encode(generation),
            value: code,
            expires_in_seconds: PAIRING_TTL.as_secs() as u32,
        })
    }

    pub fn revoke(&self, public_key: &str) -> Result<()> {
        decode_array::<32>(public_key)?;
        let mut state = self.engine.state.lock().expect("lock poisoned");
        self.engine.check_running()?;
        let mut candidate = state.pairings.clone();
        candidate.retain(|p| p.public_key != public_key);
        state.pairings = candidate;
        state.cursors.revoke(public_key);
        // Revocation also cancels in-flight code enrollment: no pending proof
        // may restore authority after the user has revoked a browser.
        state.pairing = None;
        if let Err(error) = self.engine.directory.save(
            &self.engine.key,
            &self.engine.transport_key,
            &state.pairings,
        ) {
            // Failed revocation persistence never leaves a live authorized
            // session. No success is reported until the directory fsync proves it.
            self.engine
                .running
                .store(false, std::sync::atomic::Ordering::Release);
            return Err(error);
        }
        Ok(())
    }
}

pub(crate) const PAIRING_TTL: Duration = Duration::from_secs(120);
