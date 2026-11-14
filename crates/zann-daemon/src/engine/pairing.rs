//! Connection-scoped PAKE plus native-only, bounded code admission.
use super::{Engine, State};
use crate::{settings::Pairing, Result};
use std::time::Instant;
use zann_client::browser_ipc::{decode_array, pairing_binding, ErrorCode, Reply, Request};
use zann_crypto::ipc_pairing::{CodeConfirmation, CodeExchange, MESSAGE_BYTES};

pub(crate) struct PairingAttempt {
    confirmation: CodeConfirmation,
    generation: [u8; 32],
    public_key: String,
    name: String,
}

impl Engine {
    pub(super) fn pairing_request(
        &self,
        state: &mut State,
        public: &str,
        nonce: &[u8; 32],
        channel: &[u8; 32],
        request: &Request,
        attempt: &mut Option<PairingAttempt>,
    ) -> Result<Option<Reply>> {
        let refused = || {
            Some(Reply::Error {
                code: ErrorCode::Refused,
            })
        };
        match request {
            Request::PairStatus {} => Ok(Some(
                if state.pairings.iter().any(|p| p.public_key == public) {
                    Reply::Paired {}
                } else {
                    Reply::Error {
                        code: ErrorCode::Unpaired,
                    }
                },
            )),
            Request::PairStart { name, message } => {
                // Every start (including malformed/repeated ones) consumes one
                // global guess. Reconnect cannot reset this native window.
                *attempt = None;
                let Some(window) = &mut state.pairing else {
                    return Ok(refused());
                };
                if window.expires <= Instant::now() || window.remaining == 0 {
                    return Ok(refused());
                }
                window.remaining -= 1;
                if crate::settings::validate_name(name).is_err()
                    || (state.pairings.len() >= 64
                        && !state.pairings.iter().any(|p| p.public_key == public))
                {
                    return Ok(refused());
                }
                let Ok(message) = decode_array::<MESSAGE_BYTES>(message) else {
                    return Ok(refused());
                };
                let binding = pairing_binding(
                    &self.key.public_key(),
                    nonce,
                    channel,
                    &decode_array(public)?,
                    name,
                );
                let (exchange, response) = CodeExchange::server(&window.code, &binding)
                    .map_err(zann_client::browser_ipc::IpcError::from)?;
                let Ok(confirmation) = exchange.finish(&message) else {
                    return Ok(refused());
                };
                let reply = Reply::PairChallenge {
                    message: hex::encode(response),
                    confirmation: hex::encode(confirmation.server_proof()),
                };
                *attempt = Some(PairingAttempt {
                    confirmation,
                    generation: window.generation,
                    public_key: public.into(),
                    name: name.clone(),
                });
                Ok(Some(reply))
            }
            Request::PairFinish { confirmation } => {
                // Taking before verification prevents a second guess using the
                // same PAKE state, even after malformed input.
                let Some(pending) = attempt.take() else {
                    return Ok(refused());
                };
                let Some(window) = &state.pairing else {
                    return Ok(refused());
                };
                if window.expires <= Instant::now()
                    || window.generation != pending.generation
                    || pending.public_key != public
                    || (state.pairings.len() >= 64
                        && !state.pairings.iter().any(|p| p.public_key == public))
                {
                    return Ok(refused());
                }
                let Ok(proof) = decode_array(confirmation) else {
                    return Ok(refused());
                };
                if pending.confirmation.verify_client(&proof).is_err() {
                    return Ok(refused());
                }
                state.pairing = None;
                let mut candidate = state.pairings.clone();
                if !candidate.iter().any(|p| p.public_key == public) {
                    candidate.push(Pairing {
                        public_key: public.into(),
                        name: pending.name,
                    });
                }
                self.directory
                    .save(&self.key, &self.transport_key, &candidate)?;
                state.pairings = candidate;
                Ok(Some(Reply::Paired {}))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use zann_client::app::ClientPaths;
    use zann_client::browser_ipc::BrowserPairingClient;
    use zann_client::native_messaging::{read_frame, write_frame};
    use zann_client_sqlite::local_vault::{open_vault_at_path, LocalVaultPorts};

    #[test]
    fn expiry_is_checked_at_start_and_again_before_durable_enrollment() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let vault = open_vault_at_path(
            &root.join("local.sqlite"),
            LocalVaultPorts::system_default(),
        )
        .unwrap();
        let daemon = crate::Daemon::start(ClientPaths::new(&root), vault).unwrap();
        let control = daemon.control();
        for expire_before_start in [true, false] {
            let code = control.begin_pairing().unwrap();
            let mut browser = BrowserPairingClient::new(
                &hex::encode([4; 32]),
                code.value.to_string(),
                "Browser".into(),
            )
            .unwrap();
            let mut socket = UnixStream::connect(root.join("ipc/browser.sock")).unwrap();
            let hello = read_frame(&mut socket).unwrap().unwrap();
            write_frame(&mut socket, &browser.connect(&hello).unwrap()).unwrap();
            browser
                .finish(&read_frame(&mut socket).unwrap().unwrap())
                .unwrap();
            let expire = || {
                control
                    .engine
                    .state
                    .lock()
                    .unwrap()
                    .pairing
                    .as_mut()
                    .unwrap()
                    .expires = Instant::now();
            };
            if expire_before_start {
                expire();
            }
            write_frame(&mut socket, &browser.begin().unwrap()).unwrap();
            let challenge = read_frame(&mut socket).unwrap().unwrap();
            if expire_before_start {
                assert!(browser.confirm(&challenge).is_err());
            } else {
                let confirm = browser.confirm(&challenge).unwrap();
                expire();
                write_frame(&mut socket, &confirm).unwrap();
                assert!(browser
                    .complete(&read_frame(&mut socket).unwrap().unwrap())
                    .is_err());
            }
            assert!(control.settings().unwrap().paired.is_empty());
            assert!(control.settings().unwrap().active_code_id.is_none());
        }
    }
}
