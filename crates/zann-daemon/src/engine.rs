//! One session owner, authenticated dispatch and in-process management authority.
use crate::channel::Channel;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use zann_client::app::local::{LocalError, LocalVaultService};
use zann_crypto::ipc_signatures::IpcSigningKey;
use zeroize::Zeroizing;

use crate::filesystem::Directory;
use crate::settings::{Pairing, PairingWindow};
use crate::{DaemonError, Result};
use zann_client::browser_ipc::{ErrorCode, MatchPage, Reply, Request, SignedReply, SignedRequest};

mod cursors;
mod fill;
mod pairing;
pub(crate) use pairing::PairingAttempt;

pub(crate) struct State {
    pub pairings: Vec<Pairing>,
    pub pairing: Option<PairingWindow>,
    pub cursors: cursors::CursorStore,
}

pub(crate) struct Engine {
    pub directory: Directory,
    pub key: IpcSigningKey,
    pub transport_key: zann_crypto::ipc_transport::IpcTransportKey,
    pub state: Mutex<State>,
    pub running: AtomicBool,
    vault: Arc<dyn LocalVaultService>,
}

impl Engine {
    pub fn new(directory: Directory, vault: Arc<dyn LocalVaultService>) -> Result<Self> {
        let (key, transport_key, pairings) = directory.load()?;
        Ok(Self {
            directory,
            key,
            transport_key,
            state: Mutex::new(State {
                pairings,
                pairing: None,
                cursors: cursors::CursorStore::default(),
            }),
            running: AtomicBool::new(true),
            vault,
        })
    }
    pub fn public_key(&self) -> String {
        hex::encode(self.key.public_key())
    }
    pub fn check_running(&self) -> Result<()> {
        if !self.running.load(Ordering::Acquire) {
            return Err(DaemonError::Closed);
        }
        Ok(())
    }

    fn send(
        &self,
        stream: &mut Channel<'_>,
        nonce: &[u8; 32],
        seq: u64,
        reply: &Reply,
    ) -> Result<()> {
        let signed = SignedReply::sign(&self.key, nonce, seq, reply)?;
        let bytes = Zeroizing::new(serde_json::to_vec(&signed)?);
        stream.write(&bytes)?;
        Ok(())
    }

    pub fn handle(
        &self,
        request: SignedRequest,
        nonce: &[u8; 32],
        stream: &mut Channel<'_>,
        attempt: &mut Option<PairingAttempt>,
    ) -> Result<()> {
        let (public, body) = request.verify(&self.key.public_key(), nonce)?;
        let public = hex::encode(public);
        // Approval/revocation and reply delivery are linearized by this lease.
        // A bounded response write completes before revoke returns; no later
        // request can retain a stale authorization snapshot.
        let mut state = self.state.lock().expect("lock poisoned");
        self.check_running()?;
        let paired = state.pairings.iter().any(|p| p.public_key == public);
        if let Some(reply) =
            self.pairing_request(&mut state, &public, nonce, stream.binding(), &body, attempt)?
        {
            return self.send(stream, nonce, request.sequence, &reply);
        }
        if !paired {
            return self.send(
                stream,
                nonce,
                request.sequence,
                &Reply::Error {
                    code: ErrorCode::Unpaired,
                },
            );
        }
        let delivery = |error: DaemonError| LocalError::BrowserDelivery(Box::new(error));
        let result = match body {
            Request::PairStatus {} | Request::PairStart { .. } | Request::PairFinish { .. } => {
                unreachable!()
            }
            Request::Save {
                context,
                scope,
                login,
                gesture,
            } => {
                if !gesture {
                    return self.send(
                        stream,
                        nonce,
                        request.sequence,
                        &Reply::Error {
                            code: ErrorCode::Refused,
                        },
                    );
                }
                self.vault
                    .browser_save(context, scope, login, &mut |item_id| {
                        self.send(stream, nonce, request.sequence, &Reply::Saved { item_id })
                            .map_err(delivery)
                    })
            }
            Request::Query { context, cursor } => {
                let after = state.cursors.begin(cursor, &public, nonce, &context)?;
                if state.cursors.check_capacity(nonce).is_err() {
                    return self.send(
                        stream,
                        nonce,
                        request.sequence,
                        &Reply::Error {
                            code: ErrorCode::Limit,
                        },
                    );
                }
                self.vault
                    .browser_query(context.clone(), after, &mut |page| {
                        let next_cursor = state
                            .cursors
                            .issue(page.next_cursor, &public, nonce, &context)
                            .map_err(delivery)?;
                        self.send(
                            stream,
                            nonce,
                            request.sequence,
                            &Reply::Matches {
                                page: MatchPage {
                                    items: page.items,
                                    scope: page.scope,
                                    next_cursor,
                                },
                            },
                        )
                        .map_err(delivery)
                    })
            }
            Request::Fill {
                context,
                item_id,
                gesture,
                include_totp,
            } => {
                if !gesture {
                    return self.send(
                        stream,
                        nonce,
                        request.sequence,
                        &Reply::Error {
                            code: ErrorCode::Refused,
                        },
                    );
                }
                self.vault.browser_fill(context, item_id, &mut |payload| {
                    let reply = fill::password_reply(payload, include_totp)?;
                    self.send(stream, nonce, request.sequence, &reply)
                        .map_err(delivery)
                })
            }
        };
        match result {
            Ok(()) => Ok(()),
            Err(error @ LocalError::BrowserDelivery(_)) => Err(error.into()),
            Err(LocalError::Locked) => self.send(
                stream,
                nonce,
                request.sequence,
                &Reply::Error {
                    code: ErrorCode::Locked,
                },
            ),
            Err(LocalError::DeadlineExceeded) => self.send(
                stream,
                nonce,
                request.sequence,
                &Reply::Error {
                    code: ErrorCode::Timeout,
                },
            ),
            Err(error) => {
                self.send(
                    stream,
                    nonce,
                    request.sequence,
                    &Reply::Error {
                        code: ErrorCode::Refused,
                    },
                )?;
                Err(error.into())
            }
        }
    }
}
