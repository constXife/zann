use super::{Engine, State};
use crate::Result;
use std::time::Instant;
use zann_client::browser_ipc::{ErrorCode, Reply, Request};
impl Engine {
    pub(super) fn account_request(
        state: &mut State,
        public: &str,
        nonce: &[u8; 32],
        channel: &[u8; 32],
        request: &Request,
    ) -> Result<Option<Reply>> {
        if state
            .account_ceremony
            .as_ref()
            .is_some_and(|p| p.deadline <= Instant::now())
        {
            state.account_ceremony = None;
        }
        let refused = || {
            Some(Reply::Error {
                code: ErrorCode::Refused,
            })
        };
        match request {
            Request::AccountCeremonyStatus {} => Ok(Some(Reply::AccountCeremonyPending {
                prompt: state
                    .account_ceremony
                    .as_ref()
                    .filter(|p| p.pairing == public)
                    .map(|p| p.prompt.clone()),
            })),
            Request::AccountCeremonyTake { operation_id } => {
                let Some(pending) = state.account_ceremony.as_mut() else {
                    return Ok(refused());
                };
                if pending.pairing != public
                    || pending.prompt.options.operation_id.to_string() != *operation_id
                    || pending.channel.is_some()
                {
                    return Ok(refused());
                }
                pending.channel = Some((*nonce, *channel));
                Ok(Some(Reply::AccountCeremonyPending {
                    prompt: Some(pending.prompt.clone()),
                }))
            }
            Request::AccountCeremonyFinish { operation_id, .. } => {
                let Some(pending) = state.account_ceremony.as_ref() else {
                    return Ok(refused());
                };
                if pending.pairing != public
                    || pending.prompt.options.operation_id.to_string() != *operation_id
                    || pending.channel != Some((*nonce, *channel))
                {
                    return Ok(refused());
                }
                // Move the secret-bearing result exactly once, never clone it.
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}
