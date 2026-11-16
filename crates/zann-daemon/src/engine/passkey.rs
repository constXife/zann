//! Single-use confirmation tickets bound to the paired channel and native scope.
use super::Engine;
use std::time::{Duration, Instant};
use zann_client::{
    app::local::{LocalError, LocalResult},
    browser_ipc::*,
};
struct Ticket {
    token: String,
    key: String,
    nonce: [u8; 32],
    request: PasskeyRequest,
    scope: BrowserScope,
    items: Vec<String>,
    expires: Instant,
}
#[derive(Default)]
pub(crate) struct Tickets(Vec<Ticket>);
impl Tickets {
    pub fn revoke(&mut self, key: &str) {
        self.0.retain(|t| t.key != key);
    }
    pub fn issue(
        &mut self,
        key: &str,
        nonce: &[u8; 32],
        request: PasskeyRequest,
        matches: &PasskeyMatches,
    ) -> LocalResult<String> {
        self.0.retain(|t| t.expires > Instant::now());
        if matches.items.len() > PASSKEY_CANDIDATE_LIMIT
            || self.0.len() >= 64
            || self.0.iter().filter(|t| &t.nonce == nonce).count() >= 4
        {
            return Err(refused());
        }
        let token = hex::encode(zann_crypto::ipc_signatures::random_nonce());
        self.0.push(Ticket {
            token: token.clone(),
            key: key.into(),
            nonce: *nonce,
            request,
            scope: matches.scope.clone(),
            items: matches.items.iter().map(|i| i.item_id.clone()).collect(),
            expires: Instant::now() + Duration::from_secs(30),
        });
        Ok(token)
    }
    fn consume(&mut self, key: &str, nonce: &[u8; 32], token: &str) -> LocalResult<Ticket> {
        self.0.retain(|t| t.expires > Instant::now());
        let i = self
            .0
            .iter()
            .position(|t| t.key == key && &t.nonce == nonce && t.token == token)
            .ok_or_else(refused)?;
        Ok(self.0.swap_remove(i))
    }
}
fn refused() -> LocalError {
    LocalError::InvalidArgument("passkey confirmation unavailable".into())
}
impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn complete_passkey(
        &self,
        tickets: &mut Tickets,
        key: &str,
        nonce: &[u8; 32],
        token: &str,
        gesture: bool,
        selected: Option<String>,
        sink: &mut dyn FnMut(PasskeyResponse) -> LocalResult<()>,
    ) -> LocalResult<()> {
        // Consume before admission/execution: failures and lost delivery cannot replay.
        let ticket = tickets.consume(key, nonce, token)?;
        if !gesture {
            return Err(refused());
        }
        match &ticket.request.operation {
            PasskeyOperation::Create { .. } if selected.is_none() => {}
            PasskeyOperation::Get { .. }
                if selected
                    .as_ref()
                    .is_some_and(|id| ticket.items.contains(id)) => {}
            _ => return Err(refused()),
        }
        self.vault
            .passkey_ceremony(ticket.request, ticket.scope, selected, sink)
    }
}
