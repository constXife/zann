use super::CliState;
use zann_client::server::ServerClient;
use zeroize::Zeroizing;

pub struct CommandContext<'a> {
    pub client: &'a ServerClient,
    pub addr: &'a str,
    pub allow_insecure: bool,
    pub access_token: Zeroizing<String>,
    pub context_name: Option<String>,
    pub token_name: Option<String>,
    pub config: &'a mut CliState,
}
