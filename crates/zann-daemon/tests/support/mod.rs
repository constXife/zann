#![allow(dead_code)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use zann_client::app::{
    local::{BrowserContext, ItemCreate},
    ClientPaths,
};
use zann_client::browser_ipc::{decode_array, Hello, Reply, Request, SignedReply, SignedRequest};
use zann_client::browser_ipc::{EncryptedFrame, NoiseHandshakePacket};
use zann_client::native_messaging::{read_frame, write_frame};
use zann_client_sqlite::local_vault::{open_vault_at_path, LocalVault, LocalVaultPorts};
use zann_crypto::ipc_signatures::IpcSigningKey;
use zann_crypto::ipc_transport::{IpcHandshake, IpcTransport};
use zann_daemon::Daemon;

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub root: PathBuf,
    pub vault: Arc<LocalVault>,
}
impl Fixture {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let vault = open_vault_at_path(
            &root.join("local.sqlite"),
            LocalVaultPorts::system_default(),
        )
        .unwrap();
        vault
            .seed_offline_fixture("fixture-password".into())
            .unwrap();
        Self { dir, root, vault }
    }
    pub fn daemon(&self) -> Daemon {
        Daemon::start(ClientPaths::new(&self.root), self.vault.clone()).unwrap()
    }
    pub fn login(&self, name: &str, url: &str) -> String {
        self.login_as(name, url, "alice")
    }
    pub fn login_as(&self, name: &str, url: &str, username: &str) -> String {
        let payload = serde_json::json!({"v":1,"typeId":"login","fields":{
            "url":{"kind":"url","value":url},
            "username":{"kind":"text","value":username},
            "password":{"kind":"password","value":"password-sentinel"},
            "totp_secret":{"kind":"otp","value":"JBSWY3DPEHPK3PXP"}}});
        self.vault
            .item_create(ItemCreate {
                title: name.into(),
                path: name.into(),
                type_id: "login".into(),
                payload_json: payload.to_string(),
            })
            .unwrap()
            .id
    }
}

pub fn context(url: &str) -> BrowserContext {
    BrowserContext {
        top_level_url: url.into(),
        frame_url: url.into(),
    }
}
pub fn query(url: &str) -> Request {
    Request::Query {
        context: context(url),
        cursor: None,
    }
}

pub struct Client {
    pub transport: IpcTransport,
    pub binding: [u8; 32],
    pub socket: UnixStream,
    pub key: IpcSigningKey,
    pub server: [u8; 32],
    pub nonce: [u8; 32],
    pub sequence: u64,
}
impl Client {
    pub fn connect(fixture: &Fixture, daemon: &Daemon, seed: u8) -> Self {
        let mut socket = UnixStream::connect(fixture.root.join("ipc/browser.sock")).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let hello_bytes = read_frame(&mut socket).unwrap().unwrap();
        let hello: Hello = serde_json::from_slice(&hello_bytes).unwrap();
        let server = decode_array(&daemon.server_key()).unwrap();
        let nonce = hello.verify(&server).unwrap();
        let mut handshake =
            IpcHandshake::initiator(&decode_array(&hello.transport_key).unwrap(), &hello_bytes)
                .unwrap();
        let packet = NoiseHandshakePacket::new(&handshake.write().unwrap());
        write_frame(&mut socket, &serde_json::to_vec(&packet).unwrap()).unwrap();
        let packet: NoiseHandshakePacket =
            serde_json::from_slice(&read_frame(&mut socket).unwrap().unwrap()).unwrap();
        handshake.read(&packet.decode().unwrap()).unwrap();
        let binding = handshake.binding().unwrap();
        let transport = handshake.finish().unwrap();
        Self {
            binding,
            transport,
            socket,
            key: IpcSigningKey::from_seed([seed; 32]),
            server,
            nonce,
            sequence: 0,
        }
    }
    pub fn envelope(&mut self, request: &Request) -> SignedRequest {
        self.sequence += 1;
        SignedRequest::sign(&self.key, &self.server, &self.nonce, self.sequence, request).unwrap()
    }
    pub fn send(&mut self, request: Request) -> Reply {
        let signed = self.envelope(&request);
        self.write_signed_bytes(&serde_json::to_vec(&signed).unwrap());
        self.reply()
    }
    pub fn reply(&mut self) -> Reply {
        let packet: EncryptedFrame =
            serde_json::from_slice(&read_frame(&mut self.socket).unwrap().unwrap()).unwrap();
        let bytes = packet.open(&mut self.transport).unwrap();
        let signed: SignedReply = serde_json::from_slice(&bytes).unwrap();
        signed
            .verify(&self.server, &self.nonce, self.sequence)
            .unwrap()
    }
    pub fn write_signed_bytes(&mut self, bytes: &[u8]) {
        let packet = EncryptedFrame::seal(&mut self.transport, bytes).unwrap();
        write_frame(&mut self.socket, &serde_json::to_vec(&packet).unwrap()).unwrap();
    }
    pub fn start_pairing(&mut self, code: &str) -> (zann_crypto::ipc_pairing::CodeExchange, Reply) {
        let binding = zann_client::browser_ipc::pairing_binding(
            &self.server,
            &self.nonce,
            &self.binding,
            &self.key.public_key(),
            "Browser fixture",
        );
        let (exchange, message) =
            zann_crypto::ipc_pairing::CodeExchange::client(code, &binding).unwrap();
        let reply = self.send(Request::PairStart {
            name: "Browser fixture".into(),
            message: hex::encode(message),
        });
        (exchange, reply)
    }
    pub fn pair(&mut self, daemon: &Daemon) {
        let code = daemon.control().begin_pairing().unwrap();
        let (exchange, reply) = self.start_pairing(&code.value);
        let Reply::PairChallenge {
            message,
            confirmation,
        } = &reply
        else {
            panic!("challenge expected");
        };
        let key = exchange
            .finish(&decode_array::<33>(message).unwrap())
            .unwrap();
        key.verify_server(&decode_array(confirmation).unwrap())
            .unwrap();
        assert!(matches!(
            self.send(Request::PairFinish {
                confirmation: hex::encode(key.client_proof())
            }),
            Reply::Paired {}
        ));
    }
}
