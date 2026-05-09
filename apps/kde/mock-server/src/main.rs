use base64::Engine;
use chrono::Utc;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Request, Response, Server};

const SIGNATURE_PREFIX: &str = "zann-id:v1";

#[derive(Clone)]
struct MockUser {
    password: String,
    personal_keys: bool,
}

#[derive(Default)]
struct MockState {
    users: HashMap<String, MockUser>,
    prelogins: HashMap<String, PreloginData>,
    tokens: HashMap<String, String>,
}

#[derive(Clone)]
struct PreloginData {
    kdf_salt: String,
    kdf_params: KdfParams,
    salt_fingerprint: String,
}

#[derive(Clone, Serialize)]
struct SystemInfoResponse {
    server_id: Option<String>,
    identity: Option<SystemIdentity>,
    server_fingerprint: String,
    server_name: Option<String>,
    personal_vaults_enabled: bool,
    internal_users_present: Option<bool>,
    auth_methods: Vec<i32>,
}

#[derive(Clone, Serialize)]
struct SystemIdentity {
    public_key: String,
    timestamp: i64,
    signature: String,
}

#[derive(Clone, Serialize)]
struct PreloginResponse {
    kdf_salt: String,
    kdf_params: KdfParams,
    salt_fingerprint: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct KdfParams {
    algorithm: String,
    iterations: u32,
    memory_kb: u32,
    parallelism: u32,
}

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct PersonalVaultStatusResponse {
    personal_vaults_present: bool,
    personal_key_envelopes_present: bool,
    personal_vault_id: Option<String>,
}

#[derive(Deserialize)]
struct PersonalKeysRequest {
    email: String,
    enabled: bool,
}

fn default_kdf_params() -> KdfParams {
    KdfParams {
        algorithm: "argon2id".to_string(),
        iterations: 3,
        memory_kb: 65536,
        parallelism: 4,
    }
}

fn derive_server_id(public_key: &[u8]) -> String {
    let hash = Sha256::digest(public_key);
    BASE32_NOPAD.encode(&hash).to_ascii_lowercase()
}

fn canonical_message(server_id: &str, timestamp: i64) -> String {
    format!("{SIGNATURE_PREFIX}:{server_id}:{timestamp}")
}

fn salt_fingerprint(kdf_salt: &str, params: &KdfParams) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kdf_salt.as_bytes());
    hasher.update(params.algorithm.as_bytes());
    hasher.update(params.iterations.to_le_bytes());
    hasher.update(params.memory_kb.to_le_bytes());
    hasher.update(params.parallelism.to_le_bytes());
    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

fn random_token() -> String {
    let mut buf = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut buf);
    base64::engine::general_purpose::STANDARD.encode(buf)
}

fn read_body(request: &mut Request) -> Result<String, std::io::Error> {
    let mut body = String::new();
    request.as_reader().read_to_string(&mut body)?;
    Ok(body)
}

fn send_json<T: Serialize>(request: Request, status: u16, body: &T) {
    let payload = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string());
    let response = Response::from_string(payload).with_status_code(status).with_header(
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
    );
    let _ = request.respond(response);
}

fn send_status(request: Request, status: u16, message: &str) {
    send_json(
        request,
        status,
        &ErrorResponse {
            error: message.to_string(),
        },
    );
}

fn parse_query(url: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    let Some((_, query)) = url.split_once('?') else {
        return values;
    };
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        values.insert(key.to_string(), value.to_string());
    }
    values
}

fn handle_request(
    mut request: Request,
    state: &Arc<Mutex<MockState>>,
    signing_key: &SigningKey,
    server_id: &str,
    server_fingerprint: &str,
) {
    let method = request.method().clone();
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("");

    match (method, path) {
        (Method::Get, "/v1/system/info") => {
            let timestamp = Utc::now().timestamp();
            let message = canonical_message(server_id, timestamp);
            let signature: Signature = signing_key.sign(message.as_bytes());
            let public_key = signing_key.verifying_key().to_bytes();
            let identity = SystemIdentity {
                public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
                timestamp,
                signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            };
            let users_present = {
                let guard = state.lock().expect("state");
                !guard.users.is_empty()
            };
            let response = SystemInfoResponse {
                server_id: Some(server_id.to_string()),
                identity: Some(identity),
                server_fingerprint: server_fingerprint.to_string(),
                server_name: Some("Zann Mock".to_string()),
                personal_vaults_enabled: true,
                internal_users_present: Some(users_present),
                auth_methods: vec![1],
            };
            send_json(request, 200, &response);
        }
        (Method::Get, "/v1/auth/prelogin") => {
            let query = parse_query(&url);
            let Some(email) = query.get("email").cloned() else {
                send_status(request, 400, "missing_email");
                return;
            };
            let mut guard = state.lock().expect("state");
            let entry = guard.prelogins.entry(email.clone()).or_insert_with(|| {
                let salt = random_token();
                let params = default_kdf_params();
                let fingerprint = salt_fingerprint(&salt, &params);
                PreloginData {
                    kdf_salt: salt,
                    kdf_params: params,
                    salt_fingerprint: fingerprint,
                }
            });
            let response = PreloginResponse {
                kdf_salt: entry.kdf_salt.clone(),
                kdf_params: entry.kdf_params.clone(),
                salt_fingerprint: entry.salt_fingerprint.clone(),
            };
            send_json(request, 200, &response);
        }
        (Method::Post, "/v1/auth/register") => {
            let body = match read_body(&mut request) {
                Ok(body) => body,
                Err(_) => {
                    send_status(request, 400, "invalid_body");
                    return;
                }
            };
            let payload: RegisterRequest = match serde_json::from_str(&body) {
                Ok(payload) => payload,
                Err(_) => {
                    send_status(request, 400, "invalid_json");
                    return;
                }
            };
            let mut guard = state.lock().expect("state");
            if guard.users.contains_key(&payload.email) {
                send_status(request, 400, "already_registered");
                return;
            }
            guard.prelogins.entry(payload.email.clone()).or_insert_with(|| {
                let salt = random_token();
                let params = default_kdf_params();
                let fingerprint = salt_fingerprint(&salt, &params);
                PreloginData {
                    kdf_salt: salt,
                    kdf_params: params,
                    salt_fingerprint: fingerprint,
                }
            });
            guard.users.insert(
                payload.email.clone(),
                MockUser {
                    password: payload.password,
                    personal_keys: false,
                },
            );
            let access_token = random_token();
            let refresh_token = random_token();
            guard.tokens.insert(access_token.clone(), payload.email);
            let response = LoginResponse {
                access_token,
                refresh_token,
                expires_in: 3600,
            };
            send_json(request, 200, &response);
        }
        (Method::Post, "/v1/auth/login") => {
            let body = match read_body(&mut request) {
                Ok(body) => body,
                Err(_) => {
                    send_status(request, 400, "invalid_body");
                    return;
                }
            };
            let payload: LoginRequest = match serde_json::from_str(&body) {
                Ok(payload) => payload,
                Err(_) => {
                    send_status(request, 400, "invalid_json");
                    return;
                }
            };
            let mut guard = state.lock().expect("state");
            let Some(user) = guard.users.get(&payload.email) else {
                send_status(request, 401, "invalid_credentials");
                return;
            };
            if user.password != payload.password {
                send_status(request, 401, "invalid_credentials");
                return;
            }
            let access_token = random_token();
            let refresh_token = random_token();
            guard.tokens.insert(access_token.clone(), payload.email);
            let response = LoginResponse {
                access_token,
                refresh_token,
                expires_in: 3600,
            };
            send_json(request, 200, &response);
        }
        (Method::Get, "/v1/vaults/personal/status") => {
            let auth_header = request
                .headers()
                .iter()
                .find(|header| header.field.equiv("authorization"))
                .map(|header| header.value.as_str().to_string());
            let Some(auth_header) = auth_header else {
                send_status(request, 401, "unauthorized");
                return;
            };
            let token = auth_header.trim_start_matches("Bearer ").to_string();
            let guard = state.lock().expect("state");
            let Some(email) = guard.tokens.get(&token) else {
                send_status(request, 401, "unauthorized");
                return;
            };
            let Some(user) = guard.users.get(email) else {
                send_status(request, 401, "unauthorized");
                return;
            };
            let response = PersonalVaultStatusResponse {
                personal_vaults_present: true,
                personal_key_envelopes_present: user.personal_keys,
                personal_vault_id: Some(format!("vault-{}", &email.replace('@', "_"))),
            };
            send_json(request, 200, &response);
        }
        (Method::Post, "/__test__/personal-keys") => {
            let body = match read_body(&mut request) {
                Ok(body) => body,
                Err(_) => {
                    send_status(request, 400, "invalid_body");
                    return;
                }
            };
            let payload: PersonalKeysRequest = match serde_json::from_str(&body) {
                Ok(payload) => payload,
                Err(_) => {
                    send_status(request, 400, "invalid_json");
                    return;
                }
            };
            let mut guard = state.lock().expect("state");
            let Some(user) = guard.users.get_mut(&payload.email) else {
                send_status(request, 404, "user_not_found");
                return;
            };
            user.personal_keys = payload.enabled;
            send_json(request, 200, &serde_json::json!({ "ok": true }));
        }
        _ => {
            send_status(request, 404, "not_found");
        }
    }
}

fn main() {
    let port = std::env::var("ZANN_MOCK_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(18081);
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
    let local_port = listener.local_addr().expect("addr").port();
    let server = Server::from_listener(listener, None).expect("server");

    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let server_id = derive_server_id(&public_key);
    let server_fingerprint = format!("sha256:{}", hex::encode(Sha256::digest(public_key)));

    eprintln!("[mock-server] listening on 127.0.0.1:{local_port}");
    println!("MOCK_SERVER_PORT={local_port}");

    let state = Arc::new(Mutex::new(MockState::default()));
    for request in server.incoming_requests() {
        handle_request(request, &state, &signing_key, &server_id, &server_fingerprint);
    }
}
