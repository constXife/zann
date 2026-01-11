use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};
use uuid::Uuid;

use crate::constants::TOKEN_OIDC;
use crate::infra::config::{ensure_context, load_config, save_config};
use crate::util::context_name_from_url;
use crate::infra::http::fetch_json;
use crate::infra::remote::{
    exchange_authorization_code, exchange_oidc_for_session, fetch_me_email, fetch_prelogin,
    fetch_system_info,
};
use crate::services::auth::{
    emit_oidc_status, finalize_login, oidc_status_error, oidc_status_fingerprint_changed,
    update_pending_login_for_fingerprint,
};
use crate::state::{AppState, PendingLogin, PendingLoginResult};
use crate::types::{
    ApiResponse, OidcConfigResponse, OidcDiscovery, OidcLoginStartResponse,
};

fn random_url_safe(size: usize) -> String {
    let mut bytes = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

fn log_jwt_summary(label: &str, token: &str) {
    let mut parts = token.split('.');
    let header = parts.next();
    let payload = parts.next();
    if header.is_none() || payload.is_none() {
        println!("[oidc] {label} is not a JWT");
        return;
    }
    let header = match URL_SAFE_NO_PAD.decode(header.unwrap()) {
        Ok(bytes) => bytes,
        Err(err) => {
            println!("[oidc] {label} header decode failed: {err}");
            return;
        }
    };
    let payload = match URL_SAFE_NO_PAD.decode(payload.unwrap()) {
        Ok(bytes) => bytes,
        Err(err) => {
            println!("[oidc] {label} payload decode failed: {err}");
            return;
        }
    };
    let header_json: serde_json::Value = serde_json::from_slice(&header).unwrap_or_default();
    let payload_json: serde_json::Value = serde_json::from_slice(&payload).unwrap_or_default();
    let alg = header_json.get("alg").and_then(|v| v.as_str()).unwrap_or("unknown");
    let kid = header_json.get("kid").and_then(|v| v.as_str()).unwrap_or("unknown");
    let iss = payload_json.get("iss").and_then(|v| v.as_str()).unwrap_or("unknown");
    let aud = payload_json
        .get("aud")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let azp = payload_json.get("azp").and_then(|v| v.as_str()).unwrap_or("unknown");
    let typ = header_json.get("typ").and_then(|v| v.as_str()).unwrap_or("unknown");
    let exp = payload_json.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    println!(
        "[oidc] {label} summary alg={alg} kid={kid} typ={typ} iss={iss} aud={aud} azp={azp} exp={exp}"
    );
}

pub(crate) async fn begin_login(
    server_url: String,
    state: &State<'_, AppState>,
    app: &AppHandle,
) -> Result<ApiResponse<OidcLoginStartResponse>, String> {
    if server_url.trim().is_empty() {
        return Ok(ApiResponse::err("invalid_server_url", "server_url is required"));
    }
    let client = reqwest::Client::new();
    let oidc_config_url = format!("{}/v1/auth/oidc/config", server_url.trim_end_matches('/'));
    let oidc_config =
        fetch_json::<OidcConfigResponse>(&client, &oidc_config_url).await.map_err(|e| e)?;
    let discovery_url = format!("{}/.well-known/openid-configuration", oidc_config.issuer);
    let discovery = fetch_json::<OidcDiscovery>(&client, &discovery_url).await.map_err(|e| e)?;

    let redirect_port = 8765;
    let listener = TcpListener::bind(format!("127.0.0.1:{redirect_port}"))
        .map_err(|err| err.to_string())?;
    let redirect_uri = format!("http://127.0.0.1:{}/oidc/callback", redirect_port);

    let oauth_state = random_url_safe(16);
    let code_verifier = random_url_safe(32);
    let code_challenge = pkce_challenge(&code_verifier);
    let scope = oidc_config.scopes.join(" ");

    let mut auth_url =
        reqwest::Url::parse(&discovery.authorization_endpoint).map_err(|err| err.to_string())?;
    {
        let mut pairs = auth_url.query_pairs_mut();
        pairs.append_pair("client_id", &oidc_config.client_id);
        pairs.append_pair("response_type", "code");
        pairs.append_pair("redirect_uri", &redirect_uri);
        pairs.append_pair("scope", &scope);
        pairs.append_pair("state", &oauth_state);
        pairs.append_pair("code_challenge", &code_challenge);
        pairs.append_pair("code_challenge_method", "S256");
        if let Some(audience) = oidc_config.audience.as_deref() {
            pairs.append_pair("audience", audience);
        }
    }

    let login_id = Uuid::now_v7().to_string();
    let login_id_for_thread = login_id.clone();
    let mut guard = state
        .pending_logins
        .lock()
        .map_err(|err| err.to_string())?;
    guard.insert(
        login_id.clone(),
        PendingLogin {
            server_url: server_url.clone(),
            discovery,
            oidc_config,
            oauth_state,
            code_verifier,
            redirect_uri: redirect_uri.clone(),
            fingerprint_new: None,
            fingerprint_trusted: false,
            pending_result: None,
        },
    );

    let app_handle = app.clone();
    std::thread::spawn(move || {
        if let Err(err) = listen_for_oidc_callback(
            listener,
            app_handle.clone(),
            login_id_for_thread.clone(),
            redirect_port,
        ) {
            if let Ok(mut guard) = app_handle.state::<AppState>().pending_logins.lock() {
                guard.remove(&login_id_for_thread);
            }
            let _ =
                emit_oidc_status(&app_handle, oidc_status_error(&login_id_for_thread, err));
        }
    });

    Ok(ApiResponse::ok(OidcLoginStartResponse {
        login_id,
        authorization_url: auth_url.to_string(),
    }))
}

pub(crate) async fn trust_fingerprint(
    login_id: String,
    state: &State<'_, AppState>,
    app: &AppHandle,
) -> Result<ApiResponse<()>, String> {
    let pending = {
        let mut guard = state
            .pending_logins
            .lock()
            .map_err(|err| err.to_string())?;
        guard.get_mut(&login_id).cloned()
    };
    let Some(pending) = pending else {
        return Ok(ApiResponse::err("login_not_found", "login session not found"));
    };
    let Some(new_fp) = pending.fingerprint_new.clone() else {
        return Ok(ApiResponse::err("fingerprint_missing", "no new fingerprint to trust"));
    };

    let mut config = load_config(&state.root).unwrap_or_else(|_| Default::default());
    let context_name = context_name_from_url(&pending.server_url);
    let context = ensure_context(&mut config, &context_name, &pending.server_url);
    context.server_fingerprint = Some(new_fp);
    if let Some(result) = pending.pending_result.as_ref() {
        context.server_id = result.info.server_id.clone();
    }
    save_config(&state.root, &config).map_err(|err| err.to_string())?;
    let mut guard = state
        .pending_logins
        .lock()
        .map_err(|err| err.to_string())?;
    if let Some(entry) = guard.get_mut(&login_id) {
        entry.fingerprint_trusted = true;
        if let Some(result) = entry.pending_result.clone() {
            let app_handle = app.clone();
            let login_id = login_id.clone();
            let pending = entry.clone();
            tauri::async_runtime::spawn(async move {
                let state_handle = app_handle.state::<AppState>();
                let response = finalize_login(&state_handle, &login_id, pending, result).await;
                match response {
                    Ok(payload) => {
                        if let Some(data) = payload.data {
                            let _ = emit_oidc_status(&app_handle, data);
                        } else {
                            let _ = emit_oidc_status(
                                &app_handle,
                                oidc_status_error(&login_id, "missing login payload"),
                            );
                        }
                    }
                    Err(err) => {
                        let _ = emit_oidc_status(&app_handle, oidc_status_error(&login_id, err));
                    }
                }
            });
        }
    }
    Ok(ApiResponse::ok(()))
}

fn listen_for_oidc_callback(
    listener: TcpListener,
    app: AppHandle,
    login_id: String,
    port: u16,
) -> Result<(), String> {
    listener
        .set_nonblocking(true)
        .map_err(|err| err.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let (code, oauth_state) = parse_oidc_request(&mut stream, port)?;
                println!("[oidc] callback received for login_id={}", login_id);
                respond_html(
                    &mut stream,
                    "Login complete",
                    "You can return to the app and close this window.",
                )?;
                let app_handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let login_id_for_error = login_id.clone();
                    if let Err(err) = complete_oidc_login(&app_handle, login_id, code, oauth_state).await
                    {
                        let _ = emit_oidc_status(
                            &app_handle,
                            oidc_status_error(&login_id_for_error, err),
                        );
                    }
                });
                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    return Err("login timed out".to_string());
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(err) => return Err(err.to_string()),
        }
    }
}

fn parse_oidc_request(
    stream: &mut std::net::TcpStream,
    port: u16,
) -> Result<(String, String), String> {
    let mut buffer = [0u8; 8192];
    let size = stream.read(&mut buffer).map_err(|err| err.to_string())?;
    if size == 0 {
        return Err("empty request".to_string());
    }
    let request = String::from_utf8_lossy(&buffer[..size]);
    let request_line = request.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    if method != "GET" {
        respond_html(stream, "Invalid request", "Expected GET request.")?;
        return Err("invalid request method".to_string());
    }
    if !path.starts_with('/') {
        respond_html(stream, "Invalid request", "Malformed callback URL.")?;
        return Err("invalid request path".to_string());
    }
    let full_url = format!("http://127.0.0.1:{port}{path}");
    let url = reqwest::Url::parse(&full_url).map_err(|err| err.to_string())?;
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;
    for (key, value) in url.query_pairs() {
        if key == "code" {
            code = Some(value.to_string());
        } else if key == "state" {
            state = Some(value.to_string());
        } else if key == "error" {
            error = Some(value.to_string());
        } else if key == "error_description" {
            error_description = Some(value.to_string());
        }
    }
    if let Some(error) = error {
        let detail = error_description.unwrap_or_else(|| "Authorization failed.".to_string());
        respond_html(stream, "Login error", &detail).ok();
        return Err(format!("authorization error: {error}"));
    }
    let code = code.ok_or_else(|| {
        respond_html(stream, "Login error", "Missing authorization code.").ok();
        "missing code".to_string()
    })?;
    let state = state.ok_or_else(|| {
        respond_html(stream, "Login error", "Missing state parameter.").ok();
        "missing state".to_string()
    })?;
    Ok((code, state))
}

fn respond_html(stream: &mut std::net::TcpStream, title: &str, message: &str) -> Result<(), String> {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{}</title></head>\
        <body style=\"font-family: sans-serif; padding: 24px;\"><h2>{}</h2><p>{}</p></body></html>",
        title, title, message
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).map_err(|err| err.to_string())
}

async fn complete_oidc_login(
    app: &AppHandle,
    login_id: String,
    code: String,
    oauth_state: String,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let pending = {
        let guard = state
            .pending_logins
            .lock()
            .map_err(|err| err.to_string())?;
        guard.get(&login_id).cloned()
    };
    let Some(pending) = pending else {
        return Err("login session not found".to_string());
    };
    if pending.oauth_state != oauth_state {
        return Err("invalid state".to_string());
    }

    let client = reqwest::Client::new();
    let idp_token = exchange_authorization_code(
        &client,
        &pending.discovery,
        &pending.oidc_config,
        &code,
        &pending.redirect_uri,
        &pending.code_verifier,
    )
    .await
    .map_err(|err| {
        println!("[oidc] token exchange failed: {err}");
        err
    })?;

    println!(
        "[oidc] received authorization code for {}",
        pending.server_url
    );

    let oidc_token = idp_token
        .id_token
        .as_deref()
        .unwrap_or(idp_token.access_token.as_str());
    if idp_token.id_token.is_some() {
        println!("[oidc] using id_token for session exchange");
        log_jwt_summary("id_token", oidc_token);
    } else {
        println!("[oidc] using access_token for session exchange");
        log_jwt_summary("access_token", oidc_token);
    }
    let session = exchange_oidc_for_session(&client, &pending.server_url, oidc_token)
        .await
        .map_err(|err| {
            println!("[oidc] session exchange failed: {err}");
            err
        })?;
    println!("[oidc] session exchange ok for {}", pending.server_url);

    let info = fetch_system_info(&client, &pending.server_url)
        .await
        .map_err(|err| {
            println!("[oidc] system info failed: {err}");
            err
        })?;
    let email = fetch_me_email(&client, &pending.server_url, &session.access_token)
        .await
        .map_err(|err| {
            println!("[oidc] me failed: {err}");
            err
        })?;
    let prelogin = fetch_prelogin(&client, &pending.server_url, &email)
        .await
        .map_err(|err| {
            println!("[oidc] prelogin failed: {err}");
            err
        })?;
    println!(
        "[oidc] prelogin ok email={} salt_fp={} kdf={:?}",
        email, prelogin.salt_fingerprint, prelogin.kdf_params
    );

    let result = PendingLoginResult {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        expires_in: session.expires_in,
        email: email.clone(),
        prelogin: prelogin.clone(),
        info: info.clone(),
        token_name: TOKEN_OIDC.to_string(),
    };
    if let Some(existing) = update_pending_login_for_fingerprint(
        &state,
        &pending.server_url,
        &login_id,
        &info.server_fingerprint,
        &result,
    )? {
        println!("[oidc] fingerprint changed for {}", pending.server_url);
        let _ = emit_oidc_status(
            app,
            oidc_status_fingerprint_changed(&login_id, &existing, &info.server_fingerprint),
        );
        return Ok(());
    }

    let response = finalize_login(&state, &login_id, pending, result).await?;
    println!("[oidc] login finalized for {}", state.root.display());
    if let Some(payload) = response.data {
        let _ = emit_oidc_status(app, payload);
    }
    Ok(())
}
