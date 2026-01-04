use std::collections::HashMap;

use chrono::{Duration as ChronoDuration, Utc};

use crate::cli_args::*;
use crate::modules::auth::{
    check_kdf_fingerprint, delete_access_token, delete_refresh_token, fetch_auth_system_info,
    fetch_me_email, fetch_oidc_config, fetch_oidc_discovery, fetch_prelogin, load_refresh_token,
    poll_device_token, refresh_token_missing_error, request_device_code, store_access_token,
    store_prelogin, store_refresh_token, verify_server_fingerprint, AuthResponse, LoginRequest,
    LogoutRequest,
};
use crate::modules::system::{CliConfig, CliContext, TokenEntry};
use crate::{prompt_login_command, prompt_password, DEFAULT_ADDR, TOKEN_OIDC, TOKEN_SESSION};

pub(crate) async fn handle_login_command(
    args: LoginArgs,
    addr_arg: Option<String>,
    context_arg: Option<String>,
    client: &reqwest::Client,
    config: &mut CliConfig,
) -> anyhow::Result<()> {
    let command = match args.command {
        Some(command) => command,
        None => prompt_login_command()?,
    };

    match command {
        LoginCommand::OidcDevice(login) => {
            let context_name = login
                .context
                .clone()
                .or_else(|| context_arg.clone())
                .or_else(|| config.current_context.clone())
                .unwrap_or_else(|| "default".to_string());
            let addr = addr_arg
                .or_else(|| {
                    config
                        .contexts
                        .get(&context_name)
                        .map(|ctx| ctx.addr.clone())
                })
                .unwrap_or_else(|| DEFAULT_ADDR.to_string());

            let oidc_config_url = format!("{}/v1/auth/oidc/config", addr.trim_end_matches('/'));
            let oidc_config = fetch_oidc_config(client, &oidc_config_url).await?;

            let discovery_url = format!("{}/.well-known/openid-configuration", oidc_config.issuer);
            let discovery = fetch_oidc_discovery(client, &discovery_url).await?;

            let device_auth = request_device_code(client, &discovery, &oidc_config).await?;
            let verification = device_auth
                .verification_uri_complete
                .clone()
                .unwrap_or_else(|| device_auth.verification_uri.clone());

            println!("Visit: {verification}");
            println!("User code: {}", device_auth.user_code);

            let token = poll_device_token(client, &discovery, &oidc_config, &device_auth).await?;
            let info = fetch_auth_system_info(client, &addr).await?;
            verify_server_fingerprint(
                config,
                Some(&context_name),
                &addr,
                &info.server_fingerprint,
            )?;

            let email = fetch_me_email(client, &addr, &token.access_token).await?;
            let prelogin = fetch_prelogin(client, &addr, &email).await?;
            check_kdf_fingerprint(config, &email, &prelogin.salt_fingerprint)?;

            let entry = config
                .contexts
                .entry(context_name.clone())
                .or_insert_with(|| CliContext {
                    addr: addr.clone(),
                    needs_salt_update: false,
                    server_fingerprint: None,
                    tokens: HashMap::new(),
                    current_token: None,
                    vault: None,
                });
            entry.addr = addr;
            entry.tokens.insert(
                TOKEN_OIDC.to_string(),
                TokenEntry {
                    access_expires_at: token.expires_in.map(|seconds| {
                        (Utc::now() + ChronoDuration::seconds(seconds)).to_rfc3339()
                    }),
                },
            );
            store_access_token(&context_name, TOKEN_OIDC, &token.access_token)?;
            if let Some(refresh_token) = token.refresh_token.as_deref() {
                store_refresh_token(&context_name, TOKEN_OIDC, refresh_token)?;
            }
            entry.current_token = Some(TOKEN_OIDC.to_string());
            config.current_context = Some(context_name.clone());
            store_prelogin(config, &context_name, &email, prelogin);

            if let Some(expires_in) = token.expires_in {
                println!("Logged in (expires in {expires_in}s)");
            } else {
                println!("Logged in");
            }
        }
        LoginCommand::Internal(login) => {
            let context_name = login
                .context
                .clone()
                .or_else(|| context_arg.clone())
                .or_else(|| config.current_context.clone())
                .unwrap_or_else(|| "default".to_string());
            let addr = addr_arg
                .or_else(|| {
                    config
                        .contexts
                        .get(&context_name)
                        .map(|ctx| ctx.addr.clone())
                })
                .unwrap_or_else(|| DEFAULT_ADDR.to_string());

            let password = match login.password {
                Some(password) => password,
                None => prompt_password("Password: ")?,
            };

            let info = fetch_auth_system_info(client, &addr).await?;
            verify_server_fingerprint(
                config,
                Some(&context_name),
                &addr,
                &info.server_fingerprint,
            )?;
            let prelogin = fetch_prelogin(client, &addr, &login.email).await?;
            check_kdf_fingerprint(config, &login.email, &prelogin.salt_fingerprint)?;
            let payload = LoginRequest {
                email: login.email,
                password,
                device_name: login.device_name,
                device_platform: login.device_platform,
                device_fingerprint: None,
                device_os: None,
                device_os_version: None,
                device_app_version: None,
            };
            let url = format!("{}/v1/auth/login", addr.trim_end_matches('/'));
            let response = client.post(url).json(&payload).send().await?;
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                anyhow::bail!("Login failed: {status} {body}");
            }
            let auth: AuthResponse = response.json().await?;

            let entry = config
                .contexts
                .entry(context_name.clone())
                .or_insert_with(|| CliContext {
                    addr: addr.clone(),
                    needs_salt_update: false,
                    server_fingerprint: None,
                    tokens: HashMap::new(),
                    current_token: None,
                    vault: None,
                });
            entry.addr = addr;
            entry.tokens.insert(
                TOKEN_SESSION.to_string(),
                TokenEntry {
                    access_expires_at: Some(
                        (Utc::now() + ChronoDuration::seconds(auth.expires_in as i64)).to_rfc3339(),
                    ),
                },
            );
            store_access_token(&context_name, TOKEN_SESSION, &auth.access_token)?;
            store_refresh_token(&context_name, TOKEN_SESSION, &auth.refresh_token)?;
            entry.current_token = Some(TOKEN_SESSION.to_string());
            config.current_context = Some(context_name.clone());
            store_prelogin(config, &context_name, &payload.email, prelogin);

            println!("Logged in");
        }
    }
    Ok(())
}

pub(crate) async fn handle_logout(
    args: LogoutArgs,
    addr_arg: Option<String>,
    context_arg: Option<String>,
    client: &reqwest::Client,
    config: &mut CliConfig,
) -> anyhow::Result<()> {
    let context_name = args
        .context
        .or_else(|| context_arg.clone())
        .or_else(|| config.current_context.clone())
        .unwrap_or_else(|| "default".to_string());
    let Some(context) = config.contexts.get(&context_name).cloned() else {
        anyhow::bail!("context not found: {}", context_name);
    };
    let addr = addr_arg.unwrap_or(context.addr);
    let token_name = args
        .token_name
        .or_else(|| context.current_token.clone())
        .ok_or_else(|| anyhow::anyhow!("token name not set"))?;
    let Some(_entry) = context.tokens.get(&token_name) else {
        anyhow::bail!("token not found: {}", token_name);
    };
    let refresh_token = load_refresh_token(&context_name, &token_name)?
        .ok_or_else(|| refresh_token_missing_error(&context_name, &token_name))?;

    let url = format!("{}/v1/auth/logout", addr.trim_end_matches('/'));
    let payload = LogoutRequest { refresh_token };
    let response = client.post(url).json(&payload).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Logout failed: {status} {body}");
    }

    let Some(context) = config.contexts.get_mut(&context_name) else {
        anyhow::bail!("context not found: {}", context_name);
    };
    context.tokens.remove(&token_name);
    if context.current_token.as_deref() == Some(&token_name) {
        context.current_token = None;
    }
    delete_refresh_token(&context_name, &token_name)?;
    delete_access_token(&context_name, &token_name)?;

    println!("Logged out");
    Ok(())
}
