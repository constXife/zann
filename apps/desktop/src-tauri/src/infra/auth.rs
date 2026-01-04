use chrono::{Duration as ChronoDuration, Utc};

use crate::constants::REFRESH_SKEW_SECONDS;
use crate::state::CliConfig;
use crate::util::parse_rfc3339;

pub async fn ensure_access_token_for_context(
    client: &reqwest::Client,
    addr: &str,
    context_name: &str,
    config: &mut CliConfig,
    _storage_id: Option<uuid::Uuid>,
) -> Result<String, String> {
    let context = config
        .contexts
        .get(context_name)
        .cloned()
        .ok_or_else(|| "context not found".to_string())?;
    let token_name = context
        .current_token
        .as_deref()
        .ok_or_else(|| "token not set".to_string())?;
    let entry = context
        .tokens
        .get(token_name)
        .cloned()
        .ok_or_else(|| "token entry not found".to_string())?;

    let expires_at = entry
        .access_expires_at
        .as_deref()
        .and_then(parse_rfc3339);
    let needs_refresh = expires_at
        .map(|expires_at| Utc::now() + ChronoDuration::seconds(REFRESH_SKEW_SECONDS) >= expires_at)
        .unwrap_or(false);

    if !needs_refresh {
        return Ok(entry.access_token);
    }

    let refresh = entry
        .refresh_token
        .clone()
        .ok_or_else(|| "refresh token missing".to_string())?;

    let url = format!("{}/v1/auth/refresh", addr.trim_end_matches('/'));
    let payload = serde_json::json!({ "refresh_token": refresh });
    let response = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        // При 401 - сессия истекла, нужна повторная авторизация
        if status == reqwest::StatusCode::UNAUTHORIZED {
            // Удалить токены
            if let Some(ctx) = config.contexts.get_mut(context_name) {
                ctx.tokens.remove(token_name);
            }
            return Err("session_expired".to_string());
        }
        return Err(format!("refresh failed: {status} {body}"));
    }
    #[derive(serde::Deserialize)]
    struct AuthResponse {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: u64,
    }
    let auth: AuthResponse = response.json().await.map_err(|err| err.to_string())?;
    let new_expires =
        (Utc::now() + ChronoDuration::seconds(auth.expires_in as i64)).to_rfc3339();

    if let Some(ctx) = config.contexts.get_mut(context_name) {
        if let Some(entry) = ctx.tokens.get_mut(token_name) {
            entry.access_token = auth.access_token.clone();
            entry.refresh_token = auth.refresh_token.clone().or(entry.refresh_token.clone());
            entry.access_expires_at = Some(new_expires);
        }
    }
    Ok(auth.access_token)
}
