//! WebAuthn JSON admission shared by the browser WASM edge and native tests.
use super::{passkey::*, BrowserContext, IpcError, Result};
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Options {
    challenge: String,
    rp: Option<Rp>,
    rp_id: Option<String>,
    user: Option<User>,
    pub_key_cred_params: Option<Vec<Algorithm>>,
    #[serde(default)]
    exclude_credentials: Vec<Descriptor>,
    #[serde(default)]
    allow_credentials: Vec<Descriptor>,
    authenticator_selection: Option<Selection>,
    user_verification: Option<String>,
    attestation: Option<String>,
    timeout: Option<u32>,
    extensions: Option<serde_json::Map<String, serde_json::Value>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rp {
    id: Option<String>,
    name: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct User {
    id: String,
    name: String,
    display_name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Algorithm {
    r#type: String,
    alg: i32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    r#type: String,
    id: String,
    transports: Option<Vec<String>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Selection {
    authenticator_attachment: Option<String>,
    resident_key: Option<String>,
    require_resident_key: Option<bool>,
    user_verification: Option<String>,
}
fn uv(value: Option<&str>) -> Result<bool> {
    match value {
        None | Some("preferred" | "discouraged") => Ok(false),
        Some("required") => Ok(true),
        _ => Err(IpcError::Protocol),
    }
}
fn ids(list: Vec<Descriptor>) -> Result<Vec<String>> {
    if list.len() > 64 {
        return Err(IpcError::Protocol);
    }
    list.into_iter()
        .map(|d| {
            if d.r#type != "public-key"
                || d.transports
                    .as_ref()
                    .is_some_and(|v| v.len() > 8 || v.iter().any(|s| s.len() > 32))
            {
                return Err(IpcError::Protocol);
            }
            decode(&d.id, 1023)?;
            Ok(d.id)
        })
        .collect()
}
pub fn passkey_request(context: BrowserContext, kind: &str, json: &str) -> Result<PasskeyRequest> {
    if json.len() > super::MAX_BODY_BYTES / 2 {
        return Err(IpcError::Limit);
    }
    let options: Options = serde_json::from_str(json)?;
    if options.extensions.as_ref().is_some_and(|e| !e.is_empty())
        || options.timeout.is_some_and(|t| t == 0)
    {
        return Err(IpcError::Protocol);
    }
    let (_, frame) = context.credential_context()?;
    let (rp_id, require_verification, operation) = match kind {
        "create" => {
            if options.rp_id.is_some()
                || !options.allow_credentials.is_empty()
                || options.user_verification.is_some()
                || options.attestation.as_deref().is_some_and(|v| v != "none")
            {
                return Err(IpcError::Protocol);
            }
            let rp = options.rp.ok_or(IpcError::Protocol)?;
            let user = options.user.ok_or(IpcError::Protocol)?;
            let selection = options.authenticator_selection;
            if selection.as_ref().is_some_and(|s| {
                s.authenticator_attachment
                    .as_deref()
                    .is_some_and(|v| v != "platform")
                    || s.resident_key
                        .as_deref()
                        .is_some_and(|v| !["required", "preferred", "discouraged"].contains(&v))
            }) {
                return Err(IpcError::Protocol);
            }
            let verification = uv(selection
                .as_ref()
                .and_then(|s| s.user_verification.as_deref()))?;
            let _resident = selection.as_ref().and_then(|s| s.require_resident_key);
            let algorithms = options.pub_key_cred_params.ok_or(IpcError::Protocol)?;
            if algorithms.len() > 64 || algorithms.iter().any(|a| a.r#type != "public-key") {
                return Err(IpcError::Protocol);
            }
            (
                rp.id.unwrap_or_else(|| frame.host().into()),
                verification,
                PasskeyOperation::Create {
                    rp_name: rp.name,
                    user_id: user.id,
                    user_name: user.name,
                    user_display_name: user.display_name,
                    algorithms: algorithms.into_iter().map(|a| a.alg).collect(),
                    exclude_credentials: ids(options.exclude_credentials)?,
                },
            )
        }
        "get" => {
            if options.rp.is_some()
                || options.user.is_some()
                || options.pub_key_cred_params.is_some()
                || !options.exclude_credentials.is_empty()
                || options.authenticator_selection.is_some()
                || options.attestation.is_some()
            {
                return Err(IpcError::Protocol);
            }
            (
                options.rp_id.unwrap_or_else(|| frame.host().into()),
                uv(options.user_verification.as_deref())?,
                PasskeyOperation::Get {
                    allow_credentials: ids(options.allow_credentials)?,
                },
            )
        }
        _ => return Err(IpcError::Protocol),
    };
    let request = PasskeyRequest {
        context,
        rp_id,
        challenge: options.challenge,
        require_verification,
        operation,
    };
    request.validate()?;
    Ok(request)
}
