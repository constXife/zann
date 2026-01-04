use axum::http::HeaderMap;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

use crate::app::AppState;

pub fn client_ip(
    headers: &HeaderMap,
    remote_addr: Option<SocketAddr>,
    state: Option<&AppState>,
) -> Option<String> {
    let trusted = state
        .map(|value| value.config.server.trusted_proxies.as_slice())
        .unwrap_or(&[]);
    let remote_ip = remote_addr.map(|addr| addr.ip());
    if trusted.is_empty() {
        return remote_ip.map(|ip| ip.to_string());
    }
    if remote_ip.is_some_and(|ip| is_trusted_proxy(ip, trusted)) {
        return parse_forwarded_ip(headers).or_else(|| remote_ip.map(|ip| ip.to_string()));
    }
    remote_ip.map(|ip| ip.to_string())
}

pub fn request_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(std::string::ToString::to_string)
}

pub fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(std::string::ToString::to_string)
}

fn parse_forwarded_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let first = value.split(',').next().map_or(value, str::trim);
        if !first.is_empty() {
            return Some(first.to_string());
        }
    }
    if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let value = value.trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    if let Some(value) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        for part in value.split(';') {
            let part = part.trim();
            if let Some(rest) = part.strip_prefix("for=") {
                let rest = rest.trim_matches('"');
                if !rest.is_empty() {
                    return Some(rest.to_string());
                }
            }
        }
    }
    None
}

fn is_trusted_proxy(remote_ip: IpAddr, trusted: &[String]) -> bool {
    let Ok(trusted_nets) = trusted
        .iter()
        .map(|value| value.parse::<IpNet>())
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    trusted_nets.iter().any(|net| net.contains(&remote_ip))
}
